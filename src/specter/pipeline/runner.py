"""SKANF Docker runner — pipeline stage 1.

Imports: specter.config, specter.errors, specter.models, and stdlib + httpx only.
Never imports from specter.cli (circular) or specter.pipeline.parser (doesn't exist yet).
"""

import httpx
import json
import logging
import os
import subprocess
import tempfile
import time

from specter.config import DEFAULT_TIMEOUT_SECONDS, SKANF_IMAGE_DIGEST
from specter.errors import ConfigError, SkfnContainerError
from specter.models import ScanTarget, SkfnOutput, SkfnState

logger = logging.getLogger(__name__)


def _check_docker() -> None:
    """Verify Docker daemon is reachable via `docker info`.

    Raises:
        ConfigError: Docker is not installed (FileNotFoundError) or daemon not running
                     (non-zero exit from docker info).
        subprocess.TimeoutExpired: propagates to caller — run_skanf converts to
                                   SkfnContainerError.
    """
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise ConfigError(
            "Docker is not installed or not responding — "
            "ensure Docker Desktop is running"
        )
    if result.returncode != 0:
        raise ConfigError(
            "Docker daemon is not running — "
            "start Docker Desktop or run: sudo systemctl start docker"
        )


def _fetch_bytecode(address: str, *, timeout: float | None = None) -> str:
    """Fetch runtime bytecode for an Ethereum address via Alchemy eth_getCode.

    Returns raw hex WITHOUT 0x prefix (ready to write to contract.hex).

    Raises:
        ConfigError: ALCHEMY_RPC_URL missing, network failure, HTTP error, or no
                     bytecode at address (EOA or non-existent contract).
    """
    rpc_url = os.environ.get("ALCHEMY_RPC_URL")
    if not rpc_url:
        raise ConfigError(
            "ALCHEMY_RPC_URL is not set — required for address-based scans. "
            "Export it: export ALCHEMY_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/your_key"
        )
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": [address, "latest"],
    }
    try:
        resp = httpx.post(rpc_url, json=payload, timeout=timeout or 30.0)
        resp.raise_for_status()
    except httpx.NetworkError as e:
        raise ConfigError(f"Alchemy RPC network failure: {e}") from e
    except httpx.HTTPStatusError as e:
        raise ConfigError(f"Alchemy RPC HTTP error {e.response.status_code}") from e

    result = resp.json().get("result", "0x")
    if result in ("0x", "0x0", None):
        raise ConfigError(
            f"No bytecode at address {address} — contract not found or EOA"
        )
    return result[2:]  # strip 0x prefix


def _detect_state(raw_output: str, vulnerability_json: str) -> SkfnState:
    """Detect SKANF output state from greed log lines and vulnerability.json.

    Priority order (highest to lowest):
      1. CALLDATA line → exploit generated
      2. Symbolic CALL → stalled
      3. No paths found → clean
      4. Empty vulnerability.json, no greed output → clean
      5. Fallthrough → malformed, raise SkfnContainerError

    Raises:
        SkfnContainerError: Output does not match any known SKANF output pattern,
                            or vulnerability.json is unparseable.
    """
    # 1. CALLDATA line → greed found concrete path, exploit generated
    if "INFO | greed | CALLDATA:" in raw_output:
        return SkfnState.EXPLOIT_GENERATED

    # 2. Symbolic CALL → stalled, agent needed
    if "Calling contract <SYMBOLIC>" in raw_output:
        return SkfnState.STALLED

    # 3. Explicit no-path fatal → clean (nothing exploitable on this contract)
    if "FATAL | greed | No paths found" in raw_output:
        return SkfnState.CLEAN

    # 3b. Other FATAL greed lines → pipeline crash, not a clean state
    # A container that exits 0 but logged a fatal error must not be classified as clean
    if "FATAL | greed |" in raw_output:
        logger.debug("SKANF fatal error in output:\n%s", raw_output)
        raise SkfnContainerError(
            "SKANF reported a fatal pipeline error — analysis terminated unexpectedly. "
            f"Raw output excerpt: {raw_output[:200]!r}"
        )

    # 4. Parse vulnerability.json — empty array + no greed indicators → clean
    try:
        vuln_data = json.loads(vulnerability_json or "[]")
    except json.JSONDecodeError as exc:
        logger.debug("SKANF malformed vulnerability.json:\n%s", vulnerability_json)
        raise SkfnContainerError(
            "SKANF produced unparseable vulnerability.json — "
            "cannot determine scan state"
        ) from exc

    if not vuln_data:
        # Empty vulnerability list AND no greed stall/success → truly clean contract
        return SkfnState.CLEAN

    # 5. vulnerability.json non-empty but no stall/success greed output → malformed state
    logger.debug("SKANF unexpected output state:\n%s", raw_output)
    raise SkfnContainerError(
        "SKANF produced unexpected output: vulnerability detected in vulnerability.json "
        "but greed output contains neither a CALLDATA line nor a stall indicator — "
        f"raw output: {raw_output[:200]!r}"
    )


def run_skanf(target: ScanTarget, *, timeout: float | None = None) -> SkfnOutput:
    """Run SKANF analysis against a contract address or bytecode.

    This is the Pattern 1 pipeline stage interface. Never calls sys.exit() or
    typer.Exit() — raises SprecterError subclasses on failure.

    Args:
        target: Address-based or bytecode-based scan target.
        timeout: Total timeout budget in seconds (None → DEFAULT_TIMEOUT_SECONDS).

    Returns:
        SkfnOutput with raw output and vulnerability_json captured from workdir.

    Raises:
        ConfigError: Docker not running, ALCHEMY_RPC_URL missing, no bytecode at address.
        SkfnContainerError: Container timeout, non-zero exit, or Docker invocation failure.
    """
    effective_timeout = timeout or DEFAULT_TIMEOUT_SECONDS
    start = time.monotonic()

    try:
        _check_docker()

        if target.is_address:
            elapsed = time.monotonic() - start
            remaining = max(1.0, effective_timeout - elapsed)
            bytecode = _fetch_bytecode(target.value, timeout=remaining)
        else:
            hex_s = target.value[2:] if target.value.startswith("0x") else target.value
            bytecode = hex_s.lower()

        with tempfile.TemporaryDirectory(prefix="specter-") as workdir:
            hex_path = os.path.join(workdir, "contract.hex")
            with open(hex_path, "w") as f:
                f.write(bytecode)  # no 0x prefix — SKANF requires raw hex

            phase1_timeout = max(30, int(effective_timeout * 0.6))
            address_flag = f"--address {target.value}" if target.is_address else ""

            bash_cmd = (
                f"cd /workdir && "
                f"analyze_hex.sh --file contract.hex --timeout {phase1_timeout} && "
                f"KEY=$(jq -r '.[0].key_statement // empty' vulnerability.json 2>/dev/null) && "
                f"if [ -n \"$KEY\" ]; then "
                f"  greed /workdir --find \"$KEY\" {address_flag}; "
                f"else "
                f"  greed /workdir {address_flag}; "
                f"fi"
            )

            cmd = [
                "docker", "run", "--rm",
                "--platform", "linux/amd64",
                "-v", f"{workdir}:/workdir",
                "-w", "/workdir",
                SKANF_IMAGE_DIGEST,
                "bash", "-c", bash_cmd,
            ]

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=effective_timeout,
            )

            raw_output = (proc.stdout or "") + (proc.stderr or "")
            logger.debug("SKANF raw output:\n%s", raw_output)

            if proc.returncode != 0:
                stderr_excerpt = (proc.stderr or "")[:500]
                raise SkfnContainerError(
                    f"SKANF container exited with code {proc.returncode}: {stderr_excerpt}"
                )

            logger.info("SKANF analysis complete: exit_code=%d", proc.returncode)

            vuln_json = "[]"
            vuln_path = os.path.join(workdir, "vulnerability.json")
            if os.path.exists(vuln_path):
                with open(vuln_path) as f:
                    vuln_json = f.read()

            detected_state = _detect_state(raw_output, vuln_json)
            logger.info("SKANF state detected: %s", detected_state.value)
            return SkfnOutput(
                state=detected_state,
                raw_output=raw_output,
                container_exit_code=proc.returncode,
                vulnerability_json=vuln_json,
            )

    except subprocess.TimeoutExpired:
        raise SkfnContainerError(
            f"SKANF container timed out after {effective_timeout} seconds"
        )
