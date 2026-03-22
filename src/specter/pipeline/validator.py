"""EVM exploit validator — pipeline stage 4.

Imports: models + errors + config + stdlib + httpx only.
Never imports from specter.cli (circular) or specter.pipeline.parser / .agent (cross-stage).
Exception: _fetch_bytecode imported from runner — acceptable MVP co-location exception.
"""

import logging
import os
import shutil
import subprocess
import tempfile

import httpx

from specter.config import DEFAULT_TIMEOUT_SECONDS, SKANF_IMAGE_DIGEST
from specter.errors import ConfigError, SprecterValidationError
from specter.models import AgentCalldata, SkfnContext, ValidationResult, ValidationTier

_RESOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "resources")
_ARM64_PATCH = os.path.join(_RESOURCES_DIR, "gigahorse_ops_arm64_patch.py")
_FIND_CALL_PCS_SCRIPT = os.path.join(_RESOURCES_DIR, "find_call_pcs.py")

logger = logging.getLogger(__name__)


def _detect_validation_tier(raw_output: str) -> ValidationTier:
    """Classify greed validation output into a ValidationTier.

    Mirrors runner._detect_state() but returns ValidationTier, not SkfnState.
    """
    if "INFO | greed | CALLDATA:" in raw_output:
        return ValidationTier.FULL_SUCCESS
    if "Calling contract <SYMBOLIC>" in raw_output:
        return ValidationTier.PARTIAL_SUCCESS
    if "FATAL | greed | No paths found" in raw_output:
        return ValidationTier.FAILURE
    if "FATAL | greed |" in raw_output:
        logger.debug("SKANF validation fatal error:\n%s", raw_output)
        raise SprecterValidationError(
            "SKANF validation mode reported a fatal error — "
            f"output: {raw_output[:200]!r}"
        )
    logger.debug("SKANF validation: no recognizable output, treating as failure:\n%s", raw_output)
    return ValidationTier.FAILURE


def _check_live_balance(address: str, *, timeout: float | None = None) -> bool:
    """Check if the contract holds a non-zero ETH balance OR ERC-20 token balance.

    Checks ETH balance first (fast). If non-zero, returns True immediately without
    querying token balances. If ETH is zero, queries ERC-20 token balances via
    Alchemy's alchemy_getTokenBalances API.

    Args:
        address: EIP-55 checksummed contract address.
        timeout: Request timeout in seconds.

    Returns:
        True if contract holds any ETH or ERC-20 token balance > 0.
        False if both ETH and all token balances are zero.
        False (with WARNING log) if ALCHEMY_RPC_URL is not set.

    Raises:
        ConfigError: Network failure, timeout, or HTTP error during balance check.
    """
    rpc_url = os.environ.get("ALCHEMY_RPC_URL")
    if not rpc_url:
        logger.warning(
            "ALCHEMY_RPC_URL not set — live balance check skipped, live_balance=False"
        )
        return False

    effective_timeout = timeout or 30.0

    # Step 1: Check ETH balance — fast, short-circuit if non-zero
    eth_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"],
    }
    try:
        resp = httpx.post(rpc_url, json=eth_payload, timeout=effective_timeout)
        resp.raise_for_status()
    except httpx.TimeoutException as e:
        raise ConfigError(
            f"Alchemy RPC timed out during live balance check: {e}"
        ) from e
    except httpx.NetworkError as e:
        raise ConfigError(
            f"Alchemy RPC network failure during live balance check: {e}"
        ) from e
    except httpx.HTTPStatusError as e:
        raise ConfigError(
            f"Alchemy RPC HTTP error {e.response.status_code} during live balance check"
        ) from e

    result_hex = resp.json().get("result", "0x0")
    try:
        eth_balance = int(result_hex, 16) if result_hex and result_hex != "0x" else 0
    except ValueError:
        logger.warning("Unexpected ETH balance format from RPC: %r — treating as zero", result_hex)
        eth_balance = 0
    logger.debug("ETH balance for %s: %d wei", address, eth_balance)

    if eth_balance > 0:
        return True  # short-circuit: ETH balance alone is sufficient

    # Step 2: ETH is zero — check ERC-20 token balances via alchemy_getTokenBalances
    token_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "alchemy_getTokenBalances",
        "params": [address, "erc20"],
    }
    try:
        resp = httpx.post(rpc_url, json=token_payload, timeout=effective_timeout)
        resp.raise_for_status()
    except httpx.TimeoutException as e:
        raise ConfigError(
            f"Alchemy RPC timed out during token balance check: {e}"
        ) from e
    except httpx.NetworkError as e:
        raise ConfigError(
            f"Alchemy RPC network failure during token balance check: {e}"
        ) from e
    except httpx.HTTPStatusError as e:
        raise ConfigError(
            f"Alchemy RPC HTTP error {e.response.status_code} during token balance check"
        ) from e

    data = resp.json()

    # Handle method-not-found (RPC provider doesn't support alchemy_getTokenBalances)
    if "error" in data:
        error_code = data["error"].get("code")
        logger.warning(
            "alchemy_getTokenBalances not supported by RPC provider (error %s) — "
            "token balance check skipped",
            error_code,
        )
        return False

    result_data = data.get("result", {})
    if not isinstance(result_data, dict) or "tokenBalances" not in result_data:
        logger.warning(
            "alchemy_getTokenBalances response missing tokenBalances key — "
            "token balance check skipped"
        )
        return False
    token_balances = result_data["tokenBalances"]
    if not isinstance(token_balances, list):
        logger.warning(
            "alchemy_getTokenBalances returned unexpected format — "
            "token balance check skipped"
        )
        return False

    logger.debug("Token balances for %s: %d tokens found", address, len(token_balances))

    for item in token_balances:
        balance_hex = item.get("tokenBalance", "0x0")
        if balance_hex and balance_hex not in ("0x0", "0x"):
            try:
                if int(balance_hex, 16) > 0:
                    logger.debug(
                        "Non-zero token balance found: %s = %s",
                        item.get("contractAddress", "unknown"),
                        balance_hex,
                    )
                    return True
            except ValueError:
                pass  # malformed hex — skip this token

    return False


def call_validator(
    agent_calldata: AgentCalldata,
    context: SkfnContext,
    *,
    timeout: float | None = None,
) -> ValidationResult:
    """Run SKANF validation mode to classify agent calldata effectiveness.

    Implements Pattern 1 pipeline stage interface.

    Args:
        agent_calldata: Proposed calldata from the AI agent (reserved — future validation use).
        context: Parsed SKANF vulnerability context — call_pc REQUIRED for --find mode.
        timeout: Wall-clock budget in seconds.

    Returns:
        ValidationResult with tier and live_balance.

    Raises:
        SprecterValidationError: SKANF container failed, timed out, or produced invalid output.
        ConfigError: ALCHEMY_RPC_URL missing or network failure during live balance check.
    """
    effective_timeout = timeout or DEFAULT_TIMEOUT_SECONDS

    call_pc = context.call_pc
    is_address_scan = (
        len(context.contract_address) == 42
        and context.contract_address != "0x" + "0" * 40
    )

    if not is_address_scan:
        logger.warning(
            "Bytecode scan — cannot re-fetch contract bytecode for validation; "
            "tier defaulting to FAILURE"
        )
        return ValidationResult.from_tier(ValidationTier.FAILURE, live_balance=False)

    if not call_pc:
        logger.warning(
            "No call_pc in context (free-exploration stall) — "
            "running validation in free-exploration mode"
        )

    try:
        with tempfile.TemporaryDirectory(prefix="specter-validator-") as workdir:
            from specter.pipeline.runner import _fetch_bytecode  # noqa: PLC0415

            hex_path = os.path.join(workdir, "contract.hex")
            bytecode = _fetch_bytecode(
                context.contract_address, timeout=effective_timeout * 0.1
            )
            with open(hex_path, "w") as f:
                f.write(bytecode)

            shutil.copy(_FIND_CALL_PCS_SCRIPT, os.path.join(workdir, "_find_call_pcs.py"))

            phase1_timeout = max(30, int(effective_timeout * 0.4))
            per_find_timeout = min(60, max(20, int(effective_timeout * 0.08)))
            address_flag = f"--address {context.contract_address}"

            if call_pc:
                # Targeted validation: direct greed at the known vulnerable CALL
                greed_section = f"greed /workdir --find {call_pc} {address_flag}"
            else:
                # Discovery mode: enumerate dynamic-target CALLs and try each with --find
                greed_section = (
                    f"CALL_IDS=$(python3 /workdir/_find_call_pcs.py 2>/dev/null); "
                    f"found=0; "
                    f"for callid in $CALL_IDS; do "
                    f"  output=$(timeout {per_find_timeout} greed /workdir --find \"$callid\" {address_flag} 2>&1); "
                    f"  if echo \"$output\" | grep -q 'CALLDATA:'; then echo \"$output\"; found=1; break; fi; "
                    f"done; "
                    f"if [ $found -eq 0 ]; then greed /workdir {address_flag}; fi"
                )

            bash_cmd = (
                f"cd /workdir && "
                f"analyze_hex.sh --file contract.hex --timeout {phase1_timeout} && "
                f"{greed_section}"
            )

            cmd = [
                "docker", "run", "--rm",
                "--platform", "linux/amd64",
                "-v", f"{workdir}:/workdir",
                "-w", "/workdir",
                "-v", f"{os.path.abspath(_ARM64_PATCH)}:/opt/greed/greed/TAC/gigahorse_ops.py:ro",
                SKANF_IMAGE_DIGEST,
                "bash", "-l", "-c", bash_cmd,
            ]

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=effective_timeout,
            )

            raw_output = (proc.stdout or "") + (proc.stderr or "")
            logger.debug("SKANF validation raw output:\n%s", raw_output)

            if proc.returncode != 0:
                stderr_excerpt = (proc.stderr or "")[:500]
                raise SprecterValidationError(
                    f"SKANF validation container exited with code {proc.returncode}: "
                    f"{stderr_excerpt}"
                )

            tier = _detect_validation_tier(raw_output)
            logger.info("SKANF validation tier: %s", tier.value)

            live_balance = _check_live_balance(
                context.contract_address, timeout=effective_timeout * 0.05
            )

            return ValidationResult.from_tier(tier, live_balance=live_balance, raw_output=raw_output)

    except subprocess.TimeoutExpired:
        raise SprecterValidationError(
            f"SKANF validation container timed out after {effective_timeout} seconds"
        )
