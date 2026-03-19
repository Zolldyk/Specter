import datetime
import re
import sys
import time

import typer

from specter import __version__
from specter.config import (
    DEFAULT_TIMEOUT_SECONDS,
    MODEL_VERSION,
    SKANF_IMAGE_DIGEST,
    check_dependencies,
    validate_env,
)
from specter.errors import SprecterError, ConfigError, SkfnContainerError
from specter.logging_config import _register_secret_filter, _set_log_level
from specter.models import (
    AgentCalldata,
    Finding,
    ScanResult,
    ScanTarget,
    SkfnOutput,
    SkfnState,
    ValidationStatus,
)
from specter.pipeline.parser import parse_skanf
from specter.pipeline.runner import run_skanf

app = typer.Typer(rich_markup_mode=None)

EXIT_CODES: dict[ValidationStatus, int] = {
    ValidationStatus.CLEAN: 0,
    ValidationStatus.SKANF_DETECTED_UNEXPLOITED: 0,
    ValidationStatus.AGENT_PROPOSED_UNVALIDATED: 2,
    ValidationStatus.VALIDATED_EXPLOIT: 1,
}

_SKANF_DIGEST = SKANF_IMAGE_DIGEST.split("@", 1)[1] if "@" in SKANF_IMAGE_DIGEST else SKANF_IMAGE_DIGEST


def _extract_calldata_from_greed(raw_output: str) -> str | None:
    """Extract hex calldata from greed CALLDATA log line, adding 0x prefix."""
    match = re.search(r"INFO \| greed \| CALLDATA: ([0-9a-fA-F]+)", raw_output)
    if match:
        return "0x" + match.group(1).lower()
    return None


def _emit_scan_footer(address: str, status_str: str, runtime: float) -> None:
    typer.echo(
        f"Specter scan complete — {address} — {status_str} — {runtime:.1f}s",
        err=True,
    )


def _assemble_clean_result(scan_target: ScanTarget, runtime: float) -> ScanResult:
    contract_addr = scan_target.value if scan_target.is_address else "0x" + "0" * 40
    return ScanResult(
        contract_address=contract_addr,
        scan_timestamp=datetime.datetime.now(datetime.timezone.utc),
        skanf_version_digest=_SKANF_DIGEST,
        model_version=MODEL_VERSION,
        validation_status=ValidationStatus.CLEAN,
        finding=None,
        runtime_seconds=runtime,
        error=None,
    )


def _assemble_exploit_generated_result(
    scan_target: ScanTarget, skanf_output: SkfnOutput, runtime: float
) -> ScanResult:
    contract_addr = scan_target.value if scan_target.is_address else "0x" + "0" * 40
    zero_addr = "0x" + "0" * 40
    calldata_hex = _extract_calldata_from_greed(skanf_output.raw_output)
    if calldata_hex is None:
        raise SkfnContainerError(
            "SKANF state is EXPLOIT_GENERATED but CALLDATA line could not be extracted "
            "from raw output — output may be malformed"
        )
    finding = Finding(
        exploit_calldata=AgentCalldata(
            calldata=calldata_hex,
            target_address=zero_addr,
            caller=zero_addr,
            origin=zero_addr,
        )
    )
    return ScanResult(
        contract_address=contract_addr,
        scan_timestamp=datetime.datetime.now(datetime.timezone.utc),
        skanf_version_digest=_SKANF_DIGEST,
        model_version=MODEL_VERSION,
        validation_status=ValidationStatus.VALIDATED_EXPLOIT,
        finding=finding,
        runtime_seconds=runtime,
        error=None,
    )


def _emit_result(result: ScanResult, *, json_output: bool, output_path: str | None) -> None:
    if json_output or output_path:
        json_str = result.model_dump_json(indent=2)
        if json_output:
            typer.echo(json_str)
        if output_path:
            with open(output_path, "w") as f:
                f.write(json_str)


def _parse_target(target_str: str) -> ScanTarget:
    """Determine if target is an Ethereum address or raw bytecode.

    Raises:
        ConfigError: target is neither a valid address nor a valid bytecode hex string.
    """
    s = target_str.strip()
    # EIP-55 address: 0x + exactly 40 hex chars
    if len(s) == 42 and s.startswith("0x"):
        return ScanTarget(value=s, is_address=True)
    # Raw bytecode: 0x-prefixed hex of arbitrary length (or without 0x)
    hex_s = s[2:] if s.startswith("0x") else s
    if all(c in "0123456789abcdefABCDEF" for c in hex_s) and len(hex_s) > 40:
        return ScanTarget(value="0x" + hex_s.lower(), is_address=False)
    raise ConfigError(
        f"Invalid target '{s}': must be an Ethereum address (0x + 40 hex chars) "
        f"or raw bytecode hex string (> 40 hex chars)"
    )


@app.command()
def scan(
    target: str,
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output"),
    timeout: int = typer.Option(DEFAULT_TIMEOUT_SECONDS, "--timeout", help="Scan timeout in seconds"),
    output: str | None = typer.Option(None, "--output", help="Write report to file"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON report"),
) -> None:
    """Scan a smart contract by address or bytecode."""
    _register_secret_filter()  # 1. Always first — secrets protected before any logging
    _set_log_level(verbose)    # 2. Log level set after secrets filter is in place
    validate_env()             # 3. Env validation after logging is configured

    try:
        scan_target = _parse_target(target)

        is_tty = sys.stderr.isatty()
        if is_tty:
            typer.echo("[1/4] Running SKANF analysis...", err=True, nl=False)
        else:
            typer.echo("[1/4] Running SKANF analysis...", err=True)

        deadline = time.monotonic() + timeout
        skanf_output = run_skanf(scan_target, timeout=deadline - time.monotonic())

        if is_tty:
            typer.echo("\r[1/4] Running SKANF analysis... done", err=True)

        if skanf_output.state == SkfnState.CLEAN:
            scan_runtime = time.monotonic() - (deadline - timeout)
            result = _assemble_clean_result(scan_target, scan_runtime)
            _emit_result(result, json_output=json_output, output_path=output)
            _emit_scan_footer(scan_target.value, result.validation_status.value, scan_runtime)
            raise typer.Exit(code=EXIT_CODES[result.validation_status])

        elif skanf_output.state == SkfnState.EXPLOIT_GENERATED:
            scan_runtime = time.monotonic() - (deadline - timeout)
            result = _assemble_exploit_generated_result(scan_target, skanf_output, scan_runtime)
            _emit_result(result, json_output=json_output, output_path=output)
            _emit_scan_footer(scan_target.value, result.validation_status.value, scan_runtime)
            raise typer.Exit(code=EXIT_CODES[result.validation_status])

        else:  # STALLED — proceed to parser
            if is_tty:
                typer.echo("[2/4] Parsing vulnerability report...", err=True, nl=False)
            else:
                typer.echo("[2/4] Parsing vulnerability report...", err=True)
            context = parse_skanf(skanf_output, scan_target, timeout=deadline - time.monotonic())
            if is_tty:
                typer.echo("\r[2/4] Parsing vulnerability report... done", err=True)
            # TODO: Story 3.1 — call_agent(context, timeout=deadline - time.monotonic())
            # from specter.pipeline.agent import call_agent
            # agent_result = call_agent(context, timeout=deadline - time.monotonic())
            typer.echo("\nParser stage complete — agent stage not yet implemented (Story 3.1)", err=True)
            raise typer.Exit(code=0)  # temporary stub exit

    except SprecterError as e:
        typer.echo(f"ERROR [{type(e).__name__}]: {e}", err=True)
        raise typer.Exit(code=e.exit_code)


@app.command()
def check() -> None:
    """Verify all dependencies and environment variables are configured."""
    _register_secret_filter()  # NFR5: protect secrets before any output
    items = check_dependencies()

    failed = False
    for item in items:
        symbol = "✓" if item.ok else "✗"
        line = f"{symbol}  {item.label:<22}  {item.status}"
        typer.echo(line, err=True)
        if not item.ok and item.fix:
            typer.echo(f"   {item.fix}", err=True)
        if not item.ok and item.required:
            failed = True

    if failed:
        raise typer.Exit(code=3)


@app.command()
def version() -> None:
    """Display the installed version and pinned dependency versions."""
    _register_secret_filter()  # protect secrets before any output (NFR5)
    typer.echo(f"specter {__version__}", err=True)
    typer.echo(f"SKANF image:  {SKANF_IMAGE_DIGEST}", err=True)
    typer.echo(f"Claude model: {MODEL_VERSION}", err=True)
