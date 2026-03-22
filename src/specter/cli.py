import datetime
import os
import re
import sys
import time


def _load_dotenv() -> None:
    """Load .env from the current working directory or project root, if present."""
    for candidate in (os.path.join(os.getcwd(), ".env"), os.path.join(os.path.dirname(__file__), "..", "..", ".env")):
        candidate = os.path.abspath(candidate)
        if not os.path.isfile(candidate):
            continue
        with open(candidate) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key and key not in os.environ:
                    os.environ[key] = value
        break


_load_dotenv()

import typer

from specter import __version__
from specter.config import (
    DEFAULT_TIMEOUT_SECONDS,
    MODEL_VERSION,
    SKANF_IMAGE_DIGEST,
    check_dependencies,
    get_active_model_version,
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
    ValidationResult,
    ValidationStatus,
)
from specter.output.json_out import render_json
from specter.output.markdown import render_markdown
from specter.pipeline.agent import call_agent
from specter.pipeline.parser import parse_skanf
from specter.pipeline.runner import run_skanf
from specter.pipeline.validator import call_validator

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
        model_version=get_active_model_version(),
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
        model_version=get_active_model_version(),
        validation_status=ValidationStatus.VALIDATED_EXPLOIT,
        finding=finding,
        runtime_seconds=runtime,
        error=None,
    )


def _emit_result(
    result: ScanResult,
    *,
    json_output: bool,
    output_path: str | None,
    verbose: bool = False,
    color: bool = False,
) -> None:
    if json_output:
        typer.echo(render_json(result))
    else:
        typer.echo(render_markdown(result, verbose=verbose, color=color))
    if output_path:
        with open(output_path, "w") as f:
            if json_output:
                f.write(render_json(result))
            else:
                f.write(render_markdown(result, verbose=verbose))


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

        stdout_is_tty = sys.stdout.isatty()
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
            _emit_result(result, json_output=json_output, output_path=output, verbose=verbose, color=stdout_is_tty)
            _emit_scan_footer(scan_target.value, result.validation_status.value, scan_runtime)
            raise typer.Exit(code=EXIT_CODES[result.validation_status])

        elif skanf_output.state == SkfnState.EXPLOIT_GENERATED:
            scan_runtime = time.monotonic() - (deadline - timeout)
            result = _assemble_exploit_generated_result(scan_target, skanf_output, scan_runtime)
            _emit_result(result, json_output=json_output, output_path=output, verbose=verbose, color=stdout_is_tty)
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
            if is_tty:
                typer.echo("[3/4] Calling agent...", err=True, nl=False)
            else:
                typer.echo("[3/4] Calling agent...", err=True)
            agent_result = call_agent(context, timeout=deadline - time.monotonic())
            if is_tty:
                typer.echo("\r[3/4] Calling agent... done", err=True)
            if is_tty:
                typer.echo("[4/4] Validating exploit...", err=True, nl=False)
            else:
                typer.echo("[4/4] Validating exploit...", err=True)
            validation_result = call_validator(agent_result, context, timeout=deadline - time.monotonic())
            if is_tty:
                typer.echo("\r[4/4] Validating exploit... done", err=True)

            scan_runtime = time.monotonic() - (deadline - timeout)
            contract_addr = scan_target.value if scan_target.is_address else "0x" + "0" * 40
            finding = Finding(
                exploit_calldata=agent_result,
                validation_result=validation_result,
            )
            result = ScanResult(
                contract_address=contract_addr,
                scan_timestamp=datetime.datetime.now(datetime.timezone.utc),
                skanf_version_digest=_SKANF_DIGEST,
                model_version=get_active_model_version(),
                validation_status=validation_result.validation_status,
                finding=finding,
                runtime_seconds=scan_runtime,
                error=None,
            )
            _emit_result(result, json_output=json_output, output_path=output, verbose=verbose, color=stdout_is_tty)
            _emit_scan_footer(scan_target.value, result.validation_status.value, scan_runtime)
            raise typer.Exit(code=EXIT_CODES[result.validation_status])

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
