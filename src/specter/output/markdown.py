"""Markdown report renderer for Specter scan results.

Returns a plain CommonMark string — no stream writes, no ANSI codes.
Only imports from specter.models (plus stdlib datetime).
"""
from __future__ import annotations

from datetime import timezone

from specter.models import (
    AgentCalldata,
    ScanResult,
    ValidationResult,
    ValidationStatus,
    ValidationTier,
)

_HEADING: dict[ValidationStatus, str] = {
    ValidationStatus.VALIDATED_EXPLOIT: "CONFIRMED VULNERABILITY",
    ValidationStatus.AGENT_PROPOSED_UNVALIDATED: "POTENTIAL VULNERABILITY \u2014 UNCONFIRMED",
    ValidationStatus.SKANF_DETECTED_UNEXPLOITED: "POTENTIAL VULNERABILITY \u2014 UNCONFIRMED",
    ValidationStatus.CLEAN: "NO VULNERABILITY DETECTED",
}

# ANSI color codes — only applied when color=True (TTY detection in cli.py)
_ANSI_RED   = "\033[91m"   # critical-red for CONFIRMED VULNERABILITY
_ANSI_AMBER = "\033[33m"   # warning-amber for POTENTIAL VULNERABILITY
_ANSI_GREEN = "\033[92m"   # safe-green for NO VULNERABILITY DETECTED
_ANSI_RESET = "\033[0m"

_HEADING_COLOR: dict[ValidationStatus, str] = {
    ValidationStatus.VALIDATED_EXPLOIT:          _ANSI_RED,
    ValidationStatus.AGENT_PROPOSED_UNVALIDATED: _ANSI_AMBER,
    ValidationStatus.SKANF_DETECTED_UNEXPLOITED: _ANSI_AMBER,
    ValidationStatus.CLEAN:                      _ANSI_GREEN,
}


def _render_section(heading: str, body: str) -> str:
    return f"{heading}\n\n{body}"


def _render_metadata(result: ScanResult) -> str:
    ts = result.scan_timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    runtime = f"{result.runtime_seconds:.1f}s"
    lines = [
        "| Field | Value |",
        "|---|---|",
        f"| Contract | {result.contract_address} |",
        f"| Scan Timestamp | {ts} |",
        f"| SKANF Digest | {result.skanf_version_digest} |",
        f"| Model Version | {result.model_version} |",
        f"| Runtime | {runtime} |",
    ]
    return "\n".join(lines)


def _render_vulnerability_summary(result: ScanResult) -> str:
    if result.finding is None or result.validation_status == ValidationStatus.CLEAN:
        return "No vulnerability detected."
    summary = result.finding.skanf_summary
    if not summary:
        return "No vulnerability summary available."
    return summary


def _render_failure_mode(result: ScanResult) -> str:
    if result.validation_status in (
        ValidationStatus.VALIDATED_EXPLOIT,
        ValidationStatus.CLEAN,
    ):
        return "N/A"
    if result.finding is None:
        return "N/A"
    failure_mode = result.finding.failure_mode
    if not failure_mode:
        return "N/A"
    return failure_mode


def _render_agent_reasoning(result: ScanResult, *, verbose: bool) -> str:
    if result.finding is None:
        return "No agent reasoning available."
    if not verbose:
        return "Omitted \u2014 rerun with --verbose to include."
    reasoning = result.finding.agent_reasoning
    if not reasoning:
        return "No agent reasoning trace available."
    return f"```\n{reasoning}\n```"


def _render_exploit_calldata(result: ScanResult) -> str:
    if result.finding is None or result.finding.exploit_calldata is None:
        return "No exploit calldata generated."
    cd: AgentCalldata = result.finding.exploit_calldata
    return (
        "```json\n"
        "{\n"
        f'  "calldata": "{cd.calldata}",\n'
        f'  "target_address": "{cd.target_address}",\n'
        f'  "value": {cd.value},\n'
        f'  "caller": "{cd.caller}",\n'
        f'  "origin": "{cd.origin}"\n'
        "}\n"
        "```"
    )


def _render_validation_result(result: ScanResult) -> str:
    status = result.validation_status

    if status == ValidationStatus.CLEAN:
        return "SKANF analysis found no vulnerability in this contract."

    if result.finding is None:
        return "No validation result available."

    vr: ValidationResult | None = result.finding.validation_result

    if vr is None:
        # SKANF direct pass-through (VALIDATED_EXPLOIT with no agent/EVM step)
        return "SKANF generated a direct exploit \u2014 no agent or EVM validation step required."

    if vr.tier == ValidationTier.FULL_SUCCESS:
        balance_note = " Live balance confirmed." if vr.live_balance else ""
        return (
            "Exploit calldata confirmed: Transfer event observed and asset transfer completed "
            f"in EVM simulation. Result: **confirmed vulnerability**.{balance_note}"
        )
    elif vr.tier == ValidationTier.PARTIAL_SUCCESS:
        return (
            "Vulnerable CALL instruction was reached and triggered, but no Transfer event or "
            "asset transfer was confirmed. Result: **potential vulnerability \u2014 unconfirmed**."
        )
    else:  # FAILURE
        return (
            "Calldata did not reach the vulnerable CALL instruction in EVM simulation. "
            "SKANF detected a vulnerability, but no exploit path was confirmed by either "
            "SKANF or the agent."
        )


def _render_recommended_remediation(result: ScanResult) -> str:
    status = result.validation_status

    if status == ValidationStatus.VALIDATED_EXPLOIT:
        return (
            "This contract contains a confirmed vulnerability. Immediate action is recommended:\n\n"
            "1. Pause or disable the contract if possible.\n"
            "2. Notify affected stakeholders and conduct a full security audit.\n"
            "3. Patch the vulnerable code path and re-deploy after thorough testing."
        )
    elif status in (
        ValidationStatus.AGENT_PROPOSED_UNVALIDATED,
        ValidationStatus.SKANF_DETECTED_UNEXPLOITED,
    ):
        return (
            "A potential vulnerability was detected but could not be fully confirmed. "
            "A manual security review of the flagged code path is recommended before "
            "production use."
        )
    else:  # CLEAN
        return (
            "Specter did not detect an exploitable vulnerability in this contract. "
            "This result reflects the analysis performed by SKANF and does not constitute "
            "a guarantee of contract security — no exploitable vulnerability detected by Specter."
        )


def _should_include_disclosure(result: ScanResult) -> bool:
    if result.validation_status != ValidationStatus.VALIDATED_EXPLOIT:
        return False
    if result.finding is None:
        return False
    if result.finding.validation_result is None:
        return False
    return result.finding.validation_result.live_balance is True


def _render_disclosure_notice() -> str:
    lines = [
        "> This exploit has been validated against a live contract holding assets.",
        "> If you are not the contract owner, consider reporting this vulnerability",
        "> before acting on it. Resources: Immunefi bug bounty directory,",
        "> security@[protocol] if known.",
    ]
    return "\n".join(lines)


def render_markdown(result: ScanResult, *, verbose: bool = False, color: bool = False) -> str:
    """Render a ScanResult as a plain CommonMark markdown report string.

    Pure function — no stream writes. ANSI codes only when color=True.
    """
    heading_text = _HEADING[result.validation_status]
    if color:
        ansi = _HEADING_COLOR[result.validation_status]
        heading_text = f"{ansi}{heading_text}{_ANSI_RESET}"

    sections: list[str] = [
        "# Specter Scan Report",
        _render_metadata(result),
        f"## Finding: {heading_text}",
        _render_section("### Vulnerability Summary", _render_vulnerability_summary(result)),
        _render_section("### Failure Mode", _render_failure_mode(result)),
        _render_section("### Agent Reasoning", _render_agent_reasoning(result, verbose=verbose)),
        _render_section("### Exploit Calldata", _render_exploit_calldata(result)),
        _render_section("### Validation Result", _render_validation_result(result)),
        _render_section("### Recommended Remediation", _render_recommended_remediation(result)),
    ]
    if _should_include_disclosure(result):
        sections.append(_render_section("## Responsible Disclosure Notice", _render_disclosure_notice()))
    return "\n\n".join(sections)
