"""Tests for specter.output.markdown — plain CommonMark report renderer."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from specter.models import (
    AgentCalldata,
    Finding,
    ScanResult,
    ValidationResult,
    ValidationStatus,
    ValidationTier,
)
from specter.output.markdown import render_markdown

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
_TIMESTAMP = datetime(2026, 3, 22, 10, 45, 0, tzinfo=timezone.utc)
_DIGEST = "sha256:abc123def456"
_MODEL = "claude-sonnet-4-6"
_CALLDATA_HEX = "0x1cff79cd000000000000000000000000deadbeef"
_ZERO = "0x0000000000000000000000000000000000000001"


def make_scan_result(
    status: ValidationStatus,
    *,
    with_finding: bool = True,
    agent_reasoning: str | None = None,
    live_balance: bool = True,
) -> ScanResult:
    finding = None
    if with_finding and status != ValidationStatus.CLEAN:
        if status == ValidationStatus.VALIDATED_EXPLOIT:
            tier = ValidationTier.FULL_SUCCESS
        elif status == ValidationStatus.AGENT_PROPOSED_UNVALIDATED:
            tier = ValidationTier.PARTIAL_SUCCESS
        else:
            tier = ValidationTier.FAILURE

        # live_balance is only meaningful on the FULL_SUCCESS path; use False for other tiers
        effective_live_balance = live_balance if status == ValidationStatus.VALIDATED_EXPLOIT else False
        validation_result = ValidationResult.from_tier(
            tier=tier,
            live_balance=effective_live_balance,
        )
        finding = Finding(
            skanf_summary="ArbitraryCall vulnerability detected at callPC 0x76.",
            failure_mode=(
                None
                if status == ValidationStatus.VALIDATED_EXPLOIT
                else "Calldata reached CALL but no transfer confirmed."
            ),
            agent_reasoning=agent_reasoning,
            exploit_calldata=(
                AgentCalldata(
                    calldata=_CALLDATA_HEX,
                    target_address=_CONTRACT,
                    value=0,
                    caller=_ZERO,
                    origin=_ZERO,
                )
                if status == ValidationStatus.VALIDATED_EXPLOIT
                else None
            ),
            validation_result=validation_result,
        )
    return ScanResult(
        contract_address=_CONTRACT,
        scan_timestamp=_TIMESTAMP,
        skanf_version_digest=_DIGEST,
        model_version=_MODEL,
        validation_status=status,
        finding=finding,
        runtime_seconds=42.3,
        error=None,
    )


# ---------------------------------------------------------------------------
# TestFindingHeadline
# ---------------------------------------------------------------------------

class TestFindingHeadline:
    def test_validated_exploit_headline(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        assert "## Finding: CONFIRMED VULNERABILITY" in report

    def test_agent_proposed_unvalidated_headline(self):
        report = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        assert "## Finding: POTENTIAL VULNERABILITY \u2014 UNCONFIRMED" in report

    def test_skanf_detected_unexploited_headline(self):
        report = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        assert "## Finding: POTENTIAL VULNERABILITY \u2014 UNCONFIRMED" in report

    def test_agent_proposed_and_skanf_share_headline(self):
        r1 = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        r2 = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        # Extract the Finding line from both
        line1 = next(l for l in r1.splitlines() if l.startswith("## Finding:"))
        line2 = next(l for l in r2.splitlines() if l.startswith("## Finding:"))
        assert line1 == line2

    def test_clean_headline(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "## Finding: NO VULNERABILITY DETECTED" in report

    def test_clean_scope_qualifier(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "no exploitable vulnerability detected by Specter" in report


# ---------------------------------------------------------------------------
# TestSectionOrder
# ---------------------------------------------------------------------------

_EXPECTED_HEADERS = [
    "# Specter Scan Report",
    "## Finding:",
    "### Vulnerability Summary",
    "### Failure Mode",
    "### Agent Reasoning",
    "### Exploit Calldata",
    "### Validation Result",
    "### Recommended Remediation",
]


class TestSectionOrder:
    def _get_header_positions(self, report: str) -> list[tuple[int, str]]:
        positions = []
        for header in _EXPECTED_HEADERS:
            idx = report.find(header)
            assert idx != -1, f"Header '{header}' not found in report"
            positions.append((idx, header))
        return positions

    def test_section_order_validated_exploit(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        positions = self._get_header_positions(report)
        sorted_positions = sorted(positions, key=lambda x: x[0])
        assert [h for _, h in sorted_positions] == _EXPECTED_HEADERS

    def test_section_order_agent_proposed_unvalidated(self):
        report = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        positions = self._get_header_positions(report)
        sorted_positions = sorted(positions, key=lambda x: x[0])
        assert [h for _, h in sorted_positions] == _EXPECTED_HEADERS

    def test_section_order_skanf_detected_unexploited(self):
        report = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        positions = self._get_header_positions(report)
        sorted_positions = sorted(positions, key=lambda x: x[0])
        assert [h for _, h in sorted_positions] == _EXPECTED_HEADERS

    def test_section_order_clean(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        positions = self._get_header_positions(report)
        sorted_positions = sorted(positions, key=lambda x: x[0])
        assert [h for _, h in sorted_positions] == _EXPECTED_HEADERS

    def test_first_section_is_title(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert report.startswith("# Specter Scan Report")

    def test_metadata_block_in_position_2(self):
        # AC4: metadata block is section 2 — between title and ## Finding:
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        title_pos = report.find("# Specter Scan Report")
        meta_pos = report.find("| Contract |")
        finding_pos = report.find("## Finding:")
        assert title_pos < meta_pos < finding_pos, "Metadata block not in AC4 position 2"


# ---------------------------------------------------------------------------
# TestNoAnsiCodes
# ---------------------------------------------------------------------------

class TestNoAnsiCodes:
    def test_no_ansi_validated_exploit(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        assert not ANSI_ESCAPE.search(report), "ANSI escape codes found in markdown output"

    def test_no_ansi_agent_proposed(self):
        report = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        assert not ANSI_ESCAPE.search(report), "ANSI escape codes found in markdown output"

    def test_no_ansi_skanf_detected(self):
        report = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        assert not ANSI_ESCAPE.search(report), "ANSI escape codes found in markdown output"

    def test_no_ansi_clean(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert not ANSI_ESCAPE.search(report), "ANSI escape codes found in markdown output"

    def test_no_raw_escape_sequences(self):
        for status in ValidationStatus:
            report = render_markdown(make_scan_result(status))
            assert "\x1b[" not in report
            assert "\033[" not in report


# ---------------------------------------------------------------------------
# TestOutputIsolation
# ---------------------------------------------------------------------------

class TestOutputIsolation:
    def test_no_stdout_write(self, capsys):
        render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        captured = capsys.readouterr()
        assert captured.out == "", "render_markdown wrote to stdout"

    def test_no_stderr_write(self, capsys):
        render_markdown(make_scan_result(ValidationStatus.CLEAN))
        captured = capsys.readouterr()
        assert captured.err == "", "render_markdown wrote to stderr"

    def test_returns_string(self):
        result = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert isinstance(result, str)

    def test_no_stdout_verbose(self, capsys):
        render_markdown(
            make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, agent_reasoning="trace"),
            verbose=True,
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""


# ---------------------------------------------------------------------------
# TestVerboseMode
# ---------------------------------------------------------------------------

class TestVerboseMode:
    def test_agent_reasoning_omitted_without_verbose(self):
        report = render_markdown(
            make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, agent_reasoning="full trace here")
        )
        assert "full trace here" not in report
        assert "Omitted" in report

    def test_agent_reasoning_included_with_verbose(self):
        report = render_markdown(
            make_scan_result(
                ValidationStatus.VALIDATED_EXPLOIT, agent_reasoning="full trace here"
            ),
            verbose=True,
        )
        assert "full trace here" in report

    def test_verbose_false_by_default(self):
        report = render_markdown(
            make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, agent_reasoning="secret trace")
        )
        assert "secret trace" not in report


# ---------------------------------------------------------------------------
# TestMetadataBlock
# ---------------------------------------------------------------------------

class TestMetadataBlock:
    def test_contract_address_present(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert _CONTRACT in report

    def test_scan_timestamp_present(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "2026-03-22T10:45:00Z" in report

    def test_skanf_digest_present(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert _DIGEST in report

    def test_model_version_present(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert _MODEL in report

    def test_runtime_seconds_present(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "42.3s" in report


# ---------------------------------------------------------------------------
# TestExploitCalldataSection
# ---------------------------------------------------------------------------

class TestExploitCalldataSection:
    def test_calldata_in_fenced_block_for_validated_exploit(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        assert "```json" in report
        assert _CALLDATA_HEX in report

    def test_no_exploit_calldata_for_clean(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "No exploit calldata generated." in report

    def test_no_exploit_calldata_for_agent_proposed(self):
        report = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        assert "No exploit calldata generated." in report

    def test_no_exploit_calldata_for_skanf_detected(self):
        report = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        assert "No exploit calldata generated." in report

    def test_calldata_json_fields_present(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        assert '"calldata"' in report
        assert '"target_address"' in report
        assert '"value"' in report
        assert '"caller"' in report
        assert '"origin"' in report


# ---------------------------------------------------------------------------
# TestLanguageRules
# ---------------------------------------------------------------------------

class TestLanguageRules:
    def test_confirmed_vulnerability_phrase_in_validated_exploit_body(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        # Strip headline so assertion targets body prose, not the all-caps heading
        body = report.replace("## Finding: CONFIRMED VULNERABILITY", "")
        assert "confirmed vulnerability" in body.lower()

    def test_potential_vulnerability_unconfirmed_phrase_in_agent_proposed(self):
        report = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        lower_report = report.lower()
        assert "potential vulnerability" in lower_report
        assert "unconfirmed" in lower_report

    def test_potential_vulnerability_unconfirmed_phrase_in_skanf_detected(self):
        report = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        lower_report = report.lower()
        assert "potential vulnerability" in lower_report
        assert "unconfirmed" in lower_report

    def test_no_exploitable_vulnerability_detected_by_specter_phrase_in_clean(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "no exploitable vulnerability detected by Specter" in report

    def test_clean_scope_qualifier_text(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "Specter" in report


# ---------------------------------------------------------------------------
# TestValidationResultSection
# ---------------------------------------------------------------------------

class TestValidationResultSection:
    def test_validated_exploit_includes_tier_classification(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        # Should mention EVM simulation and confirmed
        assert "EVM simulation" in report
        assert "confirmed vulnerability" in report.lower()

    def test_validated_exploit_live_balance_noted(self):
        report = render_markdown(make_scan_result(ValidationStatus.VALIDATED_EXPLOIT))
        assert "Live balance confirmed" in report

    def test_agent_proposed_unvalidated_validation_result(self):
        report = render_markdown(make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED))
        vr_idx = report.find("### Validation Result")
        assert vr_idx != -1
        vr_section = report[vr_idx:]
        assert "CALL" in vr_section

    def test_clean_validation_result_prose(self):
        report = render_markdown(make_scan_result(ValidationStatus.CLEAN))
        assert "SKANF analysis found no vulnerability" in report

    def test_skanf_detected_unexploited_validation_result(self):
        report = render_markdown(make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED))
        # Should mention failed to confirm
        assert "SKANF" in report

    def test_validated_exploit_no_validation_result_skanf_direct(self):
        # Simulates cli.py _assemble_exploit_generated_result — Finding with no validation_result
        finding = Finding(
            exploit_calldata=AgentCalldata(
                calldata=_CALLDATA_HEX,
                target_address=_CONTRACT,
                value=0,
                caller=_ZERO,
                origin=_ZERO,
            )
        )
        result = ScanResult(
            contract_address=_CONTRACT,
            scan_timestamp=_TIMESTAMP,
            skanf_version_digest=_DIGEST,
            model_version=_MODEL,
            validation_status=ValidationStatus.VALIDATED_EXPLOIT,
            finding=finding,
            runtime_seconds=42.3,
            error=None,
        )
        report = render_markdown(result)
        assert "## Finding: CONFIRMED VULNERABILITY" in report
        assert "SKANF generated a direct exploit" in report


# ---------------------------------------------------------------------------
# TestDisclosureNotice
# ---------------------------------------------------------------------------

BANNED_PHRASES = ["you must", "you should", "it is your responsibility", "you are obligated"]


class TestDisclosureNotice:
    def test_notice_present_validated_exploit_live_balance_true(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        assert "## Responsible Disclosure Notice" in report

    def test_notice_absent_validated_exploit_live_balance_false(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=False)
        report = render_markdown(result)
        assert "## Responsible Disclosure Notice" not in report

    def test_notice_absent_agent_proposed_unvalidated(self):
        result = make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED)
        report = render_markdown(result)
        assert "## Responsible Disclosure Notice" not in report

    def test_notice_absent_skanf_detected_unexploited(self):
        result = make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED)
        report = render_markdown(result)
        assert "## Responsible Disclosure Notice" not in report

    def test_notice_absent_clean(self):
        result = make_scan_result(ValidationStatus.CLEAN)
        report = render_markdown(result)
        assert "## Responsible Disclosure Notice" not in report

    def test_notice_absent_skanf_direct_passthrough(self):
        result = ScanResult(
            contract_address=_CONTRACT,
            scan_timestamp=_TIMESTAMP,
            skanf_version_digest=_DIGEST,
            model_version=_MODEL,
            validation_status=ValidationStatus.VALIDATED_EXPLOIT,
            finding=Finding(
                skanf_summary="SKANF generated direct exploit.",
                validation_result=None,
                exploit_calldata=None,
            ),
            runtime_seconds=12.0,
            error=None,
        )
        report = render_markdown(result)
        assert "## Responsible Disclosure Notice" not in report

    def test_notice_content_blockquote_format(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        notice_start = report.index("## Responsible Disclosure Notice")
        # Isolate only the notice section body (not the heading, not any future section)
        rest = report[notice_start + len("## Responsible Disclosure Notice"):]
        next_section = re.search(r"\n#{1,6} ", rest)
        notice_body = rest[: next_section.start()] if next_section else rest
        blockquote_lines = [l for l in notice_body.splitlines() if l.strip()]
        assert blockquote_lines, "No blockquote lines found in notice"
        for line in blockquote_lines:
            assert line.startswith(">"), f"Notice line does not start with '>': {line!r}"

    def test_notice_content_contains_immunefi(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        notice_start = report.index("## Responsible Disclosure Notice")
        notice_text = report[notice_start:]
        assert "Immunefi" in notice_text

    def test_notice_content_contains_security_at_protocol(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        notice_start = report.index("## Responsible Disclosure Notice")
        notice_text = report[notice_start:]
        assert "security@[protocol]" in notice_text

    def test_notice_content_neutral_tone(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        notice_start = report.index("## Responsible Disclosure Notice")
        notice_text = report[notice_start:].lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in notice_text, f"Banned phrase found in notice: {phrase!r}"

    def test_notice_appears_after_remediation(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        remediation_pos = report.index("### Recommended Remediation")
        notice_pos = report.index("## Responsible Disclosure Notice")
        assert notice_pos > remediation_pos

    def test_no_ansi_codes_with_notice(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT, live_balance=True)
        report = render_markdown(result)
        assert not ANSI_ESCAPE.search(report), "ANSI escape codes found when notice is present"
