"""Tests for Story 4.4: --output flag, --verbose mode, and TTY color detection."""
from __future__ import annotations

import os
import sys

import pytest
from typer.testing import CliRunner
from unittest.mock import ANY, patch

from specter.cli import app
from specter.models import (
    AgentCalldata,
    Finding,
    ScanResult,
    SkfnOutput,
    SkfnState,
    ValidationResult,
    ValidationStatus,
    ValidationTier,
)
from specter.output.markdown import render_markdown

# Import the shared test helper
sys.path.insert(0, os.path.dirname(__file__))
from test_markdown import make_scan_result

runner = CliRunner()

_VALID_ADDRESS = "0x" + "A" * 40


def _invoke_scan_clean(extra_args: list[str] | None = None) -> object:
    """Invoke `specter scan` with a mocked CLEAN SKANF result."""
    args = ["scan", _VALID_ADDRESS] + (extra_args or [])
    with patch("specter.cli.run_skanf") as mock_run, \
         patch("specter.cli.validate_env"), \
         patch("specter.cli._register_secret_filter"), \
         patch("specter.cli._set_log_level"):
        mock_run.return_value = SkfnOutput(
            state=SkfnState.CLEAN, raw_output="", container_exit_code=0
        )
        return runner.invoke(app, args)


class TestOutputFlags:

    # ------------------------------------------------------------------
    # AC1: --output writes markdown to file AND stdout
    # ------------------------------------------------------------------

    def test_output_flag_writes_markdown_to_file(self, tmp_path):
        report_path = str(tmp_path / "report.md")
        _invoke_scan_clean(["--output", report_path])
        assert os.path.exists(report_path)
        content = open(report_path).read()
        assert "# Specter Scan Report" in content
        assert "validation_status" not in content  # no JSON field names

    def test_output_flag_also_prints_to_stdout(self, tmp_path):
        report_path = str(tmp_path / "report.md")
        result = _invoke_scan_clean(["--output", report_path])
        assert "# Specter Scan Report" in result.output

    def test_output_file_content_matches_stdout(self, tmp_path):
        report_path = str(tmp_path / "report.md")
        result = _invoke_scan_clean(["--output", report_path])
        file_content = open(report_path).read()
        # In non-TTY test runs color=False for both; content must be byte-for-byte identical
        assert file_content.rstrip("\n") == result.stdout.rstrip("\n")

    def test_output_file_has_no_ansi_codes(self, tmp_path):
        report_path = str(tmp_path / "report.md")
        _invoke_scan_clean(["--output", report_path])
        content = open(report_path).read()
        assert "\x1b[" not in content

    def test_json_flag_with_output_writes_json_to_file(self, tmp_path):
        """--json --output writes JSON (not markdown) to file, matching stdout format."""
        import json
        report_path = str(tmp_path / "report.json")
        args = ["scan", _VALID_ADDRESS, "--json", "--output", report_path]
        with patch("specter.cli.run_skanf") as mock_run, \
             patch("specter.cli.validate_env"), \
             patch("specter.cli._register_secret_filter"), \
             patch("specter.cli._set_log_level"):
            mock_run.return_value = SkfnOutput(
                state=SkfnState.CLEAN, raw_output="", container_exit_code=0
            )
            runner.invoke(app, args)
        content = open(report_path).read()
        data = json.loads(content)
        assert "validation_status" in data
        assert "# Specter Scan Report" not in content

    # ------------------------------------------------------------------
    # AC2: --verbose populates Agent Reasoning section
    # ------------------------------------------------------------------

    def test_verbose_populates_agent_reasoning(self):
        finding = Finding(
            exploit_calldata=AgentCalldata(
                calldata="0xdeadbeef",
                target_address="0x" + "A" * 40,
                caller="0x" + "0" * 40,
                origin="0x" + "0" * 40,
            ),
            validation_result=ValidationResult.from_tier(
                tier=ValidationTier.FULL_SUCCESS, live_balance=False
            ),
            agent_reasoning="Step 1: analyze tainted bytes...\nStep 2: construct calldata...",
        )
        from datetime import datetime, timezone
        result = ScanResult(
            contract_address="0x" + "A" * 40,
            scan_timestamp=datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc),
            skanf_version_digest="sha256:abc123",
            model_version="claude-sonnet-4-6",
            validation_status=ValidationStatus.VALIDATED_EXPLOIT,
            finding=finding,
            runtime_seconds=1.0,
            error=None,
        )
        output = render_markdown(result, verbose=True)
        assert "Step 1: analyze tainted bytes" in output

    def test_no_verbose_omits_agent_reasoning(self):
        result = make_scan_result(
            ValidationStatus.VALIDATED_EXPLOIT,
            agent_reasoning="secret reasoning trace",
        )
        output = render_markdown(result, verbose=False)
        assert "secret reasoning trace" not in output
        assert "Omitted" in output

    def test_verbose_flag_wires_to_render_markdown(self):
        """--verbose CLI flag passes verbose=True through to render_markdown."""
        with patch("specter.cli.run_skanf") as mock_run, \
             patch("specter.cli.validate_env"), \
             patch("specter.cli._register_secret_filter"), \
             patch("specter.cli._set_log_level"), \
             patch("specter.cli.render_markdown", return_value="# Specter Scan Report\n") as mock_render:
            mock_run.return_value = SkfnOutput(
                state=SkfnState.CLEAN, raw_output="", container_exit_code=0
            )
            runner.invoke(app, ["scan", _VALID_ADDRESS, "--verbose"])
        mock_render.assert_called_once_with(ANY, verbose=True, color=ANY)

    # ------------------------------------------------------------------
    # AC3: TTY color on stdout when terminal detected
    # ------------------------------------------------------------------

    def test_color_adds_ansi_to_confirmed_vulnerability(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        output = render_markdown(result, color=True)
        assert "\x1b[" in output
        assert "CONFIRMED VULNERABILITY" in output
        assert "## Finding:" in output

    def test_color_adds_ansi_to_potential_vulnerability(self):
        result = make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED)
        output = render_markdown(result, color=True)
        assert "\x1b[" in output
        assert "POTENTIAL VULNERABILITY" in output

    def test_color_adds_ansi_to_skanf_detected_unexploited(self):
        result = make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED)
        output = render_markdown(result, color=True)
        assert "\x1b[" in output
        assert "POTENTIAL VULNERABILITY" in output

    def test_color_adds_ansi_to_no_vulnerability(self):
        result = make_scan_result(ValidationStatus.CLEAN)
        output = render_markdown(result, color=True)
        assert "\x1b[" in output
        assert "NO VULNERABILITY DETECTED" in output

    # ------------------------------------------------------------------
    # AC4: No ANSI in non-TTY (redirect/pipe)
    # ------------------------------------------------------------------

    def test_no_color_no_ansi_in_output(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        output = render_markdown(result, color=False)
        assert "\x1b[" not in output
        assert "CONFIRMED VULNERABILITY" in output

    def test_color_text_always_present(self):
        """ANSI-colored output still contains the full text label — color is never the sole signal."""
        for status, label in [
            (ValidationStatus.VALIDATED_EXPLOIT, "CONFIRMED VULNERABILITY"),
            (ValidationStatus.AGENT_PROPOSED_UNVALIDATED, "POTENTIAL VULNERABILITY"),
            (ValidationStatus.CLEAN, "NO VULNERABILITY DETECTED"),
        ]:
            result = make_scan_result(status)
            output = render_markdown(result, color=True)
            assert label in output, f"Text label missing for {status}"

    # ------------------------------------------------------------------
    # AC3/AC4: TTY detection wiring in cli.py
    # ------------------------------------------------------------------

    def test_color_is_applied_when_stdout_is_tty(self):
        """When sys.stdout.isatty()=True, render_markdown is called with color=True."""
        with patch("specter.cli.run_skanf") as mock_run, \
             patch("specter.cli.validate_env"), \
             patch("specter.cli._register_secret_filter"), \
             patch("specter.cli._set_log_level"), \
             patch("specter.cli.render_markdown", return_value="# Specter Scan Report\n") as mock_render, \
             patch("specter.cli.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            mock_sys.stderr.isatty.return_value = False
            mock_run.return_value = SkfnOutput(
                state=SkfnState.CLEAN, raw_output="", container_exit_code=0
            )
            runner.invoke(app, ["scan", _VALID_ADDRESS])
        mock_render.assert_called_once_with(ANY, verbose=ANY, color=True)
