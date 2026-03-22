"""Tests for specter CLI entry point (Story 1.1)."""
import socket
import subprocess
import time

from typer.testing import CliRunner

from specter import __version__
from specter.cli import app
from specter.config import MODEL_VERSION, SKANF_IMAGE_DIGEST

runner = CliRunner()


def test_help_lists_scan_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_help_lists_check_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "check" in result.output


def test_help_lists_version_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.output


def test_entry_point_subprocess_help():
    """Validates pyproject.toml entry point wiring via real subprocess invocation (AC1)."""
    result = subprocess.run(
        ["uv", "run", "specter", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "check" in result.stdout
    assert "version" in result.stdout


def test_scan_accepts_valid_address_target(monkeypatch):
    """scan command accepts a valid Ethereum address and runs SKANF pipeline (runner mocked)."""
    from unittest.mock import MagicMock
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    mock_proc = MagicMock(returncode=0, stdout="Running gigahorse.py\nYes", stderr="")
    monkeypatch.setattr("specter.pipeline.runner.subprocess.run", lambda cmd, **kw: mock_proc)
    monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: "deadbeef" * 12)
    result = runner.invoke(app, ["scan", "0x" + "a" * 40])
    assert result.exit_code == 0


def test_scan_emits_progress_to_stderr(monkeypatch):
    """AC3: [1/4] Running SKANF analysis... must appear on stderr (non-TTY path)."""
    from unittest.mock import MagicMock
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    mock_proc = MagicMock(returncode=0, stdout="Running gigahorse.py\nYes", stderr="")
    monkeypatch.setattr("specter.pipeline.runner.subprocess.run", lambda cmd, **kw: mock_proc)
    monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: "deadbeef" * 12)
    result = runner.invoke(app, ["scan", "0x" + "a" * 40])
    assert "[1/4] Running SKANF analysis..." in result.stderr


def test_scan_invalid_target_exits_3_with_error_format(monkeypatch):
    """Invalid target raises ConfigError → ERROR [ConfigError]: ... on stderr + exit 3."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    result = runner.invoke(app, ["scan", "not-a-valid-target"])
    assert result.exit_code == 3
    assert "ERROR [ConfigError]:" in result.stderr


def test_check_exits_zero_when_all_ok(monkeypatch):
    """Replaces test_check_stub_runs: all deps OK → exit 0."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0


def test_check_anthropic_key_missing_exits_3(monkeypatch):
    """AC2: missing ANTHROPIC_API_KEY → exit 3 with ✗ line on stderr."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 3
    assert "✗  ANTHROPIC_API_KEY" in result.stderr


def test_check_anthropic_key_missing_shows_fix(monkeypatch):
    """AC2: fix command shown when ANTHROPIC_API_KEY missing."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    result = runner.invoke(app, ["check"])
    assert "export ANTHROPIC_API_KEY=your_key_here" in result.stderr


def test_check_docker_not_running_exits_3(monkeypatch):
    """AC3: Docker daemon not running → exit 3 with ✗ line on stderr."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")

    def mock_run(args, **kwargs):
        raise __import__("subprocess").CalledProcessError(1, args)

    monkeypatch.setattr("specter.config.subprocess.run", mock_run)
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 3
    assert "✗  Docker daemon" in result.stderr


def test_check_docker_not_running_shows_fix(monkeypatch):
    """AC3: fix instruction names Docker daemon specifically when daemon not running."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")

    def mock_run(args, **kwargs):
        raise __import__("subprocess").CalledProcessError(1, args)

    monkeypatch.setattr("specter.config.subprocess.run", mock_run)
    result = runner.invoke(app, ["check"])
    assert "Start Docker Desktop or run: sudo systemctl start docker" in result.stderr


def test_check_stdout_is_empty(monkeypatch):
    """AC5: all output goes to stderr; stdout is empty."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    result = runner.invoke(app, ["check"])
    assert result.stdout == ""


def test_check_does_not_leak_api_key(monkeypatch):
    """AC6: API key value never appears in any output."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "super-secret-check-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    result = runner.invoke(app, ["check"])
    assert "super-secret-check-key" not in result.stdout  # stdout always empty (AC5)
    assert "super-secret-check-key" not in result.stderr  # real protection: secret filter on stderr


def test_check_skanf_image_not_found_exits_3(monkeypatch):
    """SKANF image missing with Docker running → exit 3 with ✗ SKANF image on stderr."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")

    def mock_run(args, **kwargs):
        if args[:2] == ["docker", "info"]:
            return __import__("subprocess").CompletedProcess(args, 0)
        raise __import__("subprocess").CalledProcessError(1, args)

    monkeypatch.setattr("specter.config.subprocess.run", mock_run)
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 3
    assert "✗  SKANF image" in result.stderr


def test_check_completes_under_10_seconds(monkeypatch):
    """AC4: specter check completes in under 10 seconds."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    start = time.perf_counter()
    result = runner.invoke(app, ["check"])
    elapsed = time.perf_counter() - start
    assert result.exit_code == 0
    assert elapsed < 10.0


def test_check_label_format_22_chars(monkeypatch):
    """AC1: label padded to 22 chars in output line."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr(
        "specter.config.subprocess.run",
        lambda args, **kw: __import__("subprocess").CompletedProcess(args, 0),
    )
    result = runner.invoke(app, ["check"])
    # "ANTHROPIC_API_KEY" is 17 chars, padded to 22 = 5 trailing spaces before 2-space gap
    assert "✓  ANTHROPIC_API_KEY       " in result.stderr


def test_version_stub_runs():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


# Story 1.5 — version command tests


def test_version_outputs_to_stderr():
    """AC1: version info written to stderr, not stdout."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "specter" in result.stderr
    assert "specter" not in result.stdout


def test_version_contains_package_version():
    """AC1: package version string present in output."""
    result = runner.invoke(app, ["version"])
    assert __version__ in result.output


def test_version_contains_skanf_digest():
    """AC1: SKANF_IMAGE_DIGEST value present in output."""
    result = runner.invoke(app, ["version"])
    assert SKANF_IMAGE_DIGEST in result.output


def test_version_contains_model_version():
    """AC1: MODEL_VERSION value present in output."""
    result = runner.invoke(app, ["version"])
    assert MODEL_VERSION in result.output


def test_version_stdout_is_empty():
    """AC2: stdout is empty — all output goes to stderr."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout == ""


def test_version_no_api_key_required(monkeypatch):
    """AC2: version exits 0 even without ANTHROPIC_API_KEY set."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


def test_version_does_not_leak_api_key(monkeypatch):
    """AC3: API key value never appears in stdout or stderr."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "super-secret-key")
    result = runner.invoke(app, ["version"])
    assert "super-secret-key" not in result.stdout
    assert "super-secret-key" not in result.stderr


def test_version_completes_under_one_second():
    """AC2: command returns in under 1 second."""
    start = time.perf_counter()
    result = runner.invoke(app, ["version"])
    elapsed = time.perf_counter() - start
    assert result.exit_code == 0
    assert elapsed < 1.0


def test_version_makes_no_network_calls(monkeypatch):
    """AC2: zero network calls made."""

    def no_connect(*args, **kwargs):
        raise AssertionError(f"version command made a network call: {args}")

    monkeypatch.setattr(socket, "getaddrinfo", no_connect)
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


def test_version_output_labels():
    """Output labels match documented format spec."""
    result = runner.invoke(app, ["version"])
    assert "SKANF image:" in result.stderr
    assert "Claude model:" in result.stderr


# ---------------------------------------------------------------------------
# Story 2.3 — State-based branching tests
# ---------------------------------------------------------------------------

from specter.models import SkfnOutput, SkfnState  # noqa: E402

VALID_ADDRESS = "0x" + "a" * 40
CALLDATA_RAW = "INFO | greed | CALLDATA: 1cff79cd" + "00" * 64
STALL_RAW = "INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (134_1)"
CLEAN_RAW = "Running gigahorse.py\nYes"


def _mock_run_skanf_returning(state: SkfnState, raw_output: str = ""):
    return lambda *a, **kw: SkfnOutput(
        state=state,
        raw_output=raw_output,
        container_exit_code=0,
        vulnerability_json="[]",
    )


class TestScanCleanState:
    """AC3: clean state → exit 0, footer on stderr, no agent/validator."""

    def test_clean_state_exits_zero(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 0

    def test_clean_state_emits_footer_to_stderr(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "Specter scan complete" in result.stderr

    def test_clean_state_footer_contains_clean_status(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "clean" in result.stderr

    def test_clean_state_markdown_on_stdout_by_default(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "# Specter Scan Report" in result.stdout
        assert "## Finding: NO VULNERABILITY DETECTED" in result.stdout

    def test_clean_state_json_flag_outputs_validated_status(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        assert "clean" in result.output


class TestScanExploitGeneratedState:
    """AC1: exploit_generated state → exit 1, VALIDATED_EXPLOIT in JSON output."""

    def test_exploit_generated_exits_one(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.EXPLOIT_GENERATED, CALLDATA_RAW),
        )
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 1

    def test_exploit_generated_json_contains_validated_exploit(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.EXPLOIT_GENERATED, CALLDATA_RAW),
        )
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        assert "validated_exploit" in result.output

    def test_exploit_generated_emits_footer_to_stderr(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.EXPLOIT_GENERATED, CALLDATA_RAW),
        )
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "Specter scan complete" in result.stderr

    def test_exploit_generated_unextractable_calldata_raises_error(self, monkeypatch):
        """H2 guard: EXPLOIT_GENERATED with non-hex calldata → SkfnContainerError, exit 3."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(
                SkfnState.EXPLOIT_GENERATED,
                "INFO | greed | CALLDATA: !!!not-hex!!!",
            ),
        )
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 3
        assert "ERROR [SkfnContainerError]" in result.stderr


class TestScanOutputFlag:
    """--output flag writes markdown report to file for terminal states."""

    def test_clean_state_writes_markdown_to_output_file(self, monkeypatch, tmp_path):
        output_file = tmp_path / "result.md"
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", "--output", str(output_file), VALID_ADDRESS])
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "# Specter Scan Report" in content
        assert "NO VULNERABILITY DETECTED" in content

    def test_exploit_generated_writes_markdown_to_output_file(self, monkeypatch, tmp_path):
        output_file = tmp_path / "result.md"
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.EXPLOIT_GENERATED, CALLDATA_RAW),
        )
        result = runner.invoke(app, ["scan", "--output", str(output_file), VALID_ADDRESS])
        assert result.exit_code == 1
        assert output_file.exists()
        content = output_file.read_text()
        assert "# Specter Scan Report" in content
        assert "CONFIRMED VULNERABILITY" in content


from specter.models import AgentCalldata, SkfnContext, ValidationResult, ValidationStatus, ValidationTier  # noqa: E402

MOCK_CONTEXT = SkfnContext(
    contract_address="0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
    raw_output=STALL_RAW,
)

MOCK_AGENT_CALLDATA = AgentCalldata(
    calldata="0x1cff79cd",
    target_address="0x" + "a" * 40,
    caller="0x" + "0" * 40,
    origin="0x" + "0" * 40,
)

MOCK_VALIDATION_RESULT_PARTIAL = ValidationResult.from_tier(
    ValidationTier.PARTIAL_SUCCESS, live_balance=False
)

MOCK_VALIDATION_RESULT_FULL = ValidationResult.from_tier(
    ValidationTier.FULL_SUCCESS, live_balance=False
)

MOCK_VALIDATION_RESULT_FAILURE = ValidationResult.from_tier(
    ValidationTier.FAILURE, live_balance=False
)


class TestScanStalledState:
    """AC2/AC4/AC6/AC8/AC9/AC10: stalled state → full pipeline with validator call."""

    def _mock_stalled(self, monkeypatch, validation_result=None):
        """Helper: set up mocks for a complete stalled pipeline invocation."""
        if validation_result is None:
            validation_result = MOCK_VALIDATION_RESULT_PARTIAL
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        monkeypatch.setattr("specter.cli.call_agent", lambda *a, **kw: MOCK_AGENT_CALLDATA)
        monkeypatch.setattr("specter.cli.call_validator", lambda *a, **kw: validation_result)

    def test_stalled_state_emits_stage_2_progress(self, monkeypatch):
        self._mock_stalled(monkeypatch)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "[2/4] Parsing vulnerability report..." in result.stderr

    def test_stalled_state_emits_stage_3_progress(self, monkeypatch):
        """AC6: [3/4] Calling agent... must appear on stderr."""
        self._mock_stalled(monkeypatch)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "[3/4] Calling agent..." in result.stderr

    def test_stalled_state_emits_stage_4_progress(self, monkeypatch):
        """AC8: [4/4] Validating exploit... must appear on stderr."""
        self._mock_stalled(monkeypatch)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "[4/4] Validating exploit..." in result.stderr

    def test_stalled_state_exits_two_for_partial_success(self, monkeypatch):
        """AC10: AGENT_PROPOSED_UNVALIDATED → exit 2."""
        self._mock_stalled(monkeypatch, MOCK_VALIDATION_RESULT_PARTIAL)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 2

    def test_stalled_state_exits_one_for_full_success(self, monkeypatch):
        """AC10: VALIDATED_EXPLOIT → exit 1."""
        self._mock_stalled(monkeypatch, MOCK_VALIDATION_RESULT_FULL)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 1

    def test_stalled_state_exits_zero_for_failure(self, monkeypatch):
        """AC10: SKANF_DETECTED_UNEXPLOITED → exit 0."""
        self._mock_stalled(monkeypatch, MOCK_VALIDATION_RESULT_FAILURE)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 0

    def test_stalled_state_calls_parse_skanf(self, monkeypatch):
        """parse_skanf must be called once with correct args in the stalled branch (AC4)."""
        from unittest.mock import MagicMock
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        mock_parse = MagicMock(return_value=MOCK_CONTEXT)
        monkeypatch.setattr("specter.cli.parse_skanf", mock_parse)
        monkeypatch.setattr("specter.cli.call_agent", lambda *a, **kw: MOCK_AGENT_CALLDATA)
        monkeypatch.setattr("specter.cli.call_validator", lambda *a, **kw: MOCK_VALIDATION_RESULT_PARTIAL)
        runner.invoke(app, ["scan", VALID_ADDRESS])
        mock_parse.assert_called_once()
        skanf_arg, target_arg = mock_parse.call_args.args
        assert skanf_arg.state == SkfnState.STALLED
        assert target_arg.value == VALID_ADDRESS
        assert "timeout" in mock_parse.call_args.kwargs

    def test_stalled_state_calls_call_agent(self, monkeypatch):
        """call_agent must be called once with correct context after parse_skanf (AC1)."""
        from unittest.mock import MagicMock
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        mock_agent = MagicMock(return_value=MOCK_AGENT_CALLDATA)
        monkeypatch.setattr("specter.cli.call_agent", mock_agent)
        monkeypatch.setattr("specter.cli.call_validator", lambda *a, **kw: MOCK_VALIDATION_RESULT_PARTIAL)
        runner.invoke(app, ["scan", VALID_ADDRESS])
        mock_agent.assert_called_once()
        context_arg = mock_agent.call_args.args[0]
        assert context_arg is MOCK_CONTEXT
        assert "timeout" in mock_agent.call_args.kwargs

    def test_stalled_state_calls_call_validator(self, monkeypatch):
        """call_validator must be called with agent_result and context (AC1)."""
        from unittest.mock import MagicMock
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        monkeypatch.setattr("specter.cli.call_agent", lambda *a, **kw: MOCK_AGENT_CALLDATA)
        mock_validator = MagicMock(return_value=MOCK_VALIDATION_RESULT_PARTIAL)
        monkeypatch.setattr("specter.cli.call_validator", mock_validator)
        runner.invoke(app, ["scan", VALID_ADDRESS])
        mock_validator.assert_called_once()
        agent_arg, context_arg = mock_validator.call_args.args
        assert agent_arg is MOCK_AGENT_CALLDATA
        assert context_arg is MOCK_CONTEXT
        assert "timeout" in mock_validator.call_args.kwargs

    def test_stalled_state_assembles_scan_result(self, monkeypatch):
        """AC9: ScanResult assembled from SkfnOutput, SkfnContext, AgentCalldata, ValidationResult."""
        self._mock_stalled(monkeypatch, MOCK_VALIDATION_RESULT_PARTIAL)
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        assert "agent_proposed_unvalidated" in result.output

    def test_stalled_state_emits_footer(self, monkeypatch):
        self._mock_stalled(monkeypatch)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "Specter scan complete" in result.stderr

    def test_stalled_state_no_stub_message(self, monkeypatch):
        """Stub message must be REMOVED from output."""
        self._mock_stalled(monkeypatch)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "validator stage not yet implemented" not in result.stderr

    def test_stalled_parse_error_exits_3_with_error_format(self, monkeypatch):
        """SkfnParseError from parse_skanf → exit 3, ERROR [SkfnParseError] on stderr."""
        from unittest.mock import MagicMock
        from specter.errors import SkfnParseError
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        mock_parse = MagicMock(
            side_effect=SkfnParseError("SKANF vulnerability.json is not valid JSON")
        )
        monkeypatch.setattr("specter.cli.parse_skanf", mock_parse)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 3
        assert "ERROR [SkfnParseError]" in result.stderr

    def test_stalled_agent_error_exits_3_with_error_format(self, monkeypatch):
        """AgentError from call_agent → exit 3, ERROR [AgentError] on stderr."""
        from unittest.mock import MagicMock
        from specter.errors import AgentError
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        mock_agent = MagicMock(side_effect=AgentError("Claude API returned HTTP 429: Rate limited"))
        monkeypatch.setattr("specter.cli.call_agent", mock_agent)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 3
        assert "ERROR [AgentError]" in result.stderr
        assert "429" in result.stderr

    def test_stalled_validator_error_exits_3_with_error_format(self, monkeypatch):
        """SprecterValidationError from call_validator → exit 3, ERROR [SprecterValidationError]."""
        from unittest.mock import MagicMock
        from specter.errors import SprecterValidationError
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        monkeypatch.setattr("specter.cli.call_agent", lambda *a, **kw: MOCK_AGENT_CALLDATA)
        mock_validator = MagicMock(
            side_effect=SprecterValidationError("SKANF validation container exited with code 1")
        )
        monkeypatch.setattr("specter.cli.call_validator", mock_validator)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 3
        assert "ERROR [SprecterValidationError]" in result.stderr


class TestStalledPipelineIntegration:
    """AC7/AC8: full STALLED pipeline end-to-end — ScanResult assembly and exit codes."""

    def _setup(self, monkeypatch, validation_result):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        monkeypatch.setattr("specter.cli.call_agent", lambda *a, **kw: MOCK_AGENT_CALLDATA)
        monkeypatch.setattr("specter.cli.call_validator", lambda *a, **kw: validation_result)

    def test_full_success_live_balance_true_exits_one(self, monkeypatch):
        """AC7: full_success with live_balance=True → VALIDATED_EXPLOIT, exit 1."""
        vr = ValidationResult.from_tier(ValidationTier.FULL_SUCCESS, live_balance=True)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 1

    def test_full_success_scan_result_status_validated_exploit(self, monkeypatch):
        """AC7: validation_status=VALIDATED_EXPLOIT in assembled ScanResult JSON."""
        vr = ValidationResult.from_tier(ValidationTier.FULL_SUCCESS, live_balance=True)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        assert "validated_exploit" in result.output

    def test_partial_success_exits_two(self, monkeypatch):
        """AC8: partial_success → AGENT_PROPOSED_UNVALIDATED, exit 2."""
        vr = ValidationResult.from_tier(ValidationTier.PARTIAL_SUCCESS, live_balance=False)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 2

    def test_partial_success_scan_result_status(self, monkeypatch):
        """AC8: AGENT_PROPOSED_UNVALIDATED in JSON output."""
        vr = ValidationResult.from_tier(ValidationTier.PARTIAL_SUCCESS, live_balance=False)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        assert "agent_proposed_unvalidated" in result.output

    def test_failure_exits_zero(self, monkeypatch):
        """AC8: failure → SKANF_DETECTED_UNEXPLOITED, exit 0."""
        vr = ValidationResult.from_tier(ValidationTier.FAILURE, live_balance=False)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.exit_code == 0

    def test_failure_scan_result_status(self, monkeypatch):
        """AC8: SKANF_DETECTED_UNEXPLOITED in JSON output."""
        vr = ValidationResult.from_tier(ValidationTier.FAILURE, live_balance=False)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        assert "skanf_detected_unexploited" in result.output

    def test_live_balance_true_propagated_to_scan_result(self, monkeypatch):
        """AC7: live_balance=True propagates to ScanResult.finding.validation_result.live_balance."""
        import json
        vr = ValidationResult.from_tier(ValidationTier.FULL_SUCCESS, live_balance=True)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        data = json.loads(result.stdout)
        assert data["finding"]["validation_result"]["live_balance"] is True

    def test_live_balance_false_propagated_to_scan_result(self, monkeypatch):
        """AC7: live_balance=False propagates to ScanResult.finding.validation_result.live_balance."""
        import json
        vr = ValidationResult.from_tier(ValidationTier.PARTIAL_SUCCESS, live_balance=False)
        self._setup(monkeypatch, vr)
        result = runner.invoke(app, ["scan", "--json", VALID_ADDRESS])
        data = json.loads(result.stdout)
        assert data["finding"]["validation_result"]["live_balance"] is False
