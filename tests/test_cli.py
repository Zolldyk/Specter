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

    def test_clean_state_no_json_on_stdout_by_default(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert result.stdout == ""

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
    """--output flag writes JSON to file for terminal states."""

    def test_clean_state_writes_json_to_output_file(self, monkeypatch, tmp_path):
        output_file = tmp_path / "result.json"
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("specter.cli.run_skanf", _mock_run_skanf_returning(SkfnState.CLEAN))
        result = runner.invoke(app, ["scan", "--output", str(output_file), VALID_ADDRESS])
        assert result.exit_code == 0
        assert output_file.exists()
        assert "clean" in output_file.read_text()

    def test_exploit_generated_writes_json_to_output_file(self, monkeypatch, tmp_path):
        output_file = tmp_path / "result.json"
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.EXPLOIT_GENERATED, CALLDATA_RAW),
        )
        result = runner.invoke(app, ["scan", "--output", str(output_file), VALID_ADDRESS])
        assert result.exit_code == 1
        assert output_file.exists()
        assert "validated_exploit" in output_file.read_text()


from specter.models import SkfnContext  # noqa: E402

MOCK_CONTEXT = SkfnContext(
    contract_address="0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
    raw_output=STALL_RAW,
)


class TestScanStalledState:
    """AC2/AC4: stalled state → [2/4] progress message emitted, parse_skanf called."""

    def test_stalled_state_emits_stage_2_progress(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
        result = runner.invoke(app, ["scan", VALID_ADDRESS])
        assert "[2/4] Parsing vulnerability report..." in result.stderr

    def test_stalled_state_exits_zero(self, monkeypatch):
        """Stalled path exits 0 after parser stage (stub for Story 3.1 agent call)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr(
            "specter.cli.run_skanf",
            _mock_run_skanf_returning(SkfnState.STALLED, STALL_RAW),
        )
        monkeypatch.setattr("specter.cli.parse_skanf", lambda *a, **kw: MOCK_CONTEXT)
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
        runner.invoke(app, ["scan", VALID_ADDRESS])
        mock_parse.assert_called_once()
        skanf_arg, target_arg = mock_parse.call_args.args
        assert skanf_arg.state == SkfnState.STALLED
        assert target_arg.value == VALID_ADDRESS
        assert "timeout" in mock_parse.call_args.kwargs

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
