"""Unit tests for specter.pipeline.runner (Story 2.2 + 2.3)."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from specter.errors import ConfigError, SkfnContainerError
from specter.models import ScanTarget, SkfnOutput, SkfnState
from specter.pipeline.runner import _detect_state, _fetch_bytecode, run_skanf

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_ADDRESS = "0x" + "a" * 40
VALID_BYTECODE_HEX = "deadbeef" * 12  # 96 hex chars > 40
VALID_BYTECODE_TARGET = ScanTarget(value="0x" + VALID_BYTECODE_HEX, is_address=False)
VALID_ADDRESS_TARGET = ScanTarget(value=VALID_ADDRESS, is_address=True)


def _make_proc(returncode: int = 0, stdout: str = "Running gigahorse.py\nYes", stderr: str = "") -> MagicMock:
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def _mock_subprocess_always(proc: MagicMock):
    """Returns a callable that always returns proc (used for monkeypatching)."""
    return lambda cmd, **kw: proc


# ---------------------------------------------------------------------------
# AC1 — Address scan uses SKANF_IMAGE_DIGEST (never a bare tag)
# ---------------------------------------------------------------------------

class TestAddressScanUsesDigest:
    def test_digest_in_docker_command(self, monkeypatch):
        from specter.config import SKANF_IMAGE_DIGEST

        captured = []

        def mock_run(cmd, **kw):
            captured.append(cmd)
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)
        monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: VALID_BYTECODE_HEX)

        run_skanf(VALID_ADDRESS_TARGET)

        docker_run_calls = [c for c in captured if "run" in c and "--rm" in c]
        assert docker_run_calls, "No docker run call captured"
        assert SKANF_IMAGE_DIGEST in docker_run_calls[0]

    def test_digest_contains_sha256(self, monkeypatch):
        captured = []

        def mock_run(cmd, **kw):
            captured.append(cmd)
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)
        monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: VALID_BYTECODE_HEX)

        run_skanf(VALID_ADDRESS_TARGET)

        docker_run_calls = [c for c in captured if "run" in c and "--rm" in c]
        cmd_str = " ".join(docker_run_calls[0])
        assert "sha256:" in cmd_str

    def test_no_bare_tag_in_docker_command(self, monkeypatch):
        captured = []

        def mock_run(cmd, **kw):
            captured.append(cmd)
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)
        monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: VALID_BYTECODE_HEX)

        run_skanf(VALID_ADDRESS_TARGET)

        docker_run_calls = [c for c in captured if "run" in c and "--rm" in c]
        cmd_str = " ".join(docker_run_calls[0])
        # Digest refs contain @sha256:, not bare :latest or :v1 style tags
        assert "@sha256:" in cmd_str

    def test_alchemy_fetch_called_for_address(self, monkeypatch):
        fetch_calls = []

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", _mock_subprocess_always(_make_proc()))
        monkeypatch.setattr(
            "specter.pipeline.runner._fetch_bytecode",
            lambda addr, **kw: (fetch_calls.append(addr), VALID_BYTECODE_HEX)[1],
        )

        run_skanf(VALID_ADDRESS_TARGET)

        assert fetch_calls == [VALID_ADDRESS]

    def test_returns_skfn_output(self, monkeypatch):
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", _mock_subprocess_always(_make_proc()))
        monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: VALID_BYTECODE_HEX)

        result = run_skanf(VALID_ADDRESS_TARGET)

        assert isinstance(result, SkfnOutput)
        assert result.container_exit_code == 0


# ---------------------------------------------------------------------------
# AC2 — Bytecode scan: no Alchemy call, bytecode written to container
# ---------------------------------------------------------------------------

class TestBytecodeScan:
    def test_no_alchemy_fetch_for_bytecode(self, monkeypatch):
        fetch_calls = []

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", _mock_subprocess_always(_make_proc()))
        monkeypatch.setattr(
            "specter.pipeline.runner._fetch_bytecode",
            lambda *a, **kw: fetch_calls.append("called") or "xx",
        )

        run_skanf(VALID_BYTECODE_TARGET)

        assert fetch_calls == [], "_fetch_bytecode must NOT be called for bytecode scan"

    def test_returns_skfn_output(self, monkeypatch):
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", _mock_subprocess_always(_make_proc()))

        result = run_skanf(VALID_BYTECODE_TARGET)

        assert isinstance(result, SkfnOutput)

    def test_digest_used_for_bytecode_scan(self, monkeypatch):
        from specter.config import SKANF_IMAGE_DIGEST

        captured = []

        def mock_run(cmd, **kw):
            captured.append(cmd)
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)

        run_skanf(VALID_BYTECODE_TARGET)

        docker_run_calls = [c for c in captured if "run" in c and "--rm" in c]
        assert SKANF_IMAGE_DIGEST in docker_run_calls[0]


# ---------------------------------------------------------------------------
# AC4 — Timeout → SkfnContainerError
# ---------------------------------------------------------------------------

class TestTimeout:
    def test_timeout_raises_skfn_container_error(self, monkeypatch):
        def raise_timeout(cmd, **kw):
            if "info" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            raise subprocess.TimeoutExpired(cmd, 10)

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", raise_timeout)

        with pytest.raises(SkfnContainerError, match="timed out"):
            run_skanf(VALID_BYTECODE_TARGET, timeout=10)

    def test_timeout_message_includes_seconds(self, monkeypatch):
        def raise_timeout(cmd, **kw):
            if "info" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            raise subprocess.TimeoutExpired(cmd, 30)

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", raise_timeout)

        with pytest.raises(SkfnContainerError, match="30"):
            run_skanf(VALID_BYTECODE_TARGET, timeout=30)


# ---------------------------------------------------------------------------
# AC5 — Docker not running → ConfigError before container start
# ---------------------------------------------------------------------------

class TestDockerNotRunning:
    def test_file_not_found_raises_config_error(self, monkeypatch):
        def raise_fnf(cmd, **kw):
            if "docker" in cmd and "info" in cmd:
                raise FileNotFoundError

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", raise_fnf)

        with pytest.raises(ConfigError, match="Docker"):
            run_skanf(VALID_BYTECODE_TARGET)

    def test_docker_not_running_nonzero_exit(self, monkeypatch):
        call_count = [0]

        def mock_run(cmd, **kw):
            call_count[0] += 1
            if "info" in cmd:
                return MagicMock(returncode=1, stdout="", stderr="Cannot connect")
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)

        with pytest.raises(ConfigError, match="Docker"):
            run_skanf(VALID_BYTECODE_TARGET)

    def test_config_error_raised_before_container_start(self, monkeypatch):
        docker_run_calls = []

        def mock_run(cmd, **kw):
            if "info" in cmd:
                raise FileNotFoundError
            docker_run_calls.append(cmd)
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)

        with pytest.raises(ConfigError):
            run_skanf(VALID_BYTECODE_TARGET)

        assert docker_run_calls == [], "docker run must NOT be called when Docker is unavailable"

    def test_docker_info_timeout_raises_config_error_not_skfn(self, monkeypatch):
        """docker info TimeoutExpired must raise ConfigError (AC5), not SkfnContainerError."""
        def raise_timeout(cmd, **kw):
            if "info" in cmd:
                raise subprocess.TimeoutExpired(cmd, 5)

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", raise_timeout)

        with pytest.raises(ConfigError, match="Docker"):
            run_skanf(VALID_BYTECODE_TARGET)


# ---------------------------------------------------------------------------
# Non-zero exit code → SkfnContainerError
# ---------------------------------------------------------------------------

class TestNonZeroExitCode:
    def test_nonzero_exit_raises_skfn_container_error(self, monkeypatch):
        def mock_run(cmd, **kw):
            if "info" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            return _make_proc(returncode=1, stderr="analyze_hex.sh: error")

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)

        with pytest.raises(SkfnContainerError, match="exit"):
            run_skanf(VALID_BYTECODE_TARGET)

    def test_nonzero_exit_message_contains_exit_code(self, monkeypatch):
        def mock_run(cmd, **kw):
            if "info" in cmd:
                return MagicMock(returncode=0, stdout="", stderr="")
            return _make_proc(returncode=2, stderr="some error")

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)

        with pytest.raises(SkfnContainerError, match="2"):
            run_skanf(VALID_BYTECODE_TARGET)


# ---------------------------------------------------------------------------
# contract.hex content — no 0x prefix
# ---------------------------------------------------------------------------

class TestContractHexContent:
    def _run_with_captured_workdir(self, monkeypatch, target):
        """Run run_skanf with a patched TemporaryDirectory that uses tmp_path."""
        import tempfile as _tempfile

        captured_workdir = []
        original_cls = _tempfile.TemporaryDirectory

        class MockTempDir:
            def __init__(self, **kwargs):
                self._real = original_cls(prefix=kwargs.get("prefix", ""))

            def __enter__(self):
                path = self._real.__enter__()
                captured_workdir.append(path)
                return path

            def __exit__(self, *args):
                return self._real.__exit__(*args)

        monkeypatch.setattr("specter.pipeline.runner.tempfile.TemporaryDirectory", MockTempDir)
        return captured_workdir

    def test_bytecode_hex_written_without_0x(self, monkeypatch, tmp_path):
        import os

        captured_workdir = []
        import tempfile as _tempfile
        original_cls = _tempfile.TemporaryDirectory

        class MockTempDir:
            def __init__(self, **kwargs):
                self._dir = str(tmp_path)

            def __enter__(self):
                captured_workdir.append(self._dir)
                return self._dir

            def __exit__(self, *args):
                pass

        monkeypatch.setattr("specter.pipeline.runner.tempfile.TemporaryDirectory", MockTempDir)
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", _mock_subprocess_always(_make_proc()))

        run_skanf(VALID_BYTECODE_TARGET)

        hex_file = tmp_path / "contract.hex"
        content = hex_file.read_text()
        assert not content.startswith("0x"), "contract.hex must not have 0x prefix"
        assert content == VALID_BYTECODE_HEX.lower()

    def test_address_scan_hex_written_without_0x(self, monkeypatch, tmp_path):
        import tempfile as _tempfile

        class MockTempDir:
            def __init__(self, **kwargs):
                self._dir = str(tmp_path)

            def __enter__(self):
                return self._dir

            def __exit__(self, *args):
                pass

        monkeypatch.setattr("specter.pipeline.runner.tempfile.TemporaryDirectory", MockTempDir)
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", _mock_subprocess_always(_make_proc()))
        monkeypatch.setattr("specter.pipeline.runner._fetch_bytecode", lambda *a, **kw: VALID_BYTECODE_HEX)

        run_skanf(VALID_ADDRESS_TARGET)

        hex_file = tmp_path / "contract.hex"
        content = hex_file.read_text()
        assert not content.startswith("0x"), "contract.hex must not have 0x prefix for address scan"


# ---------------------------------------------------------------------------
# --platform linux/amd64 in Docker command
# ---------------------------------------------------------------------------

class TestPlatformFlag:
    def test_platform_flag_in_docker_command(self, monkeypatch):
        captured = []

        def mock_run(cmd, **kw):
            captured.append(cmd)
            return _make_proc()

        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", mock_run)

        run_skanf(VALID_BYTECODE_TARGET)

        docker_run_calls = [c for c in captured if "run" in c and "--rm" in c]
        assert docker_run_calls
        assert "--platform" in docker_run_calls[0]
        assert "linux/amd64" in docker_run_calls[0]


# ---------------------------------------------------------------------------
# _fetch_bytecode unit tests
# ---------------------------------------------------------------------------

class TestFetchBytecode:
    def test_missing_rpc_url_raises_config_error(self, monkeypatch):
        monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)

        with pytest.raises(ConfigError, match="ALCHEMY_RPC_URL"):
            _fetch_bytecode("0x" + "a" * 40)

    def test_network_error_raises_config_error(self, monkeypatch):
        import httpx

        monkeypatch.setenv("ALCHEMY_RPC_URL", "https://fake.rpc/v2/key")
        monkeypatch.setattr(
            "specter.pipeline.runner.httpx.post",
            lambda *a, **kw: (_ for _ in ()).throw(httpx.NetworkError("refused")),
        )

        with pytest.raises(ConfigError, match="network failure"):
            _fetch_bytecode("0x" + "a" * 40)

    def test_empty_bytecode_raises_config_error(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "https://fake.rpc/v2/key")

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"result": "0x"}

        monkeypatch.setattr("specter.pipeline.runner.httpx.post", lambda *a, **kw: mock_resp)

        with pytest.raises(ConfigError, match="No bytecode"):
            _fetch_bytecode("0x" + "a" * 40)

    def test_valid_bytecode_stripped_of_0x(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "https://fake.rpc/v2/key")

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"result": "0xdeadbeef"}

        monkeypatch.setattr("specter.pipeline.runner.httpx.post", lambda *a, **kw: mock_resp)

        result = _fetch_bytecode("0x" + "a" * 40)
        assert result == "deadbeef"
        assert not result.startswith("0x")


# ---------------------------------------------------------------------------
# AC1-4 — _detect_state() unit tests (Story 2.3)
# ---------------------------------------------------------------------------

class TestDetectState:
    def test_success_fixture_returns_exploit_generated(self):
        raw = load_fixture("skanf_success.txt")
        assert _detect_state(raw, "[]") == SkfnState.EXPLOIT_GENERATED

    def test_stalled_fixture_returns_stalled(self):
        raw = load_fixture("skanf_stalled.txt")
        assert _detect_state(raw, "[]") == SkfnState.STALLED

    def test_clean_fixture_returns_clean(self):
        raw = load_fixture("skanf_clean.txt")
        assert _detect_state(raw, "[]") == SkfnState.CLEAN

    def test_no_paths_found_returns_clean(self):
        raw = "FATAL | greed | No paths found"
        assert _detect_state(raw, "[]") == SkfnState.CLEAN

    def test_invalid_vulnerability_json_raises_container_error(self):
        raw = "Running gigahorse.py\nYes"
        with pytest.raises(SkfnContainerError, match="unparseable"):
            _detect_state(raw, '{"broken": json}')

    def test_non_empty_vuln_json_no_greed_output_raises_container_error(self):
        """vulnerability.json has entries but greed produced no stall/success."""
        vuln_json = '[{"vulnerability_type":"ArbitraryCall","key_statement":"0x76"}]'
        raw = "Running gigahorse.py\nYes"
        with pytest.raises(SkfnContainerError, match="unexpected output"):
            _detect_state(raw, vuln_json)

    def test_calldata_takes_priority_over_stall(self):
        """CALLDATA line beats Calling contract <SYMBOLIC> when both present."""
        raw = "Calling contract <SYMBOLIC> (134_1)\nINFO | greed | CALLDATA: deadbeef"
        assert _detect_state(raw, "[]") == SkfnState.EXPLOIT_GENERATED

    def test_malformed_fixture_truncated_json_raises_container_error(self):
        """AC4: malformed fixture has FATAL greed line → SkfnContainerError via fatal check."""
        raw = load_fixture("skanf_malformed.txt")
        truncated_json = '{"vulnerability_type": "ArbitraryCall", "confidence": "HIGH",'
        # New FATAL check (step 3b) triggers before JSON parsing for this fixture
        with pytest.raises(SkfnContainerError, match="fatal"):
            _detect_state(raw, truncated_json)

    def test_empty_string_vulnerability_json_returns_clean(self):
        """Empty string treated as '[]' → clean."""
        raw = "Running gigahorse.py\nYes"
        assert _detect_state(raw, "") == SkfnState.CLEAN

    def test_null_string_vulnerability_json_returns_clean(self):
        """None/null vuln_json treated as '[]' → clean."""
        raw = "Running gigahorse.py\nYes"
        assert _detect_state(raw, "null") == SkfnState.CLEAN


# ---------------------------------------------------------------------------
# _detect_state() — FATAL line detection (H1 fix)
# ---------------------------------------------------------------------------

class TestDetectStateFatalLines:
    def test_other_fatal_greed_line_raises_container_error(self):
        """H1: FATAL greed lines other than 'No paths found' → SkfnContainerError."""
        raw = "Running gigahorse.py\nFATAL | greed | Analysis pipeline terminated unexpectedly"
        with pytest.raises(SkfnContainerError, match="fatal"):
            _detect_state(raw, "[]")

    def test_malformed_fixture_fatal_line_raises_container_error(self):
        """H1: malformed fixture FATAL line caught before empty vuln_json → CLEAN false negative."""
        raw = load_fixture("skanf_malformed.txt")
        with pytest.raises(SkfnContainerError, match="fatal"):
            _detect_state(raw, "[]")

    def test_no_paths_found_still_returns_clean_after_fatal_check(self):
        """Regression: 'No paths found' FATAL must still return CLEAN (checked before step 3b)."""
        raw = "FATAL | greed | No paths found"
        assert _detect_state(raw, "[]") == SkfnState.CLEAN

    def test_calldata_takes_priority_over_fatal(self):
        """CALLDATA is checked before FATAL — exploit found even if FATAL also present."""
        raw = "INFO | greed | CALLDATA: deadbeef\nFATAL | greed | Analysis error"
        assert _detect_state(raw, "[]") == SkfnState.EXPLOIT_GENERATED


# ---------------------------------------------------------------------------
# run_skanf integration tests — state detection via mocked subprocess (AC1-3)
# ---------------------------------------------------------------------------

GREED_CALLDATA_OUTPUT = "INFO | greed | Found State 7 at 0x76\nINFO | greed | CALLDATA: 1cff79cd" + "00" * 64
GREED_STALL_OUTPUT = "INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (134_1)"


class TestRunSkfnStateDetection:
    def test_run_skanf_exploit_generated_state(self, monkeypatch):
        proc = _make_proc(stdout="Running gigahorse.py\nYes", stderr=GREED_CALLDATA_OUTPUT)
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", lambda cmd, **kw: proc)
        result = run_skanf(VALID_BYTECODE_TARGET)
        assert result.state == SkfnState.EXPLOIT_GENERATED

    def test_run_skanf_stalled_state(self, monkeypatch):
        proc = _make_proc(stdout="Running gigahorse.py\nYes", stderr=GREED_STALL_OUTPUT)
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", lambda cmd, **kw: proc)
        result = run_skanf(VALID_BYTECODE_TARGET)
        assert result.state == SkfnState.STALLED

    def test_run_skanf_clean_state(self, monkeypatch):
        proc = _make_proc(stdout="Running gigahorse.py\nYes", stderr="")
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", lambda cmd, **kw: proc)
        result = run_skanf(VALID_BYTECODE_TARGET)
        assert result.state == SkfnState.CLEAN

    def test_run_skanf_propagates_container_error_from_detect_state(self, monkeypatch):
        """M1: SkfnContainerError raised by _detect_state propagates through run_skanf."""
        proc = _make_proc(stdout="Running gigahorse.py\nYes", stderr="")
        monkeypatch.setattr("specter.pipeline.runner.subprocess.run", lambda cmd, **kw: proc)
        monkeypatch.setattr(
            "specter.pipeline.runner._detect_state",
            lambda *args: (_ for _ in ()).throw(SkfnContainerError("malformed output")),
        )
        with pytest.raises(SkfnContainerError, match="malformed"):
            run_skanf(VALID_BYTECODE_TARGET)
