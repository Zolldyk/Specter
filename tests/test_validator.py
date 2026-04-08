"""Tests for src/specter/pipeline/validator.py — Story 3.2 + 3.3: EVM Exploit Validation & Live Balance Detection."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from specter.errors import ConfigError, SprecterValidationError
from specter.models import (
    AgentCalldata,
    SkfnContext,
    ValidationResult,
    ValidationStatus,
    ValidationTier,
)
from specter.pipeline.validator import _check_live_balance, _detect_validation_tier, call_validator

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "validator"


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_context(**kwargs) -> SkfnContext:
    defaults = {
        "contract_address": "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
        "raw_output": "INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (134_1)",
        "call_pc": "0x76",
        "vulnerability_type": "ArbitraryCall",
        "confidence": "HIGH",
        "key_selector": "0x1cff79cd",
    }
    defaults.update(kwargs)
    return SkfnContext(**defaults)


def make_agent_calldata(**kwargs) -> AgentCalldata:
    defaults = {
        "calldata": "0x1cff79cd000000000000000000000000deadbeef",
        "target_address": "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
        "caller": "0x0000000000000000000000000000000000000001",
        "origin": "0x0000000000000000000000000000000000000001",
    }
    defaults.update(kwargs)
    return AgentCalldata(**defaults)


def make_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def make_alchemy_response(balance_hex: str = "0x0") -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": balance_hex}
    resp.raise_for_status = MagicMock()
    return resp


def make_token_balance_response(token_balances: list) -> MagicMock:
    """Build a mock httpx response for alchemy_getTokenBalances."""
    resp = MagicMock()
    resp.json.return_value = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "address": "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
            "tokenBalances": token_balances,
        },
    }
    resp.raise_for_status = MagicMock()
    return resp


VALIDATION_SUCCESS_OUTPUT = (_FIXTURE_DIR / "validation_success.txt").read_text()
VALIDATION_STALL_OUTPUT = (_FIXTURE_DIR / "validation_stall.txt").read_text()
VALIDATION_NO_PATH_OUTPUT = (_FIXTURE_DIR / "validation_no_path.txt").read_text()
VALIDATION_FATAL_OUTPUT = (_FIXTURE_DIR / "validation_error.txt").read_text()


# ── _detect_validation_tier unit tests ───────────────────────────────────────

class TestDetectValidationTier:
    def test_calldata_line_returns_full_success(self):
        assert _detect_validation_tier(VALIDATION_SUCCESS_OUTPUT) == ValidationTier.FULL_SUCCESS

    def test_symbolic_stall_returns_partial_success(self):
        assert _detect_validation_tier(VALIDATION_STALL_OUTPUT) == ValidationTier.PARTIAL_SUCCESS

    def test_no_paths_found_returns_failure(self):
        assert _detect_validation_tier(VALIDATION_NO_PATH_OUTPUT) == ValidationTier.FAILURE

    def test_fatal_error_raises(self):
        with pytest.raises(SprecterValidationError):
            _detect_validation_tier(VALIDATION_FATAL_OUTPUT)

    def test_unrecognized_output_returns_failure(self):
        assert _detect_validation_tier("Some random output\n") == ValidationTier.FAILURE


# ── _check_live_balance unit tests ───────────────────────────────────────────

class TestCheckLiveBalance:
    def test_nonzero_balance_returns_true(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.return_value = make_alchemy_response("0xDE0B6B3A7640000")  # 1 ETH
            assert _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead") is True

    def test_zero_balance_returns_false(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            assert _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead") is False

    def test_rpc_url_not_set_returns_false(self, monkeypatch):
        monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")
            mock_http.assert_not_called()
            assert result is False

    def test_network_error_raises_config_error(self, monkeypatch):
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = _httpx.NetworkError("connection refused")
            with pytest.raises(ConfigError, match="network failure"):
                _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")

    def test_http_error_raises_config_error(self, monkeypatch):
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_http.side_effect = _httpx.HTTPStatusError(
                "rate limited", request=MagicMock(), response=mock_resp
            )
            with pytest.raises(ConfigError, match="HTTP error"):
                _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")

    def test_timeout_raises_config_error(self, monkeypatch):
        """H1: httpx.TimeoutException must be caught and re-raised as ConfigError."""
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = _httpx.TimeoutException("request timed out")
            with pytest.raises(ConfigError, match="timed out"):
                _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")

    def test_timeout_during_validation_raises_config_error(self, monkeypatch):
        """H1: httpx timeout during call_validator live balance check propagates as ConfigError."""
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.side_effect = _httpx.TimeoutException("request timed out")
            with pytest.raises(ConfigError, match="timed out"):
                call_validator(make_agent_calldata(), make_context())


# ── AC2: Full success ─────────────────────────────────────────────────────────

class TestValidatorFullSuccess:
    def test_calldata_line_yields_full_success(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context())
            assert result.tier == ValidationTier.FULL_SUCCESS
            assert result.validation_status == ValidationStatus.VALIDATED_EXPLOIT

    def test_full_success_with_live_balance(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.return_value = make_alchemy_response("0xDE0B6B3A7640000")  # 1 ETH
            result = call_validator(make_agent_calldata(), make_context())
            assert result.live_balance is True

    def test_full_success_zero_balance(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context())
            assert result.live_balance is False

    def test_docker_command_contains_find_flag_with_call_pc(self, monkeypatch):
        """M2/AC1: greed must be invoked with --find <context.call_pc>."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            call_validator(make_agent_calldata(), make_context(call_pc="0x76"))
            cmd_list = mock_sub.call_args.args[0]
            bash_cmd = cmd_list[-1]  # last arg is the bash -c command string
            assert "--find" in bash_cmd
            assert "0x76" in bash_cmd


# ── AC3: Partial success ──────────────────────────────────────────────────────

class TestValidatorPartialSuccess:
    def test_symbolic_stall_yields_partial_success(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_STALL_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context())
            assert result.tier == ValidationTier.PARTIAL_SUCCESS
            assert result.validation_status == ValidationStatus.AGENT_PROPOSED_UNVALIDATED


# ── AC4: Failure tier ─────────────────────────────────────────────────────────

class TestValidatorFailure:
    def test_no_paths_found_yields_failure(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_NO_PATH_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context())
            assert result.tier == ValidationTier.FAILURE
            assert result.validation_status == ValidationStatus.SKANF_DETECTED_UNEXPLOITED


# ── AC5: Live balance ─────────────────────────────────────────────────────────

class TestLiveBalance:
    def test_zero_balance_returns_false(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_NO_PATH_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context())
            assert result.live_balance is False

    def test_nonzero_balance_returns_true(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.return_value = make_alchemy_response("0x1")  # 1 wei
            result = call_validator(make_agent_calldata(), make_context())
            assert result.live_balance is True

    def test_bytecode_scan_skips_balance_check(self):
        bytecode_context = make_context(
            contract_address="0x" + "0" * 40,  # zero address = bytecode scan
        )
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            result = call_validator(make_agent_calldata(), bytecode_context)
            mock_http.assert_not_called()
            assert result.live_balance is False

    def test_bytecode_scan_returns_failure_tier(self):
        bytecode_context = make_context(
            contract_address="0x" + "0" * 40,
        )
        result = call_validator(make_agent_calldata(), bytecode_context)
        assert result.tier == ValidationTier.FAILURE


# ── AC6: Alchemy network failure ──────────────────────────────────────────────

class TestAlchemyFailure:
    def test_alchemy_network_failure_raises_named_error(self, monkeypatch):
        """AC6: network failure raises ConfigError distinguishing from contract-not-found."""
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_SUCCESS_OUTPUT)
            mock_http.side_effect = _httpx.NetworkError("connection refused")
            with pytest.raises(ConfigError, match="network failure"):
                call_validator(make_agent_calldata(), make_context())


# ── AC7: Error handling ───────────────────────────────────────────────────────

class TestValidatorErrors:
    def test_container_nonzero_exit_raises_skanf_named_error(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(returncode=1, stderr="greed crashed")
            with pytest.raises(SprecterValidationError, match="SKANF"):
                call_validator(make_agent_calldata(), make_context())

    def test_timeout_raises_validation_error(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
            with pytest.raises(SprecterValidationError):
                call_validator(make_agent_calldata(), make_context())

    def test_timeout_error_message_names_skanf(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
            with pytest.raises(SprecterValidationError, match="SKANF"):
                call_validator(make_agent_calldata(), make_context())


# ── Interface contract ────────────────────────────────────────────────────────

class TestValidatorInterface:
    def test_returns_validation_result_instance(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_NO_PATH_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context())
            assert isinstance(result, ValidationResult)
            assert result is not None

    def test_accepts_timeout_none(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_NO_PATH_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context(), timeout=None)
            assert isinstance(result, ValidationResult)

    def test_accepts_explicit_timeout(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"):
            mock_sub.return_value = make_proc(stdout=VALIDATION_NO_PATH_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), make_context(), timeout=30.0)
            assert isinstance(result, ValidationResult)

    def test_never_calls_print(self, monkeypatch):
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http, \
             patch("specter.pipeline.runner._fetch_bytecode", return_value="6080"), \
             patch("builtins.print") as mock_print:
            mock_sub.return_value = make_proc(stdout=VALIDATION_NO_PATH_OUTPUT)
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            call_validator(make_agent_calldata(), make_context())
            mock_print.assert_not_called()

    def test_no_call_pc_returns_failure(self, monkeypatch):
        """When context has no call_pc, validator defaults to FAILURE tier without running Docker."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        no_pc_context = make_context(call_pc=None)
        with patch("specter.pipeline.validator.subprocess.run") as mock_sub, \
             patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [make_alchemy_response("0x0"), make_token_balance_response([])]
            result = call_validator(make_agent_calldata(), no_pc_context)
            mock_sub.assert_not_called()
            assert result.tier == ValidationTier.FAILURE


# ── Live balance token checks (AC1-6 Story 3.3) ──────────────────────────────

class TestLiveBalanceTokens:
    """AC1-6: ERC-20 token balance detection in _check_live_balance."""

    def test_eth_nonzero_short_circuits_no_token_call(self, monkeypatch):
        """AC2: ETH non-zero → True without calling alchemy_getTokenBalances."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.return_value = make_alchemy_response("0xDE0B6B3A7640000")  # 1 ETH
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is True
            assert mock_http.call_count == 1  # only eth_getBalance called

    def test_eth_zero_nonzero_token_balance_returns_true(self, monkeypatch):
        """AC3: ETH zero + non-zero token balance → True."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                make_token_balance_response([
                    {"contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                     "tokenBalance": "0x000000000000000000000000000000000000000000000000000000003b9aca00"},
                ]),
            ]
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is True
            assert mock_http.call_count == 2

    def test_eth_zero_empty_token_list_returns_false(self, monkeypatch):
        """AC4: ETH zero + empty token list → False."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                make_token_balance_response([]),
            ]
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is False

    def test_eth_zero_all_zero_token_balances_returns_false(self, monkeypatch):
        """AC4: ETH zero + all-zero token balances → False."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                make_token_balance_response([
                    {"contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                     "tokenBalance": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                ]),
            ]
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is False

    def test_token_check_network_failure_raises_config_error(self, monkeypatch):
        """AC5: alchemy_getTokenBalances network failure → ConfigError naming network failure."""
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                _httpx.NetworkError("connection refused"),
            ]
            with pytest.raises(ConfigError, match="network failure"):
                _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)

    def test_token_check_http_error_raises_config_error(self, monkeypatch):
        """AC5: alchemy_getTokenBalances HTTP error → ConfigError with status code."""
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_resp = MagicMock()
            mock_resp.status_code = 503
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                _httpx.HTTPStatusError("service unavailable", request=MagicMock(), response=mock_resp),
            ]
            with pytest.raises(ConfigError, match="HTTP error"):
                _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)

    def test_token_check_timeout_raises_config_error(self, monkeypatch):
        """AC5: alchemy_getTokenBalances timeout → ConfigError naming timeout."""
        import httpx as _httpx
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                _httpx.TimeoutException("timed out"),
            ]
            with pytest.raises(ConfigError, match="timed out"):
                _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)

    def test_malformed_response_non_list_token_balances_returns_false(self, monkeypatch, caplog):
        """Malformed response (tokenBalances not a list) → WARNING logged, live_balance = False."""
        import logging
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            malformed_resp = MagicMock()
            malformed_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "address": "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
                    "tokenBalances": "unexpected-string",
                },
            }
            malformed_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [make_alchemy_response("0x0"), malformed_resp]
            with caplog.at_level(logging.WARNING, logger="specter.pipeline.validator"):
                result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is False  # no raise
            assert any("unexpected format" in r.message for r in caplog.records)

    def test_malformed_response_missing_token_balances_key_returns_false(self, monkeypatch, caplog):
        """Malformed response (missing tokenBalances key) → WARNING logged, live_balance = False."""
        import logging
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            malformed_resp = MagicMock()
            malformed_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "address": "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
                    # tokenBalances key absent
                },
            }
            malformed_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [make_alchemy_response("0x0"), malformed_resp]
            with caplog.at_level(logging.WARNING, logger="specter.pipeline.validator"):
                result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is False  # no raise
            assert any("missing tokenBalances key" in r.message for r in caplog.records)

    def test_multiple_tokens_only_one_nonzero_returns_true(self, monkeypatch):
        """Multiple tokens, only one non-zero → True."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            mock_http.side_effect = [
                make_alchemy_response("0x0"),
                make_token_balance_response([
                    {"contractAddress": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                     "tokenBalance": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                    {"contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                     "tokenBalance": "0x000000000000000000000000000000000000000000000000000000003b9aca00"},
                ]),
            ]
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead", timeout=5.0)
            assert result is True
