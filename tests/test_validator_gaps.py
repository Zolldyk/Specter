"""Additional tests for coverage gaps in validator.py and config.py."""
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from specter.errors import ConfigError
from specter.models import AgentCalldata, SkfnContext, ValidationTier
from specter.pipeline.validator import _check_live_balance, call_validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def make_eth_response(balance_hex: str = "0x0") -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": balance_hex}
    resp.raise_for_status = MagicMock()
    return resp


def make_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# _check_live_balance — alchemy_getTokenBalances method-not-found (error in response)
# ---------------------------------------------------------------------------

class TestTokenBalanceMethodNotFound:
    """Covers the 'error' key in alchemy_getTokenBalances response (validator.py line 131-138)."""

    def test_method_not_found_error_returns_false(self, monkeypatch):
        """alchemy_getTokenBalances returning an error → live_balance=False (graceful skip)."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            eth_resp = make_eth_response("0x0")  # zero ETH → triggers token balance check
            token_error_resp = MagicMock()
            token_error_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"code": -32601, "message": "Method not found"},
            }
            token_error_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [eth_resp, token_error_resp]
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")
            assert result is False

    def test_method_not_found_does_not_raise(self, monkeypatch):
        """alchemy_getTokenBalances error must be handled gracefully — no exception raised."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            eth_resp = make_eth_response("0x0")
            token_error_resp = MagicMock()
            token_error_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"code": -32601, "message": "Method not found"},
            }
            token_error_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [eth_resp, token_error_resp]
            # Should not raise
            _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")

    def test_method_not_found_still_calls_token_endpoint(self, monkeypatch):
        """Even when token endpoint returns error, two HTTP calls were made."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            eth_resp = make_eth_response("0x0")
            token_error_resp = MagicMock()
            token_error_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"code": -32601, "message": "Method not found"},
            }
            token_error_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [eth_resp, token_error_resp]
            _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")
            assert mock_http.call_count == 2

    def test_rpc_error_without_code_key_still_returns_false(self, monkeypatch):
        """error dict without 'code' key is still handled gracefully."""
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            eth_resp = make_eth_response("0x0")
            token_error_resp = MagicMock()
            token_error_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"message": "Unknown method"},  # no 'code' key
            }
            token_error_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [eth_resp, token_error_resp]
            result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")
            assert result is False


# ---------------------------------------------------------------------------
# _check_live_balance — malformed ETH balance format
# ---------------------------------------------------------------------------

class TestEthBalanceMalformed:
    def test_unexpected_eth_balance_format_treated_as_zero(self, monkeypatch, caplog):
        """Malformed ETH balance hex (non-parseable) → logs WARNING, treated as 0."""
        import logging
        monkeypatch.setenv("ALCHEMY_RPC_URL", "http://fake-rpc")
        with patch("specter.pipeline.validator.httpx.post") as mock_http:
            eth_resp = MagicMock()
            eth_resp.json.return_value = {"jsonrpc": "2.0", "id": 1, "result": "not-hex"}
            eth_resp.raise_for_status = MagicMock()
            token_resp = MagicMock()
            token_resp.json.return_value = {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"address": "0xDead...", "tokenBalances": []},
            }
            token_resp.raise_for_status = MagicMock()
            mock_http.side_effect = [eth_resp, token_resp]
            with caplog.at_level(logging.WARNING, logger="specter.pipeline.validator"):
                result = _check_live_balance("0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead")
            assert result is False
            assert any("Unexpected ETH balance" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# config.py — ALCHEMY_RPC_URL check item
# ---------------------------------------------------------------------------

class TestAlchemyRpcUrlCheckItem:
    def test_alchemy_rpc_url_missing_check_item_is_not_required(self, monkeypatch):
        """ALCHEMY_RPC_URL missing → CheckItem with ok=False, required=False."""
        import subprocess as _subprocess
        from specter.config import check_dependencies
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
        monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)
        monkeypatch.setattr(
            "specter.config.subprocess.run",
            lambda args, **kw: _subprocess.CompletedProcess(args, 0),
        )
        items = check_dependencies()
        alchemy_item = next(i for i in items if i.label == "ALCHEMY_RPC_URL")
        assert alchemy_item.ok is False
        assert alchemy_item.required is False

    def test_alchemy_rpc_url_set_check_item_is_ok(self, monkeypatch):
        """ALCHEMY_RPC_URL set → CheckItem with ok=True."""
        import subprocess as _subprocess
        from specter.config import check_dependencies
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
        monkeypatch.setenv("ALCHEMY_RPC_URL", "https://eth-mainnet.g.alchemy.com/v2/key")
        monkeypatch.setattr(
            "specter.config.subprocess.run",
            lambda args, **kw: _subprocess.CompletedProcess(args, 0),
        )
        items = check_dependencies()
        alchemy_item = next(i for i in items if i.label == "ALCHEMY_RPC_URL")
        assert alchemy_item.ok is True

    def test_alchemy_rpc_url_missing_check_item_has_fix(self, monkeypatch):
        """Missing ALCHEMY_RPC_URL → fix instruction present."""
        import subprocess as _subprocess
        from specter.config import check_dependencies
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("ALCHEMY_RPC_URL", raising=False)
        monkeypatch.setattr(
            "specter.config.subprocess.run",
            lambda args, **kw: _subprocess.CompletedProcess(args, 0),
        )
        items = check_dependencies()
        alchemy_item = next(i for i in items if i.label == "ALCHEMY_RPC_URL")
        assert alchemy_item.fix is not None
        assert "ALCHEMY_RPC_URL" in alchemy_item.fix
