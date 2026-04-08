"""Tests for specter.pipeline.agent — Claude API agent call (Story 3.1)."""
import pytest
from unittest.mock import MagicMock, patch

from specter.errors import AgentError
from specter.models import AgentCalldata, SkfnContext
from specter.pipeline.agent import call_agent


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_context(**kwargs) -> SkfnContext:
    defaults = {
        "contract_address": "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead",
        "raw_output": "INFO | greed | Calling contract <SYMBOLIC>",
        "vulnerability_type": "ArbitraryCall",
        "confidence": "HIGH",
        "call_pc": "0x76",
        "key_selector": "0x1cff79cd",
    }
    defaults.update(kwargs)
    return SkfnContext(**defaults)


def make_mock_response(tool_input: dict | None, stop_reason: str = "tool_use") -> MagicMock:
    """Build a mock anthropic.types.Message with one tool_use block."""
    mock_response = MagicMock()
    mock_response.stop_reason = stop_reason
    mock_response.model = "claude-sonnet-4-6"
    if tool_input is not None:
        block = MagicMock()
        block.type = "tool_use"
        block.name = "submit_calldata"
        block.input = tool_input
        mock_response.content = [block]
    else:
        # No tool_use block — simulate text-only response
        text_block = MagicMock()
        text_block.type = "text"
        mock_response.content = [text_block]
    return mock_response


VALID_TOOL_INPUT = {
    "calldata": "0x1cff79cd000000000000000000000000deadbeef",
    "target_address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "caller": "0x0000000000000000000000000000000000000001",
    "origin": "0x0000000000000000000000000000000000000001",
}


# ── AC1: Model, tool schema, message content ──────────────────────────────────

class TestCallAgentApiContract:
    def test_uses_configured_model_version(self):
        from specter.config import MODEL_VERSION
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            call_agent(make_context())
            call_kwargs = MockClient.return_value.messages.create.call_args[1]
            assert call_kwargs["model"] == MODEL_VERSION

    def test_includes_submit_calldata_tool(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            call_agent(make_context())
            call_kwargs = MockClient.return_value.messages.create.call_args[1]
            tool_names = [t["name"] for t in call_kwargs["tools"]]
            assert "submit_calldata" in tool_names

    def test_message_contains_contract_address(self):
        ctx = make_context()
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            call_agent(ctx)
            call_kwargs = MockClient.return_value.messages.create.call_args[1]
            message_content = call_kwargs["messages"][0]["content"]
            assert ctx.contract_address in message_content

    def test_tool_schema_has_required_fields(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            call_agent(make_context())
            call_kwargs = MockClient.return_value.messages.create.call_args[1]
            tool = next(t for t in call_kwargs["tools"] if t["name"] == "submit_calldata")
            required = tool["input_schema"]["required"]
            assert "calldata" in required
            assert "target_address" in required
            assert "caller" in required
            assert "origin" in required


# ── AC2: Well-formed response → AgentCalldata ────────────────────────────────

class TestCallAgentValidResponse:
    def test_returns_agent_calldata(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context())
            assert isinstance(result, AgentCalldata)

    def test_calldata_hex_normalized(self):
        tool_input = {**VALID_TOOL_INPUT, "calldata": "1cff79cd"}  # no 0x prefix
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(tool_input)
            result = call_agent(make_context())
            assert result.calldata.startswith("0x")
            assert result.calldata == result.calldata.lower()

    def test_never_returns_none(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context())
            assert result is not None

    def test_all_fields_populated(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context())
            assert result.calldata
            assert result.target_address
            assert result.caller
            assert result.origin

    def test_address_fields_are_eip55_checksummed(self):
        """AC2: target_address/caller/origin normalized to EIP-55 checksummed format."""
        import eth_utils
        tool_input = {
            **VALID_TOOL_INPUT,
            "target_address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "caller": "0x0000000000000000000000000000000000000001",
            "origin": "0x0000000000000000000000000000000000000001",
        }
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(tool_input)
            result = call_agent(make_context())
            assert result.target_address == eth_utils.to_checksum_address(tool_input["target_address"])
            assert result.caller == eth_utils.to_checksum_address(tool_input["caller"])
            assert result.origin == eth_utils.to_checksum_address(tool_input["origin"])

    def test_value_field_defaults_to_zero_when_absent(self):
        """AC2: value field populated — defaults to 0 when absent from tool response."""
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context())
            assert result.value == 0

    def test_value_field_set_when_provided(self):
        """AC2: value field populated when API response includes it."""
        tool_input = {**VALID_TOOL_INPUT, "value": 1_000_000}
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(tool_input)
            result = call_agent(make_context())
            assert result.value == 1_000_000


# ── AC5: Model mismatch / deprecation → AgentError ───────────────────────────

class TestCallAgentDeprecation:
    def test_model_mismatch_raises_agent_error(self):
        """AC5: response.model != MODEL_VERSION → AgentError with deprecation notice."""
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            response = make_mock_response(VALID_TOOL_INPUT)
            response.model = "claude-different-model-99"
            MockClient.return_value.messages.create.return_value = response
            with pytest.raises(AgentError, match="deprecated"):
                call_agent(make_context())

    def test_model_mismatch_error_names_both_models(self):
        """AC5: AgentError message includes both returned and expected model names."""
        from specter.config import MODEL_VERSION
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            response = make_mock_response(VALID_TOOL_INPUT)
            response.model = "claude-different-model-99"
            MockClient.return_value.messages.create.return_value = response
            with pytest.raises(AgentError, match=MODEL_VERSION):
                call_agent(make_context())

    def test_matching_model_does_not_raise(self):
        """AC5: model matches MODEL_VERSION → no error raised."""
        from specter.config import MODEL_VERSION
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            response = make_mock_response(VALID_TOOL_INPUT)
            response.model = MODEL_VERSION
            MockClient.return_value.messages.create.return_value = response
            result = call_agent(make_context())
            assert isinstance(result, AgentCalldata)


# ── AC3: Malformed response → AgentError ─────────────────────────────────────

class TestCallAgentMalformedResponse:
    def test_no_tool_use_block_raises_agent_error(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(None)
            with pytest.raises(AgentError):
                call_agent(make_context())

    def test_missing_calldata_field_raises_agent_error(self):
        bad_input = {
            "target_address": "0x" + "a" * 40,
            "caller": "0x" + "0" * 40,
            "origin": "0x" + "0" * 40,
        }
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(bad_input)
            with pytest.raises(AgentError):
                call_agent(make_context())

    def test_missing_target_address_raises_agent_error(self):
        bad_input = {
            "calldata": "0x1cff79cd",
            "caller": "0x" + "0" * 40,
            "origin": "0x" + "0" * 40,
        }
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(bad_input)
            with pytest.raises(AgentError):
                call_agent(make_context())

    def test_agent_error_names_claude(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(None)
            with pytest.raises(AgentError, match="Claude"):
                call_agent(make_context())


# ── AC4: HTTP error → AgentError with status code ────────────────────────────

class TestCallAgentHttpErrors:
    def test_status_error_429_raises_agent_error_with_code(self):
        import anthropic as anthropic_lib
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            exc = anthropic_lib.APIStatusError(
                "Rate limited", response=MagicMock(status_code=429), body={}
            )
            MockClient.return_value.messages.create.side_effect = exc
            with pytest.raises(AgentError, match="429"):
                call_agent(make_context())

    def test_status_error_500_raises_agent_error_with_code(self):
        import anthropic as anthropic_lib
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            exc = anthropic_lib.APIStatusError(
                "Internal Server Error", response=MagicMock(status_code=500), body={}
            )
            MockClient.return_value.messages.create.side_effect = exc
            with pytest.raises(AgentError, match="500"):
                call_agent(make_context())

    def test_connection_error_raises_agent_error(self):
        import anthropic as anthropic_lib
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.side_effect = \
                anthropic_lib.APIConnectionError(request=MagicMock())
            with pytest.raises(AgentError):
                call_agent(make_context())

    def test_api_error_base_class_raises_agent_error(self):
        """M1: anthropic.APIError base class (not status/connection) → AgentError."""
        import anthropic as anthropic_lib

        class _UnknownAPIError(anthropic_lib.APIError):
            def __init__(self) -> None:
                pass

        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.side_effect = _UnknownAPIError()
            with pytest.raises(AgentError):
                call_agent(make_context())


# ── AC6: No stdout writes — pure function ────────────────────────────────────

class TestCallAgentNoPrint:
    def test_call_agent_never_calls_print(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            with patch("builtins.print") as mock_print:
                call_agent(make_context())
                mock_print.assert_not_called()


# ── Interface contract ────────────────────────────────────────────────────────

class TestCallAgentInterface:
    def test_accepts_none_timeout(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context(), timeout=None)
            assert isinstance(result, AgentCalldata)

    def test_accepts_float_timeout(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context(), timeout=30.0)
            assert isinstance(result, AgentCalldata)

    def test_returns_agent_calldata_never_none(self):
        with patch("specter.pipeline.agent.anthropic.Anthropic") as MockClient:
            MockClient.return_value.messages.create.return_value = make_mock_response(VALID_TOOL_INPUT)
            result = call_agent(make_context(), timeout=None)
            assert result is not None
            assert isinstance(result, AgentCalldata)
