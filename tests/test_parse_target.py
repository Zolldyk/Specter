"""Unit tests for specter.cli._parse_target and _extract_calldata_from_greed."""
import pytest

from specter.cli import _parse_target, _extract_calldata_from_greed
from specter.errors import ConfigError
from specter.models import ScanTarget


# ---------------------------------------------------------------------------
# _parse_target — EIP-55 address inputs
# ---------------------------------------------------------------------------

class TestParseTargetAddress:
    def test_valid_address_returns_is_address_true(self):
        target = _parse_target("0x" + "a" * 40)
        assert target.is_address is True

    def test_valid_address_preserves_value(self):
        addr = "0x" + "a" * 40
        target = _parse_target(addr)
        assert target.value == addr

    def test_valid_address_exactly_42_chars(self):
        # 0x + 40 hex = 42 chars total
        target = _parse_target("0x" + "f" * 40)
        assert isinstance(target, ScanTarget)
        assert target.is_address is True

    def test_valid_address_mixed_case_hex(self):
        target = _parse_target("0x" + "aAbBcCdDeE" * 4)
        assert target.is_address is True

    def test_valid_address_strips_whitespace(self):
        addr = "  0x" + "b" * 40 + "  "
        target = _parse_target(addr)
        assert target.is_address is True

    def test_valid_address_all_zeros(self):
        target = _parse_target("0x" + "0" * 40)
        assert target.is_address is True


# ---------------------------------------------------------------------------
# _parse_target — raw bytecode inputs
# ---------------------------------------------------------------------------

class TestParseTargetBytecode:
    def test_bytecode_with_0x_prefix_returns_is_address_false(self):
        bytecode = "0x" + "60" * 50  # 100 hex chars > 40
        target = _parse_target(bytecode)
        assert target.is_address is False

    def test_bytecode_without_0x_prefix_returns_is_address_false(self):
        bytecode = "60" * 50  # 100 hex chars, no 0x
        target = _parse_target(bytecode)
        assert target.is_address is False

    def test_bytecode_without_prefix_gets_0x_added(self):
        bytecode = "deadbeef" * 15  # 120 hex chars
        target = _parse_target(bytecode)
        assert target.value.startswith("0x")
        assert target.value == "0x" + bytecode.lower()

    def test_bytecode_uppercase_lowercased_in_value(self):
        bytecode = "DEADBEEF" * 15
        target = _parse_target(bytecode)
        assert target.value == "0x" + bytecode.lower()

    def test_bytecode_41_hex_chars_no_prefix_is_bytecode(self):
        # 41 hex chars without 0x — longer than 40, so bytecode
        bytecode = "a" * 41
        target = _parse_target(bytecode)
        assert target.is_address is False

    def test_bytecode_returns_scan_target_instance(self):
        target = _parse_target("0x" + "ab" * 50)
        assert isinstance(target, ScanTarget)


# ---------------------------------------------------------------------------
# _parse_target — invalid inputs raise ConfigError
# ---------------------------------------------------------------------------

class TestParseTargetInvalid:
    def test_random_string_raises_config_error(self):
        with pytest.raises(ConfigError):
            _parse_target("not-a-valid-target")

    def test_too_short_hex_raises_config_error(self):
        # Only 40 hex chars without 0x = ambiguous/invalid (not address, not > 40 bytecode)
        with pytest.raises(ConfigError):
            _parse_target("a" * 40)

    def test_empty_string_raises_config_error(self):
        with pytest.raises(ConfigError):
            _parse_target("")

    def test_0x_only_raises_config_error(self):
        with pytest.raises(ConfigError):
            _parse_target("0x")

    def test_non_hex_bytecode_raises_config_error(self):
        # Long enough but contains non-hex chars
        with pytest.raises(ConfigError):
            _parse_target("not-hex-" * 10)

    def test_address_length_41_chars_raises_config_error(self):
        # 0x + 39 hex = 41 chars — not 42, not long enough for bytecode
        with pytest.raises(ConfigError):
            _parse_target("0x" + "a" * 39)

    def test_config_error_message_names_target(self):
        bad_target = "definitely-not-valid"
        with pytest.raises(ConfigError, match="definitely-not-valid"):
            _parse_target(bad_target)

    def test_config_error_message_explains_format(self):
        with pytest.raises(ConfigError, match="Ethereum address"):
            _parse_target("short")


# ---------------------------------------------------------------------------
# _extract_calldata_from_greed
# ---------------------------------------------------------------------------

class TestExtractCalldataFromGreed:
    def test_extracts_calldata_from_valid_log_line(self):
        raw = "INFO | greed | CALLDATA: 1cff79cd" + "00" * 64
        result = _extract_calldata_from_greed(raw)
        assert result == "0x1cff79cd" + "00" * 64

    def test_returns_none_when_no_calldata_line(self):
        raw = "INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (134_1)"
        result = _extract_calldata_from_greed(raw)
        assert result is None

    def test_result_always_has_0x_prefix(self):
        raw = "INFO | greed | CALLDATA: deadbeef"
        result = _extract_calldata_from_greed(raw)
        assert result is not None
        assert result.startswith("0x")

    def test_result_is_lowercase(self):
        raw = "INFO | greed | CALLDATA: DEADBEEF"
        result = _extract_calldata_from_greed(raw)
        assert result == "0xdeadbeef"

    def test_extracts_from_multiline_output(self):
        raw = (
            "Running gigahorse.py\n"
            "INFO | greed | Found State 7 at 0x76\n"
            "INFO | greed | CALLDATA: 1cff79cd\n"
            "INFO | greed | Done"
        )
        result = _extract_calldata_from_greed(raw)
        assert result == "0x1cff79cd"

    def test_returns_none_on_empty_string(self):
        assert _extract_calldata_from_greed("") is None

    def test_extracts_first_calldata_line_when_multiple_present(self):
        raw = (
            "INFO | greed | CALLDATA: aabbccdd\n"
            "INFO | greed | CALLDATA: 11223344\n"
        )
        result = _extract_calldata_from_greed(raw)
        assert result == "0xaabbccdd"
