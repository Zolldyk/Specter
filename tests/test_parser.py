"""Tests for specter.pipeline.parser — SKANF Figure 3 parser (Story 2.4)."""
import json
import pytest
from pathlib import Path

from specter.errors import SkfnParseError
from specter.models import ScanTarget, SkfnContext, SkfnOutput, SkfnState
from specter.pipeline.parser import parse_skanf

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


# ─── Helpers ────────────────────────────────────────────────────────────────

def make_stalled_output(raw_output: str, vulnerability_json: str = "[]") -> SkfnOutput:
    return SkfnOutput(
        state=SkfnState.STALLED,
        raw_output=raw_output,
        container_exit_code=0,
        vulnerability_json=vulnerability_json,
    )


def make_address_target(addr: str = "0xDeadDeadDeadDeadDeadDeadDeadDeadDeadDead") -> ScanTarget:
    return ScanTarget(value=addr, is_address=True)


def make_bytecode_target() -> ScanTarget:
    return ScanTarget(value="0x" + "60" * 50, is_address=False)


STALL_LOG = "INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (134_1)"
CALLDATA_LOG = "INFO | greed | CALLDATA: 1cff79cd" + "00" * 64

VULN_JSON_POPULATED = json.dumps([{
    "vulnerability_type": "ArbitraryCall",
    "confidence": "HIGH",
    "visibility": "PUBLIC",
    "key_statement": "0x76",
    "key_selector": "0x1cff79cd",
    "debug_template": "",
    "debug_arg0": "", "debug_arg1": "", "debug_arg2": "", "debug_arg3": "",
}])


# ─── AC1: Parsing populated vulnerability.json ───────────────────────────────

class TestParseSkanfPopulatedVuln:
    def test_call_pc_extracted(self):
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.call_pc == "0x76"  # hex-normalized by model validator

    def test_vulnerability_type_extracted(self):
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.vulnerability_type == "ArbitraryCall"

    def test_confidence_extracted(self):
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.confidence == "HIGH"

    def test_key_selector_extracted(self):
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.key_selector == "0x1cff79cd"  # hex-normalized by model

    def test_raw_output_preserved(self):
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.raw_output == STALL_LOG

    def test_calldata_is_none_when_stalled(self):
        """Stalled state has no CALLDATA line — calldata must be None."""
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.calldata is None

    def test_paper_figure3_fields_are_none(self):
        """Paper Figure 3 fields not in actual SKANF output."""
        out = make_stalled_output(STALL_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.tainted_bytes is None
        assert ctx.controllability_flags is None
        assert ctx.block_height is None
        assert ctx.token_balance is None


# ─── AC1: Free-exploration stall (skanf_stalled.txt fixture) ─────────────────

class TestParseSkanfFreeExplorationStall:
    def test_stall_fixture_parses_successfully(self):
        """skanf_stalled.txt has vulnerability.json=[] (free-exploration mode)."""
        raw = load_fixture("skanf_stalled.txt")
        out = make_stalled_output(raw, "[]")
        ctx = parse_skanf(out, make_address_target())
        assert isinstance(ctx, SkfnContext)

    def test_free_exploration_has_null_call_pc(self):
        """Empty vulnerability.json → call_pc=None (no Gigahorse detection)."""
        raw = load_fixture("skanf_stalled.txt")
        out = make_stalled_output(raw, "[]")
        ctx = parse_skanf(out, make_address_target())
        assert ctx.call_pc is None

    def test_free_exploration_has_null_calldata(self):
        raw = load_fixture("skanf_stalled.txt")
        out = make_stalled_output(raw, "[]")
        ctx = parse_skanf(out, make_address_target())
        assert ctx.calldata is None


# ─── AC2: EIP-55 address normalization ───────────────────────────────────────

class TestSkfnContextAddressNormalization:
    def test_lowercase_address_normalized_to_eip55(self):
        """SkfnContext.normalize_address validator is called by parse_skanf."""
        lowercase_addr = "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        target = ScanTarget(value=lowercase_addr, is_address=True)
        out = make_stalled_output(STALL_LOG)
        ctx = parse_skanf(out, target)
        # eth_utils.to_checksum_address normalizes mixed case
        assert ctx.contract_address != lowercase_addr
        assert ctx.contract_address.startswith("0x")
        assert len(ctx.contract_address) == 42

    def test_bytecode_scan_uses_zero_address(self):
        """Bytecode scans have no contract address — use 0x000...000."""
        out = make_stalled_output(STALL_LOG)
        ctx = parse_skanf(out, make_bytecode_target())
        # Zero address checksummed by eth_utils
        assert ctx.contract_address == "0x0000000000000000000000000000000000000000"


# ─── Calldata extraction — positive path (H1) ────────────────────────────────

class TestParseSkanfCalldataExtraction:
    def test_calldata_extracted_from_log_line(self):
        """Positive calldata path: CALLDATA log line present → calldata populated."""
        out = make_stalled_output(CALLDATA_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.calldata == "0x1cff79cd" + "00" * 64

    def test_calldata_uppercased_input_lowercased(self):
        """Calldata from log is lowercased and 0x-prefixed by model validator."""
        raw = "INFO | greed | CALLDATA: DEADBEEF"
        out = make_stalled_output(raw)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.calldata == "0xdeadbeef"

    def test_calldata_present_alongside_vuln_fields(self):
        """CALLDATA and vulnerability.json fields both populated simultaneously."""
        out = make_stalled_output(CALLDATA_LOG, VULN_JSON_POPULATED)
        ctx = parse_skanf(out, make_address_target())
        assert ctx.calldata is not None
        assert ctx.call_pc == "0x76"
        assert ctx.vulnerability_type == "ArbitraryCall"


# ─── AC3: Malformed input → SkfnParseError ───────────────────────────────────

class TestParseSkanfMalformedInput:
    def test_invalid_json_raises_parse_error(self):
        out = make_stalled_output(STALL_LOG, '{"broken": json}')
        with pytest.raises(SkfnParseError, match="not valid JSON"):
            parse_skanf(out, make_address_target())

    def test_truncated_json_raises_parse_error(self):
        out = make_stalled_output(STALL_LOG, '[{"vulnerability_type": "ArbitraryCall"')
        with pytest.raises(SkfnParseError):
            parse_skanf(out, make_address_target())

    def test_parse_error_names_skanf(self):
        """SkfnParseError message must be specific (NFR9)."""
        out = make_stalled_output(STALL_LOG, 'not-json')
        with pytest.raises(SkfnParseError, match="SKANF"):
            parse_skanf(out, make_address_target())

    def test_json_null_raises_parse_error(self):
        """'null' is valid JSON but not an array — must raise SkfnParseError."""
        out = make_stalled_output(STALL_LOG, 'null')
        with pytest.raises(SkfnParseError, match="SKANF"):
            parse_skanf(out, make_address_target())

    def test_json_object_raises_parse_error(self):
        """A JSON object instead of array — must raise SkfnParseError."""
        out = make_stalled_output(STALL_LOG, '{"vulnerability_type": "ArbitraryCall"}')
        with pytest.raises(SkfnParseError, match="SKANF"):
            parse_skanf(out, make_address_target())


# ─── Pattern 1: Pure function / no side effects ──────────────────────────────

class TestParseSkanfInterfaceContract:
    def test_returns_skfn_context_type(self):
        out = make_stalled_output(STALL_LOG)
        result = parse_skanf(out, make_address_target())
        assert isinstance(result, SkfnContext)

    def test_never_returns_none(self):
        out = make_stalled_output(STALL_LOG)
        result = parse_skanf(out, make_address_target())
        assert result is not None

    def test_accepts_timeout_kwarg(self):
        out = make_stalled_output(STALL_LOG)
        result = parse_skanf(out, make_address_target(), timeout=30.0)
        assert isinstance(result, SkfnContext)

    def test_accepts_none_timeout(self):
        out = make_stalled_output(STALL_LOG)
        result = parse_skanf(out, make_address_target(), timeout=None)
        assert isinstance(result, SkfnContext)
