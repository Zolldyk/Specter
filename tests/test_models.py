"""Tests for src/specter/models.py — Story 1.2: Core Data Models + Story 2.1: SkfnContext expansion."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from specter.models import (
    AgentCalldata,
    Finding,
    ScanResult,
    ScanTarget,
    SkfnContext,
    SkfnOutput,
    SkfnState,
    ValidationResult,
    ValidationStatus,
    ValidationTier,
    _TIER_TO_STATUS,
)
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# AC1 — ValidationStatus enum enforcement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "validated_exploit",
        "agent_proposed_unvalidated",
        "skanf_detected_unexploited",
        "clean",
    ],
)
def test_validation_status_accepts_valid_values(value: str) -> None:
    assert ValidationStatus(value).value == value


@pytest.mark.parametrize(
    "bad_value",
    ["CLEAN", "invalid", "dirty", "", "validated", "exploit"],
)
def test_validation_status_rejects_invalid_values(bad_value: str) -> None:
    with pytest.raises(ValueError):
        ValidationStatus(bad_value)


def test_validation_status_has_exactly_four_values() -> None:
    assert len(ValidationStatus) == 4


# ---------------------------------------------------------------------------
# AC2 — AgentCalldata hex normalization
# ---------------------------------------------------------------------------


def test_agentcalldata_normalizes_calldata_missing_prefix() -> None:
    m = AgentCalldata(
        calldata="deadbeef",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    )
    assert m.calldata == "0xdeadbeef"


def test_agentcalldata_normalizes_calldata_uppercase() -> None:
    m = AgentCalldata(
        calldata="0xDEADBEEF",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    )
    assert m.calldata == "0xdeadbeef"


def test_agentcalldata_normalizes_calldata_missing_prefix_and_uppercase() -> None:
    m = AgentCalldata(
        calldata="DEADBEEF",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    )
    assert m.calldata == "0xdeadbeef"


def test_agentcalldata_normalizes_target_address() -> None:
    m = AgentCalldata(
        calldata="0xdeadbeef",
        target_address="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    )
    # Must be EIP-55 checksummed (mixed case, 0x-prefixed)
    assert m.target_address == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"


def test_agentcalldata_normalizes_caller() -> None:
    m = AgentCalldata(
        calldata="0xdeadbeef",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="DE0B295669A9FD93D5F28D9EC85E40F4CB697BAE",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    )
    assert m.caller == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"


def test_agentcalldata_normalizes_origin() -> None:
    m = AgentCalldata(
        calldata="0xdeadbeef",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="DE0B295669A9FD93D5F28D9EC85E40F4CB697BAE",
    )
    assert m.origin == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"


def test_agentcalldata_value_defaults_to_zero() -> None:
    m = AgentCalldata(
        calldata="0xdeadbeef",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    )
    assert m.value == 0


def test_agentcalldata_value_accepts_nonzero() -> None:
    m = AgentCalldata(
        calldata="0xdeadbeef",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        value=1_000_000_000_000_000_000,
    )
    assert m.value == 1_000_000_000_000_000_000


def test_agentcalldata_value_present_in_json() -> None:
    m = AgentCalldata(
        calldata="0xdeadbeef",
        target_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        caller="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        origin="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        value=42,
    )
    import json
    data = json.loads(m.model_dump_json())
    assert "value" in data
    assert data["value"] == 42


# ---------------------------------------------------------------------------
# AC3 — ScanResult JSON schema
# ---------------------------------------------------------------------------


def test_scanresult_schema_has_exactly_four_validation_status_values() -> None:
    schema = ScanResult.model_json_schema()
    # Find the enum definition - may be in $defs
    defs = schema.get("$defs", {})
    vs_def = defs.get("ValidationStatus", {})
    enum_values = vs_def.get("enum", [])
    assert len(enum_values) == 4
    assert set(enum_values) == {
        "validated_exploit",
        "agent_proposed_unvalidated",
        "skanf_detected_unexploited",
        "clean",
    }


# ---------------------------------------------------------------------------
# AC4 — ScanResult field completeness
# ---------------------------------------------------------------------------


def test_scanresult_json_includes_all_required_fields() -> None:
    import json

    result = ScanResult(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        skanf_version_digest="sha256:abc123",
        model_version="1.0.0",
        validation_status=ValidationStatus.CLEAN,
        finding=None,
        runtime_seconds=1.23,
        error=None,
    )
    # AC4: serialize to JSON and inspect — not just a dict
    data = json.loads(result.model_dump_json())
    for field in [
        "contract_address",
        "scan_timestamp",
        "skanf_version_digest",
        "model_version",
        "validation_status",
        "finding",
        "runtime_seconds",
        "error",
    ]:
        assert field in data, f"Missing field: {field}"
    # scan_timestamp must be ISO 8601 string in JSON output
    assert isinstance(data["scan_timestamp"], str)
    assert data["scan_timestamp"] == "2026-03-17T12:00:00Z"
    # validation_status must be the string value, not enum object
    assert data["validation_status"] == "clean"


def test_scanresult_has_exactly_eight_fields() -> None:
    result = ScanResult(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        skanf_version_digest="sha256:abc123",
        model_version="1.0.0",
        validation_status=ValidationStatus.CLEAN,
        finding=None,
        runtime_seconds=1.23,
        error=None,
    )
    assert len(ScanResult.model_fields) == 8


# ---------------------------------------------------------------------------
# SkfnContext address normalization
# ---------------------------------------------------------------------------


def test_skfncontext_normalizes_address_to_checksummed() -> None:
    ctx = SkfnContext(
        contract_address="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        raw_output="some output",
    )
    # Must have 0x prefix
    assert ctx.contract_address.startswith("0x")
    # Must be EIP-55 checksummed (mixed case)
    expected = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    assert ctx.contract_address == expected


def test_skfncontext_accepts_already_checksummed_address() -> None:
    addr = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    ctx = SkfnContext(contract_address=addr, raw_output="out")
    assert ctx.contract_address == addr


# ---------------------------------------------------------------------------
# ScanResult contract_address EIP-55 normalization (H1/H2 fix)
# ---------------------------------------------------------------------------


def test_scanresult_normalizes_contract_address_to_eip55() -> None:
    result = ScanResult(
        contract_address="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",  # lowercase, no 0x
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        skanf_version_digest="sha256:abc123",
        model_version="1.0.0",
        validation_status=ValidationStatus.CLEAN,
        finding=None,
        runtime_seconds=1.23,
        error=None,
    )
    assert result.contract_address == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"


def test_scanresult_accepts_already_checksummed_address() -> None:
    addr = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    result = ScanResult(
        contract_address=addr,
        scan_timestamp=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
        skanf_version_digest="sha256:abc123",
        model_version="1.0.0",
        validation_status=ValidationStatus.CLEAN,
        finding=None,
        runtime_seconds=1.23,
        error=None,
    )
    assert result.contract_address == addr


# ---------------------------------------------------------------------------
# ValidationResult tier/status consistency (M2 fix)
# ---------------------------------------------------------------------------


def test_validationresult_from_tier_derives_status() -> None:
    r = ValidationResult.from_tier(ValidationTier.FULL_SUCCESS, live_balance=True)
    assert r.validation_status == ValidationStatus.VALIDATED_EXPLOIT

    r = ValidationResult.from_tier(ValidationTier.PARTIAL_SUCCESS, live_balance=False)
    assert r.validation_status == ValidationStatus.AGENT_PROPOSED_UNVALIDATED

    r = ValidationResult.from_tier(ValidationTier.FAILURE, live_balance=False)
    assert r.validation_status == ValidationStatus.SKANF_DETECTED_UNEXPLOITED


def test_validationresult_rejects_inconsistent_tier_status() -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        ValidationResult(
            tier=ValidationTier.FULL_SUCCESS,
            live_balance=True,
            validation_status=ValidationStatus.CLEAN,  # wrong — should be VALIDATED_EXPLOIT
        )


def test_validationresult_tier_to_status_mapping_is_complete() -> None:
    assert set(_TIER_TO_STATUS.keys()) == set(ValidationTier)


# ---------------------------------------------------------------------------
# SkfnContext expanded fields (Story 2.1 — real SKANF output inspection)
# ---------------------------------------------------------------------------


def test_skfncontext_minimal_construction_still_works() -> None:
    """Existing callers with only contract_address+raw_output must not break."""
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="Running gigahorse.py\nYes\n",
    )
    assert ctx.call_pc is None
    assert ctx.vulnerability_type is None
    assert ctx.confidence is None
    assert ctx.key_selector is None
    assert ctx.calldata is None
    assert ctx.tainted_bytes is None
    assert ctx.controllability_flags is None
    assert ctx.block_height is None
    assert ctx.token_balance is None


def test_skfncontext_call_pc_normalizes_hex() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        call_pc="76",  # no 0x prefix
    )
    assert ctx.call_pc == "0x76"


def test_skfncontext_call_pc_normalizes_uppercase() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        call_pc="0X76",
    )
    assert ctx.call_pc == "0x76"


def test_skfncontext_call_pc_none_passes_through() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        call_pc=None,
    )
    assert ctx.call_pc is None


def test_skfncontext_key_selector_normalizes_hex() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        key_selector="1CFF79CD",  # uppercase, no 0x
    )
    assert ctx.key_selector == "0x1cff79cd"


def test_skfncontext_calldata_normalizes_hex() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        calldata="1CFF79CD0000",  # uppercase, no 0x
    )
    assert ctx.calldata == "0x1cff79cd0000"


def test_skfncontext_calldata_none_means_stall() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="INFO | greed.TAC.flow_ops | Calling contract <SYMBOLIC> (134_1)",
        call_pc="0x76",
        vulnerability_type="ArbitraryCall",
        calldata=None,
    )
    assert ctx.calldata is None


def test_skfncontext_full_success_fields() -> None:
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="INFO | greed | Found State 7 at 0x76\nINFO | greed | CALLDATA: 1cff79cd0000",
        call_pc="0x76",
        vulnerability_type="ArbitraryCall",
        confidence="HIGH",
        key_selector="0x1cff79cd",
        calldata="1cff79cd0000",
    )
    assert ctx.call_pc == "0x76"
    assert ctx.vulnerability_type == "ArbitraryCall"
    assert ctx.confidence == "HIGH"
    assert ctx.key_selector == "0x1cff79cd"
    assert ctx.calldata == "0x1cff79cd0000"
    # Paper fields stay None when not set
    assert ctx.tainted_bytes is None
    assert ctx.controllability_flags is None
    assert ctx.block_height is None
    assert ctx.token_balance is None


def test_skfncontext_optional_paper_fields_accept_values() -> None:
    """Reserved paper-fields (tainted_bytes, etc.) accept values when provided."""
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        tainted_bytes=[0, 4, 8],
        controllability_flags={"arg0": True, "arg1": False},
        block_height=19500000,
        token_balance="1500000000000000000",
    )
    assert ctx.tainted_bytes == [0, 4, 8]
    assert ctx.controllability_flags == {"arg0": True, "arg1": False}
    assert ctx.block_height == 19500000
    assert ctx.token_balance == "1500000000000000000"


def test_skfncontext_contract_address_still_checksummed_with_new_fields() -> None:
    ctx = SkfnContext(
        contract_address="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        raw_output="...",
        call_pc="0x76",
    )
    assert ctx.contract_address == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"


def test_skfncontext_confidence_accepts_any_string_by_design() -> None:
    """confidence is an unvalidated str — any string is accepted (not an enum).
    Parser (Story 2.4) is responsible for mapping greed output to HIGH/MEDIUM/LOW.
    This test documents the 'any string allowed' decision explicitly.
    """
    ctx = SkfnContext(
        contract_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        raw_output="...",
        confidence="BOGUS_VALUE",
    )
    assert ctx.confidence == "BOGUS_VALUE"


def test_skfncontext_rejects_invalid_contract_address() -> None:
    with pytest.raises(Exception):  # eth_utils raises ValueError or similar
        SkfnContext(contract_address="not_an_address", raw_output="some output")


# ---------------------------------------------------------------------------
# models.py zero specter imports (Task 3)
# ---------------------------------------------------------------------------


def test_models_has_no_specter_imports() -> None:
    """Verify models.py source contains no 'from specter' or 'import specter' lines."""
    import pathlib

    models_path = pathlib.Path(__file__).parent.parent / "src" / "specter" / "models.py"
    source = models_path.read_text()
    lines = source.splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not (
            stripped.startswith("from specter") or stripped.startswith("import specter")
        ), f"Forbidden import found: {line!r}"
