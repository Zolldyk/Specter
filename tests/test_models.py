"""Tests for src/specter/models.py — Story 1.2: Core Data Models."""
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
    assert r.validation_status == ValidationStatus.SKANF_DETECTED_UNEXPLOITED

    r = ValidationResult.from_tier(ValidationTier.FAILURE, live_balance=False)
    assert r.validation_status == ValidationStatus.CLEAN


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
