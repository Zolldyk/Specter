"""Core Pydantic v2 data models for Specter.

This module is the foundation layer — it imports NOTHING from specter.
All other specter modules import FROM this module.
"""
from __future__ import annotations

import enum
from datetime import datetime
import eth_utils
from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class ValidationStatus(str, enum.Enum):
    VALIDATED_EXPLOIT = "validated_exploit"
    AGENT_PROPOSED_UNVALIDATED = "agent_proposed_unvalidated"
    SKANF_DETECTED_UNEXPLOITED = "skanf_detected_unexploited"
    CLEAN = "clean"


class SkfnState(str, enum.Enum):
    EXPLOIT_GENERATED = "exploit_generated"
    STALLED = "stalled"
    CLEAN = "clean"


class ValidationTier(str, enum.Enum):
    FULL_SUCCESS = "full_success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"


class ScanTarget(BaseModel):
    value: str  # address (0x + 40 hex chars) or bytecode (0x + hex)
    is_address: bool  # True = address-based scan, False = raw bytecode


class SkfnOutput(BaseModel):
    state: SkfnState
    raw_output: str  # complete SKANF stdout for downstream parsing
    container_exit_code: int
    vulnerability_json: str = "[]"  # raw vulnerability.json content; populated by runner.py


def _normalize_hex(v: str) -> str:
    """Normalize a hex string: lowercase + ensure 0x prefix."""
    v = v.strip().lower()
    if not v.startswith("0x"):
        v = "0x" + v
    return v


def _normalize_address_eip55(v: str) -> str:
    """Normalize an Ethereum address to EIP-55 checksummed format."""
    v = v.strip().lower()
    if not v.startswith("0x"):
        v = "0x" + v
    return eth_utils.to_checksum_address(v)


class SkfnContext(BaseModel):
    """Parsed SKANF output — fields derived from actual container inspection (Story 2.1).

    Field population sources:
      - contract_address: caller-supplied (EIP-55 checksummed)
      - raw_output: combined stdout+stderr from the full two-phase SKANF pipeline
      - call_pc: key_statement from vulnerability.json (TAC statement ID, e.g. "0x76")
      - vulnerability_type: vulnerability_type from vulnerability.json (e.g. "ArbitraryCall")
      - confidence: confidence from vulnerability.json ("HIGH" / "MEDIUM" / "LOW")
      - key_selector: key_selector from vulnerability.json (4-byte fn selector, 0x-prefixed)
      - calldata: CALLDATA value from greed log line; None means stall (target symbolic)

    Fields NOT present in actual SKANF output (paper Figure 3 only — reserved for future):
      - tainted_bytes: greed internal solver state, not logged to stdout/stderr
      - controllability_flags: greed internal solver state, not logged
      - block_height: only available when WEB3_PROVIDER is configured
      - token_balance: symbolic in greed (BALANCE_<xid>), not serialized to output
    """

    contract_address: str
    raw_output: str

    # From vulnerability.json (Phase 1 Gigahorse output) — None if clean/no detection
    call_pc: str | None = None
    vulnerability_type: str | None = None
    confidence: str | None = None
    key_selector: str | None = None

    # From greed log (Phase 2 symbolic execution) — None means stall
    calldata: str | None = None

    # Paper Figure 3 fields — NOT present in actual SKANF output; reserved for future use
    tainted_bytes: list[int] | None = None
    controllability_flags: dict[str, bool] | None = None
    block_height: int | None = None
    token_balance: str | None = None

    @field_validator("contract_address", mode="before")
    @classmethod
    def normalize_address(cls, v: str) -> str:
        return _normalize_address_eip55(v)

    @field_validator("call_pc", mode="before")
    @classmethod
    def normalize_call_pc(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _normalize_hex(v)

    @field_validator("key_selector", mode="before")
    @classmethod
    def normalize_key_selector(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _normalize_hex(v)

    @field_validator("calldata", mode="before")
    @classmethod
    def normalize_calldata(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _normalize_hex(v)


class AgentCalldata(BaseModel):
    """Exploit calldata produced by the AI agent."""

    calldata: str
    target_address: str
    caller: str
    origin: str

    @field_validator("calldata", mode="before")
    @classmethod
    def normalize_calldata(cls, v: str) -> str:
        return _normalize_hex(v)

    @field_validator("target_address", "caller", "origin", mode="before")
    @classmethod
    def normalize_address_fields(cls, v: str) -> str:
        return _normalize_address_eip55(v)


_TIER_TO_STATUS: dict[ValidationTier, ValidationStatus] = {
    ValidationTier.FULL_SUCCESS: ValidationStatus.VALIDATED_EXPLOIT,
    ValidationTier.PARTIAL_SUCCESS: ValidationStatus.SKANF_DETECTED_UNEXPLOITED,
    ValidationTier.FAILURE: ValidationStatus.CLEAN,
}


class ValidationResult(BaseModel):
    tier: ValidationTier
    live_balance: bool
    validation_status: ValidationStatus  # must match tier per _TIER_TO_STATUS mapping
    raw_output: str | None = None  # SKANF validation mode output

    @model_validator(mode="after")
    def check_tier_status_consistency(self) -> "ValidationResult":
        expected = _TIER_TO_STATUS[self.tier]
        if self.validation_status != expected:
            raise ValueError(
                f"validation_status {self.validation_status!r} is inconsistent with "
                f"tier {self.tier!r} (expected {expected!r})"
            )
        return self

    @classmethod
    def from_tier(
        cls,
        tier: ValidationTier,
        live_balance: bool,
        raw_output: str | None = None,
    ) -> "ValidationResult":
        """Canonical constructor that derives validation_status from tier."""
        return cls(
            tier=tier,
            live_balance=live_balance,
            validation_status=_TIER_TO_STATUS[tier],
            raw_output=raw_output,
        )


class Finding(BaseModel):
    skanf_summary: str | None = None
    failure_mode: str | None = None
    agent_reasoning: str | None = None  # populated when --verbose
    exploit_calldata: AgentCalldata | None = None
    validation_result: ValidationResult | None = None


class ScanResult(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    contract_address: str  # 0x-prefixed, EIP-55 checksummed — normalized by validator below
    scan_timestamp: datetime  # ISO 8601
    skanf_version_digest: str  # sha256:<hash>
    model_version: str  # from config.MODEL_VERSION
    validation_status: ValidationStatus  # the machine-readable gate field
    finding: Finding | None  # None when status=clean
    runtime_seconds: float  # NFR4: always present in JSON output
    error: str | None  # None on success, error message on tool error

    @field_validator("contract_address", mode="before")
    @classmethod
    def normalize_contract_address(cls, v: str) -> str:
        return _normalize_address_eip55(v)
