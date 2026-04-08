"""Tests for specter.output.json_out — JSON report renderer."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from specter.models import (
    ScanResult,
    ValidationStatus,
)
from specter.output.json_out import render_json
from test_markdown import make_scan_result

REQUIRED_FIELDS = {
    "contract_address",
    "scan_timestamp",
    "skanf_version_digest",
    "model_version",
    "validation_status",
    "finding",
    "runtime_seconds",
    "error",
}


class TestJsonOut:
    def test_required_fields_present(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        data = json.loads(render_json(result))
        assert REQUIRED_FIELDS.issubset(data.keys())

    def test_validation_status_validated_exploit(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        data = json.loads(render_json(result))
        assert data["validation_status"] == "validated_exploit"

    def test_validation_status_agent_proposed_unvalidated(self):
        result = make_scan_result(ValidationStatus.AGENT_PROPOSED_UNVALIDATED)
        data = json.loads(render_json(result))
        assert data["validation_status"] == "agent_proposed_unvalidated"

    def test_validation_status_skanf_detected_unexploited(self):
        result = make_scan_result(ValidationStatus.SKANF_DETECTED_UNEXPLOITED)
        data = json.loads(render_json(result))
        assert data["validation_status"] == "skanf_detected_unexploited"

    def test_validation_status_clean(self):
        result = make_scan_result(ValidationStatus.CLEAN)
        data = json.loads(render_json(result))
        assert data["validation_status"] == "clean"
        assert data["finding"] is None

    def test_output_is_valid_json(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        # Raises no exception if valid JSON
        json.loads(render_json(result))

    def test_returns_string_not_bytes(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        output = render_json(result)
        assert isinstance(output, str)
        assert not isinstance(output, bytes)

    def test_no_ansi_codes(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        output = render_json(result)
        assert "\x1b[" not in output

    def test_scan_timestamp_iso8601(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        data = json.loads(render_json(result))
        ts = data["scan_timestamp"]
        # Should parse without raising
        datetime.fromisoformat(ts)

    def test_runtime_seconds_present(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        data = json.loads(render_json(result))
        assert isinstance(data["runtime_seconds"], float)

    def test_finding_null_when_clean(self):
        result = make_scan_result(ValidationStatus.CLEAN)
        data = json.loads(render_json(result))
        assert data["finding"] is None

    def test_finding_populated_when_exploit(self):
        result = make_scan_result(ValidationStatus.VALIDATED_EXPLOIT)
        data = json.loads(render_json(result))
        assert data["finding"] is not None
