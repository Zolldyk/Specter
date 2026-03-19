"""SKANF Figure 3 output parser — pipeline stage 2.

Imports: specter.errors, specter.models, and stdlib only.
Never imports from specter.cli, specter.config, or other pipeline stages.
"""
import json
import logging
import re

from pydantic import ValidationError

from specter.errors import SkfnParseError
from specter.models import ScanTarget, SkfnContext, SkfnOutput

logger = logging.getLogger(__name__)

_CALLDATA_RE = re.compile(r"INFO \| greed \| CALLDATA: ([0-9a-fA-F]+)")


def parse_skanf(
    skanf_output: SkfnOutput,
    scan_target: ScanTarget,
    *,
    timeout: float | None = None,
) -> SkfnContext:
    """Parse SKANF SkfnOutput into a validated SkfnContext.

    Called ONLY when skanf_output.state == SkfnState.STALLED.
    Implements the Pattern 1 pipeline stage interface.

    Args:
        skanf_output: Output from run_skanf() with state=STALLED.
        scan_target: Original scan target (provides contract_address).
        timeout: Budget parameter (unused in parser — parsing is synchronous).

    Returns:
        SkfnContext with all available fields populated from SKANF output.

    Raises:
        SkfnParseError: vulnerability.json is not valid JSON, or Pydantic
                        validation fails on the constructed SkfnContext.
    """
    raw = skanf_output.raw_output
    vuln_json_str = skanf_output.vulnerability_json

    # Derive contract_address from scan target
    contract_address = scan_target.value if scan_target.is_address else "0x" + "0" * 40

    # Parse vulnerability.json for Phase 1 Gigahorse findings
    call_pc = None
    vulnerability_type = None
    confidence = None
    key_selector = None

    logger.debug("SKANF parser: parsing vulnerability.json: %r", vuln_json_str[:200])

    try:
        vuln_data = json.loads(vuln_json_str or "[]")
    except json.JSONDecodeError as exc:
        logger.debug("SKANF parser: malformed vulnerability.json:\n%s", vuln_json_str)
        raise SkfnParseError(
            "SKANF vulnerability.json is not valid JSON — cannot parse SkfnContext"
        ) from exc

    if not isinstance(vuln_data, list):
        raise SkfnParseError(
            f"SKANF vulnerability.json must be a JSON array — got {type(vuln_data).__name__}"
        )

    if vuln_data:
        entry = vuln_data[0]  # primary (first) vulnerability entry
        call_pc = entry.get("key_statement")            # e.g., "0x76"
        vulnerability_type = entry.get("vulnerability_type")  # e.g., "ArbitraryCall"
        confidence = entry.get("confidence")             # e.g., "HIGH"
        key_selector = entry.get("key_selector")         # e.g., "0x1cff79cd"
        logger.debug(
            "SKANF parser: vuln entry — call_pc=%r type=%r conf=%r sel=%r",
            call_pc, vulnerability_type, confidence, key_selector,
        )

    # Extract calldata from greed CALLDATA log line (None when STALLED)
    calldata_match = _CALLDATA_RE.search(raw)
    calldata = ("0x" + calldata_match.group(1).lower()) if calldata_match else None

    logger.info("SKANF Figure 3 context parsed — call_pc=%r, calldata=%r", call_pc, calldata)

    try:
        return SkfnContext(
            contract_address=contract_address,
            raw_output=raw,
            call_pc=call_pc,
            vulnerability_type=vulnerability_type,
            confidence=confidence,
            key_selector=key_selector,
            calldata=calldata,
            # Paper Figure 3 fields not present in actual output — remain None
        )
    except ValidationError as exc:
        raise SkfnParseError(
            f"SKANF output produced an invalid SkfnContext: {exc}"
        ) from exc
