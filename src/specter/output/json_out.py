"""JSON report renderer for Specter scan results.

Returns a plain JSON string — no stream writes, no ANSI codes.
Only imports from specter.models (top-down import rule enforced).
"""
from specter.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Render a ScanResult as a stable JSON string.

    Returns plain str — no stream writes. Caller (cli.py) writes to stdout.
    Only imports from specter.models (top-down import rule enforced).
    """
    return result.model_dump_json(indent=2)
