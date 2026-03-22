"""Find CALL instruction IDs with dynamic (non-static) target addresses.

This script is executed inside the SKANF Docker container after analyze_hex.sh.
It loads the Gigahorse output via the greed Python API and returns a space-
separated list of CALL statement IDs whose target address is not statically known.
These IDs are passed to `greed --find` for directed symbolic execution.

Usage (inside container):
    python3 /workdir/_find_call_pcs.py
"""
import sys

try:
    from greed import Project

    p = Project(target_dir="/workdir")
    ids = [
        s.id
        for func in p.function_at.values()
        for block in func.blocks
        for s in block._statement_at.values()
        if s.__internal_name__ == "CALL" and s.arg2_val is None
    ]
    sys.stdout.write(" ".join(ids[:6]))
except Exception:
    sys.stdout.write("")
