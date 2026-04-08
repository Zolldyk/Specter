"""Specter configuration constants and environment validation.

Imports: specter.errors and stdlib only (os, logging).
"""

import logging
import os
import subprocess
from typing import NamedTuple

from specter.errors import ConfigError

# Pinned dependency constants — single sources of truth
# NFR12: SKANF Docker image pinned by sha256 digest (never by tag)
# Replace <hash> with the actual sha256 digest from `docker pull dockerofsyang/skanf` output
SKANF_IMAGE_DIGEST = "dockerofsyang/skanf@sha256:5ef0297fd41b8e7e94f8e4fdc0c0a0d135078db675e2017a81735c27c447c817"

# NFR13: Claude model pinned by explicit version string
MODEL_VERSION = "claude-sonnet-4-6"

# OpenAI model used when OPENAI_API_KEY is set and ANTHROPIC_API_KEY is absent/invalid
OPENAI_MODEL_VERSION = "gpt-4o"

# Gemini model used when GEMINI_API_KEY is set
GEMINI_MODEL_VERSION = "gemini-2.5-flash"

# NFR1: Default scan timeout ceiling
DEFAULT_TIMEOUT_SECONDS = 600

# Optional RPC endpoint for address-based bytecode resolution (soft dependency).
# NOTE: evaluated once at import time — do NOT use for runtime checks.
# Runtime consumers (runner.py, check_dependencies) must call os.environ.get() directly.
ALCHEMY_RPC_URL: str | None = os.environ.get("ALCHEMY_RPC_URL")


class CheckItem(NamedTuple):
    """Result of a single dependency check performed by `specter check`."""

    ok: bool
    label: str
    status: str
    fix: str | None = None
    required: bool = True


_logger = logging.getLogger(__name__)


def get_active_model_version() -> str:
    """Return the model version string for whichever AI provider key is active.

    Priority matches call_agent(): ANTHROPIC_API_KEY → OPENAI_API_KEY → GEMINI_API_KEY.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return MODEL_VERSION
    if os.environ.get("OPENAI_API_KEY"):
        return OPENAI_MODEL_VERSION
    if os.environ.get("GEMINI_API_KEY"):
        return GEMINI_MODEL_VERSION
    return MODEL_VERSION  # fallback — validate_env() will catch the missing key


def validate_env() -> None:
    """Validate required environment variables. Call third in CLI startup sequence.

    Raises:
        ConfigError: If neither ANTHROPIC_API_KEY nor OPENAI_API_KEY is set.
    """
    if (
        not os.environ.get("ANTHROPIC_API_KEY")
        and not os.environ.get("OPENAI_API_KEY")
        and not os.environ.get("GEMINI_API_KEY")
    ):
        raise ConfigError(
            "No AI provider API key set. "
            "Export ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY before running specter."
        )

    if not os.environ.get("ETHERSCAN_API_KEY"):
        _logger.warning(
            "ETHERSCAN_API_KEY not set — Etherscan contract metadata unavailable for address-based scans"
        )


def check_dependencies() -> list[CheckItem]:
    """Run all dependency checks for `specter check`. Call after _register_secret_filter().

    Returns a list of CheckItem — one per checked dependency. Callers use
    `item.required and not item.ok` to determine whether to exit 3.
    """
    items: list[CheckItem] = []

    # AI provider key — at least one of ANTHROPIC_API_KEY or OPENAI_API_KEY required
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    if has_anthropic:
        items.append(CheckItem(True, "ANTHROPIC_API_KEY", "set", required=False))
    else:
        items.append(CheckItem(False, "ANTHROPIC_API_KEY", "not set",
            fix="export ANTHROPIC_API_KEY=your_key_here", required=False))
    if has_openai:
        items.append(CheckItem(True, "OPENAI_API_KEY", "set", required=False))
    else:
        items.append(CheckItem(False, "OPENAI_API_KEY", "not set",
            fix="export OPENAI_API_KEY=your_key_here", required=False))
    has_gemini = bool(os.environ.get("GEMINI_API_KEY"))
    if has_gemini:
        items.append(CheckItem(True, "GEMINI_API_KEY", "set", required=False))
    else:
        items.append(CheckItem(False, "GEMINI_API_KEY", "not set",
            fix="export GEMINI_API_KEY=your_key_here", required=False))
    if not has_anthropic and not has_openai and not has_gemini:
        items.append(CheckItem(False, "AI provider key", "no provider key set",
            fix="export ANTHROPIC_API_KEY=... or OPENAI_API_KEY=... or GEMINI_API_KEY=..."))

    # ETHERSCAN_API_KEY (optional — missing does not cause exit 3)
    if os.environ.get("ETHERSCAN_API_KEY"):
        items.append(CheckItem(True, "ETHERSCAN_API_KEY", "set", required=False))
    else:
        items.append(CheckItem(
            False, "ETHERSCAN_API_KEY", "not set",
            fix="export ETHERSCAN_API_KEY=your_key_here",
            required=False,
        ))

    # ALCHEMY_RPC_URL (optional — warn only, same pattern as ETHERSCAN_API_KEY)
    if os.environ.get("ALCHEMY_RPC_URL"):
        items.append(CheckItem(True, "ALCHEMY_RPC_URL", "set", required=False))
    else:
        items.append(CheckItem(
            False, "ALCHEMY_RPC_URL", "not set",
            fix="export ALCHEMY_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/your_key",
            required=False,
        ))

    # Docker daemon (required)
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
        items.append(CheckItem(True, "Docker daemon", "running"))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        items.append(CheckItem(
            False, "Docker daemon", "not running",
            fix="Start Docker Desktop or run: sudo systemctl start docker",
        ))

    # SKANF image (required — presence checked with docker image inspect)
    # Note: if Docker daemon is also down, this check will also fail, producing two ✗ entries
    # for the same root cause. The Docker daemon fix takes precedence; fixing it resolves both.
    try:
        subprocess.run(
            ["docker", "image", "inspect", SKANF_IMAGE_DIGEST],
            capture_output=True, timeout=5, check=True,
        )
        items.append(CheckItem(True, "SKANF image", "present"))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        items.append(CheckItem(
            False, "SKANF image", "not found",
            fix=f"docker pull {SKANF_IMAGE_DIGEST}",
        ))

    return items
