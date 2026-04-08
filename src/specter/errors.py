"""Specter exception hierarchy.

All pipeline errors map to typed exceptions with a fixed exit code.
This module imports nothing from specter — it is a pure leaf module.
"""


class SprecterError(Exception):
    """Base class. All Specter errors map to a non-zero exit code."""

    exit_code: int = 3


class SkfnContainerError(SprecterError):
    """SKANF container failed, crashed, or produced unexpected output."""

    exit_code = 3


class SkfnParseError(SprecterError):
    """SKANF output could not be parsed into a valid SkfnContext."""

    exit_code = 3


class AgentError(SprecterError):
    """Claude API call failed or response could not be parsed into AgentCalldata."""

    exit_code = 3


class SprecterValidationError(SprecterError):
    """EVM validation step failed unrecoverably (tool error, not scan failure).

    Named SprecterValidationError to avoid conflict with pydantic.ValidationError.
    """

    exit_code = 3


class ConfigError(SprecterError):
    """Missing env var, Docker not reachable, or dependency check failed."""

    exit_code = 3
