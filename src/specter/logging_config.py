"""Specter logging configuration.

Provides SecretFilter for redacting API key values from all log output,
and helpers for registering the filter and setting the log level.

This module imports nothing from specter — only stdlib os and logging.
"""
import logging
import os


class SecretFilter(logging.Filter):
    """Redacts known API key values from log records before emission.

    Secrets are captured from environment variables ending with ``_API_KEY``
    at construction time.  Any occurrence of a secret value in ``record.msg``
    or ``record.args`` is replaced with ``***``.

    Value-matching is used (not key-name matching), so a secret appearing
    inside a formatted URL or exception message is also redacted.
    """

    def __init__(self) -> None:
        super().__init__()
        # Capture non-empty values at construction — immutable after init.
        self._secrets: frozenset[str] = frozenset(
            v
            for k, v in os.environ.items()
            if k.endswith("_API_KEY") and v
        )

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if not self._secrets:
            return True

        for secret in self._secrets:
            # Replace in the format string
            if isinstance(record.msg, str):
                record.msg = record.msg.replace(secret, "***")

            # Replace in format args — handles logger.debug("url: %s", url_with_key)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: v.replace(secret, "***") if isinstance(v, str) else v
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        v.replace(secret, "***") if isinstance(v, str) else v
                        for v in record.args
                    )

        return True


def _register_secret_filter() -> None:
    """Register SecretFilter on the root logger (idempotent).

    Must be called first in the CLI startup sequence — before any pipeline
    code runs — so that secrets are protected regardless of log level.
    Safe to call multiple times; only one SecretFilter is ever attached.
    """
    root_logger = logging.getLogger()
    if not any(isinstance(f, SecretFilter) for f in root_logger.filters):
        root_logger.addFilter(SecretFilter())


def _set_log_level(verbose: bool) -> None:
    """Set the root logger level to DEBUG (verbose) or INFO (default).

    Must be called after ``_register_secret_filter()`` so that the filter
    is in place before any debug-level output can be emitted.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger().setLevel(level)
