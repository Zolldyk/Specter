"""Tests for SecretFilter and logging helpers (Story 1.3, AC1, AC4)."""
import logging

import pytest

from specter.logging_config import SecretFilter, _register_secret_filter, _set_log_level


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(msg: str, *args: object) -> logging.LogRecord:
    """Create a LogRecord with the given message and optional args."""
    record = logging.LogRecord(
        name="test",
        level=logging.DEBUG,
        pathname="",
        lineno=0,
        msg=msg,
        args=args if args else None,
        exc_info=None,
    )
    return record


# ---------------------------------------------------------------------------
# SecretFilter — basic redaction
# ---------------------------------------------------------------------------


class TestSecretFilterRedactsMsg:
    """AC1: SecretFilter replaces known secret values in record.msg."""

    def test_redacts_api_key_in_msg(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-super-secret")
        sf = SecretFilter()
        record = _make_record("Calling API with key sk-ant-super-secret in URL")
        sf.filter(record)
        assert "sk-ant-super-secret" not in record.msg
        assert "***" in record.msg

    def test_replaces_with_triple_stars(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "my-secret-key")
        sf = SecretFilter()
        record = _make_record("key=my-secret-key")
        sf.filter(record)
        assert record.msg == "key=***"

    def test_does_not_redact_when_no_match(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "real-secret")
        sf = SecretFilter()
        record = _make_record("no secrets here")
        sf.filter(record)
        assert record.msg == "no secrets here"

    def test_always_returns_true(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "some-key")
        sf = SecretFilter()
        record = _make_record("hello")
        result = sf.filter(record)
        assert result is True

    def test_returns_true_when_no_secrets_configured(self, monkeypatch):
        # Remove any _API_KEY env vars
        for key in list(__import__("os").environ.keys()):
            if key.endswith("_API_KEY"):
                monkeypatch.delenv(key, raising=False)
        sf = SecretFilter()
        record = _make_record("some message")
        assert sf.filter(record) is True


class TestSecretFilterRedactsArgs:
    """AC4: SecretFilter replaces secret values found in record.args (tuple)."""

    def test_redacts_secret_in_tuple_args(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-123")
        sf = SecretFilter()
        record = _make_record("URL: %s", "https://api.example.com/v1?key=sk-secret-123")
        sf.filter(record)
        assert isinstance(record.args, tuple)
        assert "sk-secret-123" not in record.args[0]
        assert "***" in record.args[0]

    def test_redacts_secret_in_dict_args(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-abc")
        sf = SecretFilter()
        # Python 3.13 LogRecord constructor rejects raw dict args;
        # set record.args directly after construction to replicate the
        # internal state produced by logger.debug("%(url)s", {"url": "..."}).
        record = _make_record("endpoint: %(url)s")
        record.args = {"url": "https://api.example.com?key=sk-secret-abc"}
        sf.filter(record)
        assert isinstance(record.args, dict)
        assert "sk-secret-abc" not in record.args["url"]
        assert "***" in record.args["url"]

    def test_non_string_args_are_untouched(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-xyz")
        sf = SecretFilter()
        record = _make_record("count: %d", 42)
        sf.filter(record)
        assert record.args == (42,)

    def test_redacts_secret_embedded_in_url(self, monkeypatch):
        """AC4: value-matching catches secrets inside formatted URLs."""
        monkeypatch.setenv("OPENAI_API_KEY", "openai-key-999")
        sf = SecretFilter()
        record = _make_record(
            "request to https://api.openai.com/v1/completions?key=openai-key-999"
        )
        sf.filter(record)
        assert "openai-key-999" not in record.msg
        assert "***" in record.msg


class TestSecretFilterCapturesAtConstruction:
    """Filter reads env vars at __init__ time, not at filter time."""

    def test_secret_set_after_construction_not_redacted(self, monkeypatch):
        # Ensure clean env
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        sf = SecretFilter()
        # Set the var AFTER construction
        monkeypatch.setenv("ANTHROPIC_API_KEY", "late-secret")
        record = _make_record("key=late-secret")
        sf.filter(record)
        # Should NOT be redacted — filter was built before env var was set
        assert "late-secret" in record.msg

    def test_secret_set_before_construction_is_redacted(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "early-secret")
        sf = SecretFilter()
        record = _make_record("key=early-secret")
        sf.filter(record)
        assert "early-secret" not in record.msg


class TestSecretFilterMultipleKeys:
    """Handles multiple *_API_KEY env vars simultaneously."""

    def test_redacts_all_api_keys(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-secret")
        monkeypatch.setenv("OPENAI_API_KEY", "oai-secret")
        sf = SecretFilter()
        record = _make_record("keys: ant-secret and oai-secret")
        sf.filter(record)
        assert "ant-secret" not in record.msg
        assert "oai-secret" not in record.msg

    def test_empty_api_key_value_not_added(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        sf = SecretFilter()
        # Empty string would match everything — must be excluded
        record = _make_record("hello world")
        result = sf.filter(record)
        assert result is True
        assert record.msg == "hello world"


# ---------------------------------------------------------------------------
# _register_secret_filter
# ---------------------------------------------------------------------------


@pytest.fixture()
def clean_root_secret_filters():
    """Remove all SecretFilter instances from root logger before and after each test."""
    root = logging.getLogger()
    root.filters = [f for f in root.filters if not isinstance(f, SecretFilter)]
    yield root
    root.filters = [f for f in root.filters if not isinstance(f, SecretFilter)]


@pytest.fixture()
def restore_root_log_level():
    """Restore the root logger level after each test."""
    root = logging.getLogger()
    original_level = root.level
    yield root
    root.setLevel(original_level)


class TestRegisterSecretFilter:
    def test_attaches_filter_to_root_logger(self, clean_root_secret_filters):
        root = clean_root_secret_filters
        before_count = len(root.filters)
        _register_secret_filter()
        assert len(root.filters) > before_count

    def test_filter_is_secret_filter_instance(self, clean_root_secret_filters):
        root = clean_root_secret_filters
        _register_secret_filter()
        secret_filters = [f for f in root.filters if isinstance(f, SecretFilter)]
        assert len(secret_filters) >= 1

    def test_is_idempotent(self, clean_root_secret_filters):
        """Calling _register_secret_filter() twice must not add duplicate filters."""
        root = clean_root_secret_filters
        _register_secret_filter()
        _register_secret_filter()
        secret_filters = [f for f in root.filters if isinstance(f, SecretFilter)]
        assert len(secret_filters) == 1


# ---------------------------------------------------------------------------
# _set_log_level
# ---------------------------------------------------------------------------


class TestSetLogLevel:
    def test_verbose_true_sets_debug(self, restore_root_log_level):
        _set_log_level(verbose=True)
        assert logging.getLogger().level == logging.DEBUG

    def test_verbose_false_sets_info(self, restore_root_log_level):
        _set_log_level(verbose=False)
        assert logging.getLogger().level == logging.INFO

    def test_calling_twice_overrides(self, restore_root_log_level):
        _set_log_level(verbose=True)
        assert logging.getLogger().level == logging.DEBUG
        _set_log_level(verbose=False)
        assert logging.getLogger().level == logging.INFO


# ---------------------------------------------------------------------------
# Module import purity (AC3 analogue for logging_config)
# ---------------------------------------------------------------------------


class TestLoggingConfigModuleHasNoSprecterImports:
    """logging_config.py must only import stdlib (os, logging)."""

    def test_no_specter_imports(self):
        import ast
        import pathlib

        module_path = (
            pathlib.Path(__file__).parent.parent / "src/specter/logging_config.py"
        )
        tree = ast.parse(module_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("specter"), (
                        f"logging_config.py must not import from specter, found: {alias.name}"
                    )
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    assert not node.module.startswith("specter"), (
                        f"logging_config.py must not import from specter, found: {node.module}"
                    )
