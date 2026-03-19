"""Tests for specter.config — constants and validate_env()."""
import logging

import pytest

import subprocess

from specter.config import (
    DEFAULT_TIMEOUT_SECONDS,
    MODEL_VERSION,
    SKANF_IMAGE_DIGEST,
    check_dependencies,
    validate_env,
)
from specter.errors import ConfigError


# --- AC1: Constants format ---


def test_skanf_image_digest_format():
    assert SKANF_IMAGE_DIGEST.startswith("dockerofsyang/skanf@sha256:")
    sha256_part = SKANF_IMAGE_DIGEST.split("sha256:")[-1]
    assert len(sha256_part) == 64, f"Expected 64-char hex digest, got {len(sha256_part)} chars — update SKANF_IMAGE_DIGEST in config.py"
    assert all(c in "0123456789abcdef" for c in sha256_part), "Digest must be lowercase hex"


def test_model_version():
    assert MODEL_VERSION == "claude-sonnet-4-6"


def test_default_timeout_seconds():
    assert DEFAULT_TIMEOUT_SECONDS == 600


# --- AC2: Missing ANTHROPIC_API_KEY raises ConfigError ---


def test_validate_env_raises_config_error_when_anthropic_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        validate_env()
    assert "ANTHROPIC_API_KEY" in str(exc_info.value)


def test_validate_env_raises_config_error_when_anthropic_key_empty(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    with pytest.raises(ConfigError) as exc_info:
        validate_env()
    assert "ANTHROPIC_API_KEY" in str(exc_info.value)


# --- AC3: Missing ETHERSCAN_API_KEY does NOT raise ---


def test_validate_env_does_not_raise_when_etherscan_key_missing(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    validate_env()  # should not raise


def test_validate_env_warns_when_etherscan_key_missing(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="specter.config"):
        validate_env()
    assert "ETHERSCAN_API_KEY" in caplog.text


def test_validate_env_succeeds_when_all_keys_set(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    with caplog.at_level(logging.WARNING, logger="specter.config"):
        validate_env()
    assert caplog.text == ""


# --- Story 1.6: check_dependencies() ---


def _make_docker_ok():
    def mock_run(args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=0, stdout=b"", stderr=b"")
    return mock_run


def _make_docker_fail():
    def mock_run(args, **kwargs):
        raise subprocess.CalledProcessError(1, args)
    return mock_run


def test_check_dependencies_returns_list_of_check_items(monkeypatch):
    """check_dependencies() returns a non-empty list of CheckItem."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr("specter.config.subprocess.run", _make_docker_ok())
    items = check_dependencies()
    assert isinstance(items, list)
    assert len(items) == 5  # ANTHROPIC_API_KEY, ETHERSCAN_API_KEY, ALCHEMY_RPC_URL, Docker, SKANF image
    for item in items:
        assert hasattr(item, "ok")
        assert hasattr(item, "label")
        assert hasattr(item, "status")


def test_check_dependencies_anthropic_key_missing_is_required_failure(monkeypatch):
    """Missing ANTHROPIC_API_KEY → CheckItem with ok=False, required=True."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("specter.config.subprocess.run", _make_docker_ok())
    items = check_dependencies()
    anthropic_item = next(i for i in items if i.label == "ANTHROPIC_API_KEY")
    assert anthropic_item.ok is False
    assert anthropic_item.required is True
    assert anthropic_item.fix == "export ANTHROPIC_API_KEY=your_key_here"


def test_check_dependencies_etherscan_key_missing_is_not_required(monkeypatch):
    """Missing ETHERSCAN_API_KEY → CheckItem with ok=False, required=False (advisory only)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    monkeypatch.setattr("specter.config.subprocess.run", _make_docker_ok())
    items = check_dependencies()
    etherscan_item = next(i for i in items if i.label == "ETHERSCAN_API_KEY")
    assert etherscan_item.ok is False
    assert etherscan_item.required is False


def test_check_dependencies_docker_fail_is_required_failure(monkeypatch):
    """Docker CalledProcessError → Docker daemon CheckItem ok=False, required=True."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr("specter.config.subprocess.run", _make_docker_fail())
    items = check_dependencies()
    docker_item = next(i for i in items if i.label == "Docker daemon")
    assert docker_item.ok is False
    assert docker_item.required is True
    assert docker_item.fix is not None


def test_check_dependencies_all_ok_has_no_failures(monkeypatch):
    """All deps available → no items with ok=False and required=True."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    monkeypatch.setattr("specter.config.subprocess.run", _make_docker_ok())
    items = check_dependencies()
    required_failures = [i for i in items if not i.ok and i.required]
    assert required_failures == []


def test_check_dependencies_skanf_missing_is_required_failure(monkeypatch):
    """Docker daemon OK but SKANF image not found → SKANF CheckItem ok=False, required=True."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")

    def mock_run(args, **kwargs):
        if args[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(args, returncode=0)
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr("specter.config.subprocess.run", mock_run)
    items = check_dependencies()
    skanf_item = next(i for i in items if i.label == "SKANF image")
    assert skanf_item.ok is False
    assert skanf_item.required is True
    assert skanf_item.fix is not None
    assert "docker pull" in skanf_item.fix
