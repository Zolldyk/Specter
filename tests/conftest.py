"""Shared pytest fixtures and session-level initialization."""
import pytest


@pytest.fixture(scope="session", autouse=True)
def initialize_eth_hash():
    """Pre-initialize eth_hash backend before CliRunner tests.

    eth_hash lazily loads its backend (pycryptodome) on first use. On Python 3.13
    macOS, the initialization calls platform.architecture() which returns a str
    instead of bytes, causing an AttributeError inside the typer CliRunner's
    isolated environment. Pre-initializing outside CliRunner caches the backend
    for all subsequent calls.
    """
    import eth_utils
    eth_utils.to_checksum_address("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")
