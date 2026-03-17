"""Tests for specter CLI entry point (Story 1.1)."""
import subprocess

from typer.testing import CliRunner

from specter.cli import app

runner = CliRunner()


def test_help_lists_scan_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_help_lists_check_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "check" in result.output


def test_help_lists_version_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.output


def test_entry_point_subprocess_help():
    """Validates pyproject.toml entry point wiring via real subprocess invocation (AC1)."""
    result = subprocess.run(
        ["uv", "run", "specter", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "check" in result.stdout
    assert "version" in result.stdout


def test_scan_stub_accepts_target():
    result = runner.invoke(app, ["scan", "0xdeadbeef"])
    assert result.exit_code == 0


def test_check_stub_runs():
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0


def test_version_stub_runs():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
