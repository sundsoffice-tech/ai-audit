"""Tests for the python -m ai_audit CLI."""

from __future__ import annotations

import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ai_audit", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_help_no_args() -> None:
    result = _run()
    assert result.returncode == 2
    assert "Commands:" in result.stdout


def test_help_flag() -> None:
    result = _run("--help")
    assert result.returncode == 0
    assert "gen-key" in result.stdout
    assert "verify" in result.stdout


def test_gen_key_default_output() -> None:
    result = _run("gen-key")
    assert result.returncode == 0
    assert "AI_AUDIT_SIGNING_KEY=" in result.stdout
    assert "AI_AUDIT_VERIFY_KEY=" in result.stdout
    seed_line = next(line for line in result.stdout.splitlines() if line.startswith("AI_AUDIT_SIGNING_KEY="))
    seed = seed_line.split("=", 1)[1]
    assert len(seed) == 64
    int(seed, 16)


def test_gen_key_quiet_returns_only_seed() -> None:
    result = _run("gen-key", "--quiet")
    assert result.returncode == 0
    seed = result.stdout.strip()
    assert len(seed) == 64
    int(seed, 16)


def test_gen_key_two_calls_produce_different_seeds() -> None:
    a = _run("gen-key", "-q").stdout.strip()
    b = _run("gen-key", "-q").stdout.strip()
    assert a != b


def test_info_includes_version() -> None:
    result = _run("info")
    assert result.returncode == 0
    assert "ai-audit-trail" in result.stdout
    assert "PyNaCl" in result.stdout


def test_unknown_command_returns_error() -> None:
    result = _run("nope")
    assert result.returncode == 2
    assert "Unknown command" in result.stdout
