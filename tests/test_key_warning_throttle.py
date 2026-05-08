"""Tests for the once-per-process ephemeral-key warning throttle."""

from __future__ import annotations

import logging

import pytest

from ai_audit import AuditConfig, get_verify_key_hex, init_audit_config, reset_signing_key


@pytest.fixture(autouse=True)
def _reset_keys() -> None:
    reset_signing_key()


def test_ephemeral_warning_emitted_exactly_once(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="ai_audit.keys")

    # Ephemeral path triggers the warning on first access
    init_audit_config(AuditConfig())
    get_verify_key_hex()

    # Second init+access should NOT emit the warning again
    init_audit_config(AuditConfig())
    get_verify_key_hex()

    # Third
    init_audit_config(AuditConfig())
    get_verify_key_hex()

    matching = [r for r in caplog.records if "ephemeral" in r.getMessage().lower()]
    assert len(matching) == 1, f"Expected exactly 1 ephemeral warning, got {len(matching)}"


def test_reset_signing_key_re_arms_the_warning(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="ai_audit.keys")

    init_audit_config(AuditConfig())
    get_verify_key_hex()

    # Explicit reset must rearm the guard so tests that exercise the
    # ephemeral path can re-observe the warning.
    reset_signing_key()
    init_audit_config(AuditConfig())
    get_verify_key_hex()

    matching = [r for r in caplog.records if "ephemeral" in r.getMessage().lower()]
    assert len(matching) == 2


def test_no_warning_when_key_is_configured(caplog: pytest.LogCaptureFixture) -> None:
    import nacl.signing

    caplog.set_level(logging.WARNING, logger="ai_audit.keys")

    seed_hex = nacl.signing.SigningKey.generate().encode().hex()
    init_audit_config(AuditConfig(signing_key_hex=seed_hex))
    get_verify_key_hex()

    matching = [r for r in caplog.records if "ephemeral" in r.getMessage().lower()]
    assert matching == []
