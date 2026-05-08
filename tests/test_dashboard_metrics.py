"""Tests for ComplianceSummary computed properties + auto verify-key fetch."""

from __future__ import annotations

import nacl.signing
import pytest

from ai_audit import (
    AuditConfig,
    ComplianceSummary,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    build_compliance_summary,
    init_audit_config,
    reset_signing_key,
)


@pytest.fixture(autouse=True)
def _reset_keys() -> None:
    reset_signing_key()


def _make_receipts(actions: list[ReceiptAction], tenant: str = "test") -> list:
    store = ReceiptStore()
    for i, a in enumerate(actions):
        c = ReceiptCollector(trace_id=f"t-{i}", tenant_id=tenant)
        c.set_input(f"in-{i}")
        c.set_output(f"out-{i}")
        c.set_action(a)
        c.emit(store)
        c.cleanup()
    return store.get_by_tenant(tenant)


# ---------------------------------------------------------------------------
# Computed properties
# ---------------------------------------------------------------------------


def test_action_distribution_sums_to_one() -> None:
    summary = build_compliance_summary(
        _make_receipts([ReceiptAction.ALLOW, ReceiptAction.ALLOW, ReceiptAction.REJECT])
    )
    dist = summary.action_distribution
    assert sum(dist.values()) == pytest.approx(1.0)
    assert dist["allow"] == pytest.approx(2 / 3)
    assert dist["reject"] == pytest.approx(1 / 3)


def test_action_distribution_empty_when_no_receipts() -> None:
    summary = ComplianceSummary()
    assert summary.action_distribution == {}


def test_reject_rate_counts_reject_and_escalate() -> None:
    summary = build_compliance_summary(
        _make_receipts([
            ReceiptAction.ALLOW,
            ReceiptAction.REJECT,
            ReceiptAction.ESCALATE,
            ReceiptAction.ALLOW,
        ])
    )
    # 2 of 4 are reject-class
    assert summary.reject_rate == pytest.approx(0.5)
    # ALLOW is 2 of 4
    assert summary.allow_rate == pytest.approx(0.5)


def test_reject_and_allow_rates_zero_for_empty_summary() -> None:
    summary = ComplianceSummary()
    assert summary.reject_rate == 0.0
    assert summary.allow_rate == 0.0


def test_is_certified_and_is_flagged_match_status() -> None:
    s = ComplianceSummary(sprt_status="CERTIFIED")
    assert s.is_certified and not s.is_flagged

    s = ComplianceSummary(sprt_status="FLAGGED")
    assert s.is_flagged and not s.is_certified

    s = ComplianceSummary(sprt_status="MONITORING")
    assert not s.is_certified and not s.is_flagged


# ---------------------------------------------------------------------------
# verification_key_id auto-fetch
# ---------------------------------------------------------------------------


def test_verification_key_id_autofetched_when_not_passed() -> None:
    seed_hex = nacl.signing.SigningKey.generate().encode().hex()
    init_audit_config(AuditConfig(signing_key_hex=seed_hex))

    summary = build_compliance_summary(_make_receipts([ReceiptAction.ALLOW]))
    # Auto-populated from active KeyProvider (16-char prefix of public key)
    assert summary.verification_key_id != ""
    assert len(summary.verification_key_id) == 16


def test_verification_key_id_explicit_argument_wins() -> None:
    seed_hex = nacl.signing.SigningKey.generate().encode().hex()
    init_audit_config(AuditConfig(signing_key_hex=seed_hex))

    summary = build_compliance_summary(
        _make_receipts([ReceiptAction.ALLOW]),
        verify_key_hex="cafebabedeadbeef" * 4,
    )
    assert summary.verification_key_id == "cafebabedeadbeef"


def test_verification_key_id_falls_back_silently_when_provider_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contract: ``build_compliance_summary`` must never raise, even when
    the active KeyProvider raises on access (e.g. KMS outage, expired
    credentials, production mode without a configured key).
    """
    seed_hex = nacl.signing.SigningKey.generate().encode().hex()
    init_audit_config(AuditConfig(signing_key_hex=seed_hex))

    def _explode() -> str:
        raise RuntimeError("simulated KMS outage")

    monkeypatch.setattr("ai_audit.keys.get_verify_key_hex", _explode)
    monkeypatch.setattr("ai_audit.dashboard.get_verify_key_hex", _explode, raising=False)

    summary = build_compliance_summary(_make_receipts([ReceiptAction.ALLOW]))
    assert summary.verification_key_id == ""
    assert summary.total_receipts == 1


def test_verification_key_id_empty_with_no_provider_and_no_receipts() -> None:
    """Pure offline path: empty receipt list, no provider initialised."""
    summary = build_compliance_summary([])
    assert summary.total_receipts == 0
    # No provider was registered before this call, no receipts to seed one
    assert summary.verification_key_id == ""
