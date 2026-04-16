"""Tests for online/streaming SPRT monitor."""

from ai_audit.sprt import SPRTMonitor


def test_sprt_converges_to_certified() -> None:
    """30 consecutive accepts should converge to CERTIFIED (matching batch SPRT)."""
    monitor = SPRTMonitor(tenant_id="acme")
    for _ in range(30):
        state = monitor.update(is_reject=False)
    assert state.status == "CERTIFIED"
    assert state.n == 30
    assert state.rejects == 0
    assert state.confidence == 1.0


def test_sprt_flags_high_reject_rate() -> None:
    """Mostly rejects should converge to FLAGGED."""
    monitor = SPRTMonitor(tenant_id="acme")
    for i in range(30):
        monitor.update(is_reject=(i % 2 == 0))  # 50% reject rate
    assert monitor.state.status == "FLAGGED"


def test_sprt_monitoring_before_min_samples() -> None:
    """Before min_samples, status must be MONITORING regardless of data."""
    monitor = SPRTMonitor(tenant_id="acme", min_samples=10)
    for _ in range(9):
        state = monitor.update(is_reject=False)
    assert state.status == "MONITORING"
    assert state.n == 9


def test_sprt_serialisation_roundtrip() -> None:
    """SPRTMonitor must survive serialisation via state/from_state."""
    monitor = SPRTMonitor(tenant_id="acme")
    for _ in range(20):
        monitor.update(is_reject=False)

    state = monitor.state
    restored = SPRTMonitor.from_state(state)

    assert restored.state.llr == state.llr
    assert restored.state.n == state.n
    assert restored.state.rejects == state.rejects
    assert restored.state.status == state.status


def test_sprt_from_state_continues_correctly() -> None:
    """Restored monitor must continue converging from the saved point."""
    monitor = SPRTMonitor(tenant_id="acme")
    for _ in range(15):
        monitor.update(is_reject=False)

    state = monitor.state
    restored = SPRTMonitor.from_state(state)

    # Continue with more accepts
    for _ in range(15):
        restored.update(is_reject=False)

    assert restored.state.status == "CERTIFIED"
    assert restored.state.n == 30


def test_sprt_reset() -> None:
    """Reset should return monitor to initial state."""
    monitor = SPRTMonitor(tenant_id="acme")
    for _ in range(20):
        monitor.update(is_reject=False)
    assert monitor.state.n == 20

    monitor.reset()
    assert monitor.state.n == 0
    assert monitor.state.llr == 0.0
    assert monitor.state.status == "MONITORING"


def test_sprt_matches_batch_result() -> None:
    """Online SPRT must converge to the same result as batch SPRT in dashboard.py."""
    from ai_audit import (
        AuditConfig,
        ReceiptAction,
        ReceiptCollector,
        ReceiptStore,
        build_compliance_summary,
        init_audit_config,
        reset_signing_key,
    )

    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))

    store = ReceiptStore()
    monitor = SPRTMonitor(tenant_id="test")

    for _i in range(30):
        c = ReceiptCollector(tenant_id="test")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()
        monitor.update(is_reject=False)

    batch_summary = build_compliance_summary(store.get_by_tenant("test"), chain_intact=True)
    online_state = monitor.state

    assert batch_summary.sprt_status == online_state.status
    assert batch_summary.sprt_status == "CERTIFIED"
