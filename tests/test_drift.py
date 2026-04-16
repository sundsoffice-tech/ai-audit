"""Tests for Drift Detection (Jensen-Shannon Divergence)."""

from ai_audit.drift import DriftMonitor


def test_stable_distribution() -> None:
    """Identical baseline and current should show STABLE."""
    monitor = DriftMonitor(window_size=50)

    # Fill baseline: 80% allow, 20% reject
    for _ in range(40):
        monitor.update("allow")
    for _ in range(10):
        monitor.update("reject")

    # Continue with same distribution
    for _ in range(40):
        monitor.update("allow")
    for _ in range(10):
        monitor.update("reject")

    state = monitor.state
    assert state.status == "STABLE"
    assert state.drift_score < 0.05


def test_drifting_distribution() -> None:
    """Moderate shift should trigger DRIFTING."""
    monitor = DriftMonitor(window_size=50)

    # Baseline: 80% allow, 20% reject
    for _ in range(40):
        monitor.update("allow")
    for _ in range(10):
        monitor.update("reject")

    # Shift: 50% allow, 50% reject
    for _ in range(25):
        monitor.update("allow")
    for _ in range(25):
        monitor.update("reject")

    state = monitor.state
    assert state.status in ("DRIFTING", "CRITICAL_DRIFT")
    assert state.drift_score > 0.05


def test_critical_drift() -> None:
    """Major shift should trigger CRITICAL_DRIFT."""
    monitor = DriftMonitor(window_size=50)

    # Baseline: 100% allow
    for _ in range(50):
        monitor.update("allow")

    # Shift: 100% reject
    for _ in range(50):
        monitor.update("reject")

    state = monitor.state
    assert state.status == "CRITICAL_DRIFT"
    assert state.drift_score > 0.15


def test_monitoring_before_baseline() -> None:
    """Before baseline is frozen, status should be STABLE with score 0."""
    monitor = DriftMonitor(window_size=100)
    for _ in range(50):
        state = monitor.update("allow")
    assert state.status == "STABLE"
    assert state.drift_score == 0.0


def test_reset_baseline() -> None:
    """After reset_baseline, the new distribution becomes the reference."""
    monitor = DriftMonitor(window_size=50)

    # Original baseline: all allow
    for _ in range(50):
        monitor.update("allow")

    # Shift to mostly reject
    for _ in range(50):
        monitor.update("reject")
    assert monitor.state.status in ("DRIFTING", "CRITICAL_DRIFT")

    # Reset baseline to current (mostly reject)
    monitor.reset_baseline()

    # Continue with reject — now stable relative to new baseline
    for _ in range(50):
        monitor.update("reject")
    assert monitor.state.status == "STABLE"


def test_jsd_symmetric() -> None:
    """JSD should be symmetric: JSD(P,Q) == JSD(Q,P)."""
    from ai_audit.drift import _jensen_shannon_divergence

    p = {"allow": 0.8, "reject": 0.2}
    q = {"allow": 0.3, "reject": 0.7}

    assert abs(_jensen_shannon_divergence(p, q) - _jensen_shannon_divergence(q, p)) < 1e-10


def test_jsd_identical_is_zero() -> None:
    """JSD of identical distributions should be 0."""
    from ai_audit.drift import _jensen_shannon_divergence

    p = {"allow": 0.5, "reject": 0.5}
    assert _jensen_shannon_divergence(p, p) < 1e-10


def test_new_action_types_detected() -> None:
    """Introduction of new action types not in baseline should trigger drift."""
    monitor = DriftMonitor(window_size=50)

    # Baseline: only allow
    for _ in range(50):
        monitor.update("allow")

    # New action type appears
    for _ in range(25):
        monitor.update("allow")
    for _ in range(25):
        monitor.update("escalate")

    state = monitor.state
    assert state.drift_score > 0.05
