"""Tests for Agent Behavioral Contracts with (p,δ,k)-Satisfaction."""

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.contracts import BehavioralContract, Constraint, ContractMonitor


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_receipt(action: ReceiptAction = ReceiptAction.ALLOW, tenant: str = "acme"):
    store = ReceiptStore()
    c = ReceiptCollector(trace_id="t1", tenant_id=tenant)
    c.set_input("test query")
    c.add_check("safety", score=0.05, threshold=0.8, fired=False)
    c.set_output("test answer")
    c.set_action(action)
    rid = c.emit(store)
    c.cleanup()
    return store.get(rid)


def test_all_compliant() -> None:
    """All receipts satisfying all constraints should yield p=1.0, COMPLIANT."""
    contract = BehavioralContract(
        contract_id="safety-v1",
        constraints=[
            Constraint(name="must_allow", kind="hard", field="action", operator="==", value="allow"),
        ],
    )
    monitor = ContractMonitor(contract)
    for _ in range(20):
        r = _make_receipt(ReceiptAction.ALLOW)
        assert r is not None
        state = monitor.evaluate(r)

    assert state.p == 1.0
    assert state.hard_violations == 0
    assert state.status == "COMPLIANT"
    assert state.reliability_index == 1.0


def test_hard_violation_detected() -> None:
    """A hard constraint violation should reduce p and mark VIOLATED."""
    contract = BehavioralContract(
        contract_id="no-reject",
        constraints=[
            Constraint(name="no_reject", kind="hard", field="action", operator="!=", value="reject"),
        ],
    )
    monitor = ContractMonitor(contract)

    # 9 allows, 1 reject
    for _ in range(9):
        r = _make_receipt(ReceiptAction.ALLOW)
        assert r is not None
        monitor.evaluate(r)

    r = _make_receipt(ReceiptAction.REJECT)
    assert r is not None
    state = monitor.evaluate(r)

    assert state.hard_violations == 1
    assert state.p == 0.9
    assert state.reliability_index < 1.0


def test_soft_constraint_deviation() -> None:
    """Soft constraint violation should track delta and mark DEGRADED."""
    contract = BehavioralContract(
        contract_id="quality",
        constraints=[
            Constraint(
                name="safety_score_low", kind="soft",
                field="checks.safety.score", operator="<=", value=0.1, delta=0.5,
            ),
        ],
    )
    monitor = ContractMonitor(contract)

    r = _make_receipt()
    assert r is not None
    state = monitor.evaluate(r)

    # Safety score is 0.05 which satisfies <= 0.1
    assert state.status in ("COMPLIANT", "DEGRADED")


def test_recovery_after_violation() -> None:
    """Agent should show recovery (k steps) after returning to compliance."""
    contract = BehavioralContract(
        contract_id="recovery-test",
        constraints=[
            Constraint(name="must_allow", kind="hard", field="action", operator="==", value="allow"),
        ],
    )
    monitor = ContractMonitor(contract)

    # Violate once
    r = _make_receipt(ReceiptAction.REJECT)
    assert r is not None
    monitor.evaluate(r)

    # Recover with 5 clean steps
    for _ in range(5):
        r = _make_receipt(ReceiptAction.ALLOW)
        assert r is not None
        state = monitor.evaluate(r)

    assert state.recovered
    assert state.k > 0


def test_reliability_index_range() -> None:
    """Θ should always be in [0, 1]."""
    contract = BehavioralContract(
        contract_id="theta-test",
        constraints=[
            Constraint(name="c1", kind="hard", field="action", operator="==", value="allow"),
        ],
    )
    monitor = ContractMonitor(contract)

    for action in [ReceiptAction.ALLOW, ReceiptAction.REJECT, ReceiptAction.ALLOW] * 5:
        r = _make_receipt(action)
        assert r is not None
        state = monitor.evaluate(r)
        assert 0.0 <= state.reliability_index <= 1.0


def test_multiple_constraints() -> None:
    """Multiple constraints should all be evaluated."""
    contract = BehavioralContract(
        contract_id="multi",
        constraints=[
            Constraint(name="must_allow", kind="hard", field="action", operator="==", value="allow"),
            Constraint(name="right_tenant", kind="hard", field="tenant_id", operator="==", value="acme"),
        ],
    )
    monitor = ContractMonitor(contract)

    r = _make_receipt(ReceiptAction.ALLOW, tenant="acme")
    assert r is not None
    state = monitor.evaluate(r)
    assert state.hard_violations == 0

    r = _make_receipt(ReceiptAction.ALLOW, tenant="evil")
    assert r is not None
    state = monitor.evaluate(r)
    assert state.hard_violations == 1


def test_reset() -> None:
    """Reset should clear all state."""
    contract = BehavioralContract(contract_id="reset-test", constraints=[])
    monitor = ContractMonitor(contract)
    r = _make_receipt()
    assert r is not None
    monitor.evaluate(r)
    assert monitor.state.total_evaluations == 1
    monitor.reset()
    assert monitor.state.total_evaluations == 0
