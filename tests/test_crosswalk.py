"""Tests for ISO 42001 / NIST AI RMF Compliance Crosswalk."""

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.crosswalk import ControlStatus, build_crosswalk, nist_function_map


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_rich_chain(count: int = 10) -> list:
    """Create receipts with all fields populated for maximum coverage."""
    store = ReceiptStore()
    for i in range(count):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme", session_id=f"s{i}")
        c.set_input(f"query {i}")
        c.add_check("safety", score=0.05, threshold=0.8, fired=False)
        c.add_check("routing", score=0.9, threshold=0.5, fired=True)
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c._receipt.model_id = "claude-3-opus"
        c._receipt.config_digest = "abc123"
        c._receipt.nist_tags = ["GOVERN-1.1", "MEASURE-2.3"]
        c.emit(store)
        c.cleanup()
    return store.get_by_tenant("acme")


def test_crosswalk_returns_all_controls() -> None:
    """build_crosswalk should return entries for all ISO + NIST controls."""
    receipts = _make_rich_chain()
    entries = build_crosswalk(receipts, chain_intact=True)
    assert len(entries) == 9  # 5 ISO + 4 NIST

    frameworks = {e.framework for e in entries}
    assert "ISO 42001" in frameworks
    assert "NIST AI RMF" in frameworks


def test_iso_a628_pass_with_chain() -> None:
    """A.6.2.8 (Logging) should PASS when chain is intact and receipts are signed."""
    receipts = _make_rich_chain()
    entries = build_crosswalk(receipts, chain_intact=True)
    a628 = next(e for e in entries if e.control_id == "A.6.2.8")
    assert a628.status == ControlStatus.PASS
    assert len(a628.evidence_pointers) > 0


def test_iso_a628_degrades_without_chain() -> None:
    """A.6.2.8 should not PASS when chain is broken."""
    receipts = _make_rich_chain()
    entries = build_crosswalk(receipts, chain_intact=False)
    a628 = next(e for e in entries if e.control_id == "A.6.2.8")
    assert a628.status != ControlStatus.PASS


def test_iso_a75_provenance() -> None:
    """A.7.5 (Data provenance) should pass with input/output hashes."""
    receipts = _make_rich_chain()
    entries = build_crosswalk(receipts)
    a75 = next(e for e in entries if e.control_id == "A.7.5")
    assert a75.status == ControlStatus.PASS
    assert a75.coverage >= 0.9


def test_nist_function_map() -> None:
    """nist_function_map should return all 4 NIST functions."""
    receipts = _make_rich_chain()
    nist = nist_function_map(receipts)
    assert set(nist.keys()) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}
    assert all(isinstance(v.status, ControlStatus) for v in nist.values())


def test_nist_measure_with_scores() -> None:
    """MEASURE should pass when receipts include check scores."""
    receipts = _make_rich_chain()
    nist = nist_function_map(receipts)
    assert nist["MEASURE"].status == ControlStatus.PASS
    assert nist["MEASURE"].coverage >= 0.5


def test_empty_receipts_crosswalk() -> None:
    """Empty receipts should produce FAIL/N/A statuses."""
    entries = build_crosswalk([], chain_intact=True)
    assert len(entries) == 9
    for e in entries:
        assert e.status in (ControlStatus.FAIL, ControlStatus.NOT_APPLICABLE, ControlStatus.PARTIAL)


def test_evidence_pointers_populated() -> None:
    """All crosswalk entries with data should have evidence_pointers."""
    receipts = _make_rich_chain()
    entries = build_crosswalk(receipts)
    for e in entries:
        if e.status == ControlStatus.PASS:
            assert len(e.evidence_pointers) > 0, f"{e.control_id} missing evidence_pointers"
