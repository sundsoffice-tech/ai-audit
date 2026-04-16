"""Tests for Chain Epochs and Rollover."""

import nacl.signing

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.epochs import EpochManager, EpochSeal


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_receipts(count: int = 5, tenant: str = "acme") -> list:
    store = ReceiptStore()
    for i in range(count):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id=tenant)
        c.set_input(f"query {i}")
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()
    return store.get_by_tenant(tenant)


def test_epoch_seal_sign_verify() -> None:
    """EpochSeal should sign and verify correctly."""
    key = nacl.signing.SigningKey.generate()
    seal = EpochSeal(epoch_id="e1", tenant_id="acme", receipt_count=100)
    seal.seal(key)
    assert seal.signature != ""
    assert seal.verify(key.verify_key)


def test_epoch_seal_tamper_detected() -> None:
    """Modifying a sealed epoch must fail verification."""
    key = nacl.signing.SigningKey.generate()
    seal = EpochSeal(epoch_id="e1", tenant_id="acme", receipt_count=100)
    seal.seal(key)
    seal.receipt_count = 999
    assert not seal.verify(key.verify_key)


def test_epoch_manager_auto_seal() -> None:
    """EpochManager should auto-seal at max_epoch_size."""
    key = nacl.signing.SigningKey.generate()
    mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=3)

    receipts = _make_receipts(5)
    results = []
    for r in receipts:
        result = mgr.add_receipt(r)
        if result is not None:
            results.append(result)

    assert len(results) == 1  # auto-sealed after 3rd receipt
    assert results[0].receipt_count == 3
    assert mgr.current_epoch_size == 2  # 2 remaining


def test_epoch_manager_explicit_seal() -> None:
    """Explicit seal_epoch should seal whatever is buffered."""
    key = nacl.signing.SigningKey.generate()
    mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=1000)

    receipts = _make_receipts(5)
    for r in receipts:
        mgr.add_receipt(r)

    seal = mgr.seal_epoch()
    assert seal is not None
    assert seal.receipt_count == 5
    assert mgr.current_epoch_size == 0


def test_epoch_manager_empty_seal() -> None:
    """Sealing an empty epoch should return None."""
    key = nacl.signing.SigningKey.generate()
    mgr = EpochManager(tenant_id="acme", private_key=key)
    assert mgr.seal_epoch() is None


def test_epoch_chain_of_seals() -> None:
    """Multiple epochs should form a valid chain."""
    key = nacl.signing.SigningKey.generate()
    mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=2)

    receipts = _make_receipts(6)
    for r in receipts:
        mgr.add_receipt(r)

    assert len(mgr.seals) == 3
    assert mgr.seals[0].prev_epoch_seal_hash == ""
    assert mgr.seals[1].prev_epoch_seal_hash != ""
    assert mgr.seals[2].prev_epoch_seal_hash != ""


def test_epoch_chain_verification() -> None:
    """verify_epoch_chain should pass for untampered chain."""
    key = nacl.signing.SigningKey.generate()
    mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=2)

    receipts = _make_receipts(6)
    for r in receipts:
        mgr.add_receipt(r)

    assert mgr.verify_epoch_chain(key.verify_key)


def test_epoch_chain_tamper_detected() -> None:
    """Tampering with an epoch seal must be detected."""
    key = nacl.signing.SigningKey.generate()
    mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=2)

    receipts = _make_receipts(4)
    for r in receipts:
        mgr.add_receipt(r)

    mgr._seals[1].receipt_count = 999
    assert not mgr.verify_epoch_chain(key.verify_key)
