"""Tests for Merkle-Tree Batch Sealing."""

import nacl.signing

from ai_audit.batch import (
    BatchSeal,
    MerkleBatcher,
    build_inclusion_proof,
    merkle_root,
    verify_inclusion,
)


def _make_key() -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey.generate()


def test_merkle_root_empty() -> None:
    """Empty leaf list should return 32 zero bytes."""
    root = merkle_root([])
    assert root == b"\x00" * 32


def test_merkle_root_single_leaf() -> None:
    """Single leaf should produce a deterministic root."""
    root = merkle_root([b"hello"])
    assert len(root) == 32
    assert root == merkle_root([b"hello"])  # deterministic


def test_merkle_root_deterministic() -> None:
    """Same leaves in same order must produce same root."""
    leaves = [b"a", b"b", b"c", b"d"]
    assert merkle_root(leaves) == merkle_root(leaves)


def test_merkle_root_order_sensitive() -> None:
    """Different order must produce different root."""
    assert merkle_root([b"a", b"b"]) != merkle_root([b"b", b"a"])


def test_merkle_root_odd_leaves() -> None:
    """Odd number of leaves should still produce a valid root."""
    root = merkle_root([b"a", b"b", b"c"])
    assert len(root) == 32


def test_inclusion_proof_valid() -> None:
    """Inclusion proof for a known leaf must verify against the root."""
    leaves = [b"alpha", b"beta", b"gamma", b"delta"]
    root = merkle_root(leaves)

    for idx in range(len(leaves)):
        proof = build_inclusion_proof(leaves, idx)
        assert verify_inclusion(leaves[idx], proof, root), f"Failed for index {idx}"


def test_inclusion_proof_invalid_leaf() -> None:
    """Proof must fail for a leaf that was not in the tree."""
    leaves = [b"alpha", b"beta", b"gamma", b"delta"]
    root = merkle_root(leaves)
    proof = build_inclusion_proof(leaves, 0)
    assert not verify_inclusion(b"FAKE", proof, root)


def test_batch_seal_sign_verify() -> None:
    """BatchSeal must sign and verify correctly."""
    key = _make_key()
    seal = BatchSeal(
        batch_id="test-batch",
        tenant_id="acme",
        merkle_root="deadbeef" * 8,
        leaf_count=4,
        prev_batch_root="",
        timestamp="2026-04-16T00:00:00Z",
        receipt_ids=["r1", "r2", "r3", "r4"],
    )
    seal.seal(key)
    assert seal.signature != ""

    verify_key = key.verify_key
    assert seal.verify(verify_key)


def test_batch_seal_tamper_detected() -> None:
    """Modifying a sealed batch must fail verification."""
    key = _make_key()
    seal = BatchSeal(
        batch_id="test-batch",
        tenant_id="acme",
        merkle_root="deadbeef" * 8,
        leaf_count=4,
    )
    seal.seal(key)

    # Tamper
    seal.leaf_count = 999
    assert not seal.verify(key.verify_key)


def test_batcher_auto_flush() -> None:
    """Batcher should auto-flush when max_batch_size is reached."""
    key = _make_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=3)

    result1 = batcher.add("r1", b"payload1")
    assert result1 is None
    result2 = batcher.add("r2", b"payload2")
    assert result2 is None
    result3 = batcher.add("r3", b"payload3")
    assert result3 is not None  # auto-flushed

    assert result3.leaf_count == 3
    assert result3.tenant_id == "acme"
    assert batcher.pending_count == 0


def test_batcher_manual_flush() -> None:
    """Manual flush should seal whatever is in the buffer."""
    key = _make_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=100)

    batcher.add("r1", b"payload1")
    batcher.add("r2", b"payload2")
    seal = batcher.flush()

    assert seal is not None
    assert seal.leaf_count == 2
    assert seal.signature != ""


def test_batcher_empty_flush() -> None:
    """Flushing an empty buffer should return None."""
    key = _make_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key)
    assert batcher.flush() is None


def test_batcher_chain_of_roots() -> None:
    """Multiple batches should form a valid Chain-of-Roots."""
    key = _make_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=2)

    # Create 3 batches of 2 receipts each
    for i in range(6):
        batcher.add(f"r{i}", f"payload{i}".encode())

    assert len(batcher.seals) == 3

    # Verify chain linkage
    assert batcher.seals[0].prev_batch_root == ""  # first batch
    assert batcher.seals[1].prev_batch_root == batcher.seals[0].merkle_root
    assert batcher.seals[2].prev_batch_root == batcher.seals[1].merkle_root


def test_batcher_chain_of_roots_verification() -> None:
    """verify_chain_of_roots should pass for untampered chain."""
    key = _make_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=2)

    for i in range(6):
        batcher.add(f"r{i}", f"payload{i}".encode())

    assert batcher.verify_chain_of_roots(key.verify_key)


def test_batcher_chain_tamper_detected() -> None:
    """Tampering with a seal in the chain must be detected."""
    key = _make_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=2)

    for i in range(4):
        batcher.add(f"r{i}", f"payload{i}".encode())

    assert len(batcher.seals) == 2
    # Tamper with second seal
    batcher._seals[1].leaf_count = 999
    assert not batcher.verify_chain_of_roots(key.verify_key)
