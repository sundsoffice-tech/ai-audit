"""Tests for Crypto-Shredding (GDPR Art. 17)."""

import hashlib

import pytest

from ai_audit.shredding import (
    AESGCMDEKStore,
    decrypt_field,
    encrypt_field,
    shred_tenant,
)


def test_encrypt_decrypt_roundtrip() -> None:
    """Encrypt then decrypt should return original plaintext."""
    store = AESGCMDEKStore()
    store.create_dek("tenant-acme")

    field = encrypt_field("Hello, World!", store, "tenant-acme")
    assert field.ciphertext != b""
    assert field.nonce != b""
    assert field.dek_id == "tenant-acme"
    assert not field.shredded

    plaintext = decrypt_field(field, store)
    assert plaintext == "Hello, World!"


def test_different_encryptions_produce_different_ciphertext() -> None:
    """Same plaintext encrypted twice should produce different ciphertext (random nonce)."""
    store = AESGCMDEKStore()
    store.create_dek("t1")

    f1 = encrypt_field("same text", store, "t1")
    f2 = encrypt_field("same text", store, "t1")
    assert f1.ciphertext != f2.ciphertext  # Different nonces


def test_shred_makes_decrypt_fail() -> None:
    """After shredding, decryption must fail permanently."""
    store = AESGCMDEKStore()
    store.create_dek("tenant-acme")

    field = encrypt_field("sensitive PII data", store, "tenant-acme")
    assert decrypt_field(field, store) == "sensitive PII data"

    # Shred
    assert shred_tenant("tenant-acme", store)

    # Decryption must fail
    with pytest.raises(KeyError, match="not found or has been destroyed"):
        decrypt_field(field, store)


def test_shred_nonexistent_dek() -> None:
    """Shredding a non-existent DEK should return False."""
    store = AESGCMDEKStore()
    assert not shred_tenant("nonexistent", store)


def test_ciphertext_hash_survives_shredding() -> None:
    """The hash of the ciphertext remains valid after DEK destruction.

    This is the key property for GDPR-compliant audit trails:
    the hash-chain hashes ciphertext (not plaintext), so the chain
    remains mathematically intact even after crypto-shredding.
    """
    store = AESGCMDEKStore()
    store.create_dek("t1")

    field = encrypt_field("PII data here", store, "t1")

    # Hash the ciphertext (this is what goes into the receipt chain)
    chain_hash = hashlib.sha256(field.ciphertext).hexdigest()

    # Shred the DEK
    shred_tenant("t1", store)

    # The ciphertext is still there — its hash is unchanged
    assert hashlib.sha256(field.ciphertext).hexdigest() == chain_hash


def test_active_keys_count() -> None:
    """AESGCMDEKStore should track active key count."""
    store = AESGCMDEKStore()
    assert store.active_keys == 0

    store.create_dek("t1")
    store.create_dek("t2")
    assert store.active_keys == 2

    store.destroy_dek("t1")
    assert store.active_keys == 1


def test_encrypt_with_destroyed_key_fails() -> None:
    """Encrypting with a destroyed DEK must raise KeyError."""
    store = AESGCMDEKStore()
    store.create_dek("t1")
    store.destroy_dek("t1")

    with pytest.raises(KeyError):
        encrypt_field("test", store, "t1")


def test_encrypted_field_shredded_flag() -> None:
    """Manually setting shredded=True should prevent decryption."""
    store = AESGCMDEKStore()
    store.create_dek("t1")

    field = encrypt_field("test", store, "t1")
    field.shredded = True

    with pytest.raises(KeyError, match="shredded"):
        decrypt_field(field, store)
