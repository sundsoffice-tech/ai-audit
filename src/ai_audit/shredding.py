"""
ai_audit.shredding — Crypto-Shredding for GDPR Art. 17 (Right to Erasure).

Resolves the fundamental conflict between append-only hash-chains and
the right to deletion by encrypting PII fields with per-tenant Data
Encryption Keys (DEKs). Destroying the DEK renders the ciphertext
permanently unreadable while keeping the hash-chain mathematically intact
(because the chain hashes the *ciphertext*, not the plaintext).

Flow::

    raw text → PII redact → DEK encrypt → hash → seal

Key components:
- ``EncryptedField``: ciphertext + nonce + dek_id + shredded flag
- ``DEKStore`` ABC: create/get/destroy keys (implement for your KMS)
- ``AESGCMDEKStore``: Secure-by-default local implementation for dev/test

NB 409cad95 (Enterprise) validated — 2026-04-16.
NB ee9616a5 (CHEF) correction: DEKStore must dock onto KeyProvider interface.
"""

from __future__ import annotations

import abc
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedField:
    """A field encrypted with AES-256-GCM for crypto-shredding.

    After shredding (DEK destruction), ``shredded=True`` and the
    ciphertext is permanently unreadable. The hash-chain remains intact
    because it hashed the ciphertext, not the plaintext.
    """

    ciphertext: bytes = b""
    nonce: bytes = b""         # 12-byte GCM nonce
    dek_id: str = ""           # References the DEK in the DEKStore
    shredded: bool = False     # True after DEK destruction


class DEKStore(abc.ABC):
    """Abstract base class for Data Encryption Key management.

    Implement this for your KMS (AWS KMS, GCP KMS, HashiCorp Vault, etc.).
    The ``AESGCMDEKStore`` provides a local in-memory implementation
    suitable for development and testing.
    """

    @abc.abstractmethod
    def create_dek(self, dek_id: str) -> bytes:
        """Create and store a new 256-bit DEK. Returns the raw key bytes."""

    @abc.abstractmethod
    def get_dek(self, dek_id: str) -> bytes | None:
        """Retrieve a DEK by ID. Returns None if destroyed or not found."""

    @abc.abstractmethod
    def destroy_dek(self, dek_id: str) -> bool:
        """Irreversibly destroy a DEK. Returns True if found and destroyed."""


class AESGCMDEKStore(DEKStore):
    """In-memory DEK store using AES-256-GCM.

    Suitable for development, testing, and single-process deployments.
    For production, implement ``DEKStore`` with your KMS.

    Keys are stored in a plain dict — do NOT use in multi-process production
    without an external backing store.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def create_dek(self, dek_id: str) -> bytes:
        """Generate a random 256-bit AES key."""
        key = secrets.token_bytes(32)  # AES-256
        self._keys[dek_id] = key
        return key

    def get_dek(self, dek_id: str) -> bytes | None:
        return self._keys.get(dek_id)

    def destroy_dek(self, dek_id: str) -> bool:
        """Securely destroy the DEK by overwriting with zeros before deletion."""
        if dek_id not in self._keys:
            return False
        # Overwrite in memory (best-effort for Python)
        key = self._keys[dek_id]
        self._keys[dek_id] = b"\x00" * len(key)
        del self._keys[dek_id]
        return True

    @property
    def active_keys(self) -> int:
        """Number of active (non-destroyed) DEKs."""
        return len(self._keys)


def encrypt_field(plaintext: str, dek_store: DEKStore, dek_id: str) -> EncryptedField:
    """Encrypt a plaintext field using AES-256-GCM.

    Parameters:
        plaintext:  The text to encrypt.
        dek_store:  DEK store to retrieve the key from.
        dek_id:     DEK identifier (must already exist in the store).

    Returns:
        ``EncryptedField`` with ciphertext, nonce, and dek_id.

    Raises:
        KeyError: If the DEK has been destroyed or doesn't exist.
    """
    key = dek_store.get_dek(dek_id)
    if key is None:
        raise KeyError(f"DEK '{dek_id}' not found or has been destroyed")

    nonce = os.urandom(12)  # 96-bit GCM nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return EncryptedField(ciphertext=ciphertext, nonce=nonce, dek_id=dek_id)


def decrypt_field(field: EncryptedField, dek_store: DEKStore) -> str:
    """Decrypt an encrypted field.

    Parameters:
        field:      The encrypted field to decrypt.
        dek_store:  DEK store to retrieve the key from.

    Returns:
        Decrypted plaintext string.

    Raises:
        KeyError: If the DEK has been destroyed (field is shredded).
        ValueError: If decryption fails (wrong key, tampered ciphertext).
    """
    if field.shredded:
        raise KeyError(f"Field is shredded — DEK '{field.dek_id}' has been destroyed")

    key = dek_store.get_dek(field.dek_id)
    if key is None:
        raise KeyError(f"DEK '{field.dek_id}' not found or has been destroyed")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(field.nonce, field.ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e


def shred_tenant(dek_id: str, dek_store: DEKStore) -> bool:
    """Crypto-shred a tenant's data by destroying their DEK.

    After this call:
    - All ``EncryptedField``s with this ``dek_id`` are permanently unreadable
    - The hash-chain remains intact (it hashed the ciphertext, not plaintext)
    - GDPR Art. 17 compliance is achieved without modifying the chain

    Parameters:
        dek_id:     The DEK to destroy.
        dek_store:  DEK store managing the key.

    Returns:
        True if the DEK was found and destroyed.
    """
    return dek_store.destroy_dek(dek_id)
