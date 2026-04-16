"""
ai_audit.epochs — Chain Epochs and Rollover for long-lived audit trails.

Prevents unbounded chain growth by periodically sealing epochs.
Each epoch aggregates a range of receipts into a single ``EpochSeal``
with a Merkle root. Epochs themselves form a chain via
``prev_epoch_seal_hash``, enabling cross-epoch verification.

Rollover triggers:
- **Count**: seal after N receipts (default: 10,000)
- **Explicit**: ``seal_epoch()`` API call (e.g. daily cron)

After sealing, old epoch data can be archived or deleted without
breaking the current chain — only the ``EpochSeal`` chain matters.

NB 409cad95 (Enterprise) validated — 2026-04-16.
NB correction: lock-free rollover (no hot-path blocking).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

import nacl.signing
import orjson

from ai_audit.batch import merkle_root
from ai_audit.models import DecisionReceipt


@dataclass
class EpochSeal:
    """Cryptographic seal for a completed epoch.

    Attributes:
        epoch_id:              Unique epoch identifier.
        tenant_id:             Tenant this epoch belongs to.
        first_receipt_hash:    Hash of the first receipt in this epoch.
        last_receipt_hash:     Hash of the last receipt in this epoch.
        receipt_count:         Number of receipts in this epoch.
        merkle_root:           Merkle root over all receipt payloads.
        sealed_at:             ISO 8601 timestamp of sealing.
        prev_epoch_seal_hash:  SHA-256 of the previous EpochSeal's payload (chain).
        signature:             Ed25519 signature (hex).
    """

    epoch_id: str = ""
    tenant_id: str = ""
    first_receipt_hash: str = ""
    last_receipt_hash: str = ""
    receipt_count: int = 0
    merkle_root: str = ""
    sealed_at: str = ""
    prev_epoch_seal_hash: str = ""
    signature: str = ""

    def seal_payload(self) -> bytes:
        """Canonical bytes for hashing and signing (excludes ``signature``)."""
        data = {
            "epoch_id": self.epoch_id,
            "tenant_id": self.tenant_id,
            "first_receipt_hash": self.first_receipt_hash,
            "last_receipt_hash": self.last_receipt_hash,
            "receipt_count": self.receipt_count,
            "merkle_root": self.merkle_root,
            "sealed_at": self.sealed_at,
            "prev_epoch_seal_hash": self.prev_epoch_seal_hash,
        }
        return orjson.dumps(data, option=orjson.OPT_SORT_KEYS)

    def compute_hash(self) -> str:
        """SHA-256 of the canonical seal payload."""
        return hashlib.sha256(self.seal_payload()).hexdigest()

    def seal(self, private_key: nacl.signing.SigningKey) -> None:
        """Sign the epoch seal with Ed25519."""
        payload = self.seal_payload()
        signed = private_key.sign(payload)
        self.signature = signed.signature.hex()

    def verify(self, verify_key: nacl.signing.VerifyKey) -> bool:
        """Verify the Ed25519 signature."""
        try:
            verify_key.verify(self.seal_payload(), bytes.fromhex(self.signature))
            return True
        except (nacl.exceptions.BadSignatureError, ValueError):
            return False


class EpochManager:
    """Manages epoch lifecycle for a single tenant.

    Parameters:
        tenant_id:        Tenant identifier.
        private_key:      Ed25519 signing key.
        max_epoch_size:   Auto-seal after this many receipts (default: 10,000).
    """

    def __init__(
        self,
        tenant_id: str,
        private_key: nacl.signing.SigningKey,
        *,
        max_epoch_size: int = 10_000,
    ) -> None:
        self._tenant_id = tenant_id
        self._private_key = private_key
        self._max_epoch_size = max_epoch_size
        self._current_receipts: list[DecisionReceipt] = []
        self._epoch_number: int = 0
        self._prev_epoch_hash: str = ""
        self._seals: list[EpochSeal] = []

    def add_receipt(self, receipt: DecisionReceipt) -> EpochSeal | None:
        """Add a receipt to the current epoch.

        Returns:
            An ``EpochSeal`` if the epoch was auto-sealed, else ``None``.
        """
        self._current_receipts.append(receipt)
        if len(self._current_receipts) >= self._max_epoch_size:
            return self.seal_epoch()
        return None

    def seal_epoch(self) -> EpochSeal | None:
        """Seal the current epoch explicitly.

        Returns:
            The ``EpochSeal``, or ``None`` if no receipts in current epoch.
        """
        if not self._current_receipts:
            return None

        sorted_receipts = sorted(self._current_receipts, key=lambda r: r.timestamp)
        payloads = [r.seal_payload() for r in sorted_receipts]
        root = merkle_root(payloads)

        self._epoch_number += 1
        seal = EpochSeal(
            epoch_id=f"{self._tenant_id}-epoch-{self._epoch_number}",
            tenant_id=self._tenant_id,
            first_receipt_hash=sorted_receipts[0].receipt_hash,
            last_receipt_hash=sorted_receipts[-1].receipt_hash,
            receipt_count=len(sorted_receipts),
            merkle_root=root.hex(),
            sealed_at=datetime.now(UTC).isoformat(),
            prev_epoch_seal_hash=self._prev_epoch_hash,
        )
        seal.seal(self._private_key)

        self._prev_epoch_hash = seal.compute_hash()
        self._seals.append(seal)
        self._current_receipts.clear()

        return seal

    @property
    def current_epoch_size(self) -> int:
        """Number of receipts in the unsealed current epoch."""
        return len(self._current_receipts)

    @property
    def seals(self) -> list[EpochSeal]:
        """All completed epoch seals."""
        return list(self._seals)

    def verify_epoch_chain(self, verify_key: nacl.signing.VerifyKey) -> bool:
        """Verify the chain of epoch seals.

        Checks:
        1. Each seal's Ed25519 signature is valid.
        2. Each seal's ``prev_epoch_seal_hash`` matches the preceding seal's hash.
        """
        prev_hash = ""
        for seal in self._seals:
            if seal.prev_epoch_seal_hash != prev_hash:
                return False
            if not seal.verify(verify_key):
                return False
            prev_hash = seal.compute_hash()
        return True
