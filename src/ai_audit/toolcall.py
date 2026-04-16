"""
ai_audit.toolcall — Cryptographic Tool-Call Receipts for Agentic AI.

World-first: Every external API call made by an AI agent is
cryptographically sealed with Ed25519, creating a tamper-evident
audit trail of agent actions. No existing framework (Langfuse, MLflow,
Arize) provides cryptographic non-repudiation for tool calls.

Usage::

    from ai_audit.toolcall import ToolCallReceipt, seal_tool_call

    receipt = seal_tool_call(
        agent_id="triage-agent",
        tool_name="search_api",
        tool_args={"query": "EU AI Act", "limit": 10},
        tool_result="Found 5 results...",
        tenant_id="acme",
    )
    assert receipt.tool_args_hash != ""
    assert receipt.signature != ""

NB a861f2b3 (Agentic) validated — 2026-04-16.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import nacl.signing
import orjson


@dataclass
class ToolCallReceipt:
    """Cryptographic receipt for an agent's external tool call.

    Extends the Decision Receipt concept with tool-specific fields.
    The ``tool_args_hash`` is a SHA-256 of the canonical tool arguments,
    ensuring the exact parameters are tamper-evident without storing
    potentially sensitive argument values in the receipt itself.

    Attributes:
        receipt_id:        Unique receipt identifier.
        agent_id:          Identifier of the calling agent.
        parent_receipt_id: Receipt that triggered this tool call (trace linkage).
        tenant_id:         Tenant context.
        tool_name:         Name of the tool/API called.
        tool_args_hash:    SHA-256 of canonical tool arguments.
        tool_result_hash:  SHA-256 of the tool's response.
        timestamp:         When the call was made.
        duration_ms:       Call duration in milliseconds.
        success:           Whether the call succeeded.
        error:             Error message if the call failed.
        prev_receipt_hash: Hash-chain linkage.
        receipt_hash:      SHA-256 self-hash.
        signature:         Ed25519 signature (hex).
    """

    receipt_id: str = ""
    agent_id: str = ""
    parent_receipt_id: str = ""
    tenant_id: str = ""
    tool_name: str = ""
    tool_args_hash: str = ""
    tool_result_hash: str = ""
    timestamp: str = ""
    duration_ms: float = 0.0
    success: bool = True
    error: str = ""
    prev_receipt_hash: str = ""
    receipt_hash: str = ""
    signature: str = ""

    def seal_payload(self) -> bytes:
        """Canonical bytes for hashing + signing (excludes receipt_hash & signature)."""
        data = {
            "receipt_id": self.receipt_id,
            "agent_id": self.agent_id,
            "parent_receipt_id": self.parent_receipt_id,
            "tenant_id": self.tenant_id,
            "tool_name": self.tool_name,
            "tool_args_hash": self.tool_args_hash,
            "tool_result_hash": self.tool_result_hash,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "success": self.success,
            "error": self.error,
            "prev_receipt_hash": self.prev_receipt_hash,
        }
        return orjson.dumps(data, option=orjson.OPT_SORT_KEYS)

    def compute_hash(self) -> str:
        return hashlib.sha256(self.seal_payload()).hexdigest()

    def seal(self, private_key: nacl.signing.SigningKey) -> None:
        """Seal the receipt: compute hash and Ed25519 signature."""
        payload = self.seal_payload()
        self.receipt_hash = hashlib.sha256(payload).hexdigest()
        signed = private_key.sign(payload)
        self.signature = signed.signature.hex()

    def verify(self, verify_key: nacl.signing.VerifyKey) -> bool:
        """Verify the Ed25519 signature."""
        try:
            verify_key.verify(self.seal_payload(), bytes.fromhex(self.signature))
            return True
        except (nacl.exceptions.BadSignatureError, ValueError):
            return False


def _hash_args(args: dict[str, object]) -> str:
    """Canonical SHA-256 hash of tool arguments."""
    canonical = orjson.dumps(args, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(canonical).hexdigest()


def _hash_result(result: str) -> str:
    """SHA-256 hash of tool result."""
    return hashlib.sha256(result.encode()).hexdigest()


def seal_tool_call(
    *,
    agent_id: str,
    tool_name: str,
    tool_args: dict[str, object],
    tool_result: str,
    private_key: nacl.signing.SigningKey,
    tenant_id: str = "",
    parent_receipt_id: str = "",
    prev_receipt_hash: str = "",
    duration_ms: float = 0.0,
    success: bool = True,
    error: str = "",
) -> ToolCallReceipt:
    """Create and seal a tool-call receipt in one step.

    Parameters:
        agent_id:          Agent that made the call.
        tool_name:         Tool/API name.
        tool_args:         Arguments passed to the tool.
        tool_result:       String result from the tool.
        private_key:       Ed25519 signing key.
        tenant_id:         Tenant context.
        parent_receipt_id: Parent receipt for trace linkage.
        prev_receipt_hash: Previous receipt hash for chain linkage.
        duration_ms:       Call duration.
        success:           Whether the call succeeded.
        error:             Error message if failed.

    Returns:
        Sealed :class:`ToolCallReceipt`.
    """
    receipt = ToolCallReceipt(
        receipt_id=uuid.uuid4().hex,
        agent_id=agent_id,
        parent_receipt_id=parent_receipt_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        tool_args_hash=_hash_args(tool_args),
        tool_result_hash=_hash_result(tool_result),
        timestamp=datetime.now(UTC).isoformat(),
        duration_ms=duration_ms,
        success=success,
        error=error,
        prev_receipt_hash=prev_receipt_hash,
    )
    receipt.seal(private_key)
    return receipt


def verify_tool_call_chain(
    receipts: list[ToolCallReceipt],
    verify_key: nacl.signing.VerifyKey,
) -> bool:
    """Verify a chain of tool-call receipts.

    Checks Ed25519 signatures and hash-chain linkage.
    """
    prev_hash = ""
    for i, r in enumerate(receipts):
        if not r.verify(verify_key):
            return False
        if i > 0 and r.prev_receipt_hash != prev_hash:
            return False
        prev_hash = r.receipt_hash
    return True
