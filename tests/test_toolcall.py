"""Tests for Cryptographic Tool-Call Receipts."""

import nacl.signing

from ai_audit.toolcall import ToolCallReceipt, seal_tool_call, verify_tool_call_chain


def _make_key() -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey.generate()


def test_seal_tool_call() -> None:
    """seal_tool_call should create a fully sealed receipt."""
    key = _make_key()
    receipt = seal_tool_call(
        agent_id="search-agent",
        tool_name="web_search",
        tool_args={"query": "EU AI Act", "limit": 10},
        tool_result="Found 5 results about EU AI Act...",
        private_key=key,
        tenant_id="acme",
    )
    assert receipt.receipt_id != ""
    assert receipt.tool_args_hash != ""
    assert receipt.tool_result_hash != ""
    assert receipt.receipt_hash != ""
    assert receipt.signature != ""
    assert receipt.agent_id == "search-agent"
    assert receipt.tool_name == "web_search"


def test_tool_call_verify() -> None:
    """Sealed tool-call receipt should verify with correct key."""
    key = _make_key()
    receipt = seal_tool_call(
        agent_id="agent-1",
        tool_name="api_call",
        tool_args={"endpoint": "/users"},
        tool_result="200 OK",
        private_key=key,
    )
    assert receipt.verify(key.verify_key)


def test_tool_call_tamper_detected() -> None:
    """Modifying a sealed receipt should fail verification."""
    key = _make_key()
    receipt = seal_tool_call(
        agent_id="agent-1",
        tool_name="api_call",
        tool_args={"endpoint": "/users"},
        tool_result="200 OK",
        private_key=key,
    )
    receipt.tool_name = "TAMPERED"
    assert not receipt.verify(key.verify_key)


def test_different_args_different_hash() -> None:
    """Different tool arguments must produce different hashes."""
    key = _make_key()
    r1 = seal_tool_call(
        agent_id="a", tool_name="t",
        tool_args={"x": 1}, tool_result="r", private_key=key,
    )
    r2 = seal_tool_call(
        agent_id="a", tool_name="t",
        tool_args={"x": 2}, tool_result="r", private_key=key,
    )
    assert r1.tool_args_hash != r2.tool_args_hash


def test_tool_call_chain_verification() -> None:
    """A chain of tool-call receipts should verify correctly."""
    key = _make_key()
    chain: list[ToolCallReceipt] = []
    prev_hash = ""

    for i in range(5):
        receipt = seal_tool_call(
            agent_id="agent-1",
            tool_name=f"tool_{i}",
            tool_args={"step": i},
            tool_result=f"result_{i}",
            private_key=key,
            prev_receipt_hash=prev_hash,
        )
        chain.append(receipt)
        prev_hash = receipt.receipt_hash

    assert verify_tool_call_chain(chain, key.verify_key)


def test_tool_call_chain_tamper_detected() -> None:
    """Tampering with a receipt in the chain must be detected."""
    key = _make_key()
    chain: list[ToolCallReceipt] = []
    prev_hash = ""

    for i in range(3):
        receipt = seal_tool_call(
            agent_id="agent-1",
            tool_name=f"tool_{i}",
            tool_args={"step": i},
            tool_result=f"result_{i}",
            private_key=key,
            prev_receipt_hash=prev_hash,
        )
        chain.append(receipt)
        prev_hash = receipt.receipt_hash

    chain[1].tool_name = "TAMPERED"
    assert not verify_tool_call_chain(chain, key.verify_key)


def test_failed_tool_call() -> None:
    """Failed tool calls should be auditable too."""
    key = _make_key()
    receipt = seal_tool_call(
        agent_id="agent-1",
        tool_name="dangerous_api",
        tool_args={"action": "delete"},
        tool_result="",
        private_key=key,
        success=False,
        error="Permission denied",
    )
    assert not receipt.success
    assert receipt.error == "Permission denied"
    assert receipt.verify(key.verify_key)
