"""Tests for ai_audit.integrations.anthropic (no real Anthropic SDK required)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from ai_audit import ReceiptAction, ReceiptStore, reset_signing_key
from ai_audit.integrations.anthropic import AuditedAnthropic, emit_messages_receipt


@dataclass
class _Block:
    text: str = ""
    type: str = "text"


@dataclass
class _MessagesResponse:
    content: list[_Block] = field(default_factory=list)
    stop_reason: str = "end_turn"


@pytest.fixture(autouse=True)
def _reset_keys() -> None:
    reset_signing_key()


def test_emit_messages_receipt_creates_receipt() -> None:
    store = ReceiptStore()
    response = _MessagesResponse(content=[_Block(text="Hello!")])
    receipt_id = emit_messages_receipt(
        store, tenant_id="acme", model="claude-opus-4-7",
        messages=[{"role": "user", "content": "Hi"}], response=response,
    )
    assert receipt_id
    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.ALLOW
    assert "anthropic.stop_reason=end_turn" in receipts[0].reason_codes


def test_refusal_maps_to_reject() -> None:
    store = ReceiptStore()
    response = _MessagesResponse(content=[_Block(text="I can't")], stop_reason="refusal")
    emit_messages_receipt(
        store, tenant_id="acme", model="claude-opus-4-7",
        messages=[{"role": "user", "content": "x"}], response=response,
    )
    assert store.get_by_tenant("acme")[0].action == ReceiptAction.REJECT


def test_audited_anthropic_wrap_emits_receipt() -> None:
    store = ReceiptStore()

    class _FakeMessages:
        def create(self, **kw: Any) -> _MessagesResponse:
            user = kw["messages"][-1]["content"]
            return _MessagesResponse(content=[_Block(text=f"echo: {user}")])

    class _FakeClient:
        messages = _FakeMessages()

    client = AuditedAnthropic(store=store, tenant_id="acme", client=_FakeClient())
    response = client.messages.create(
        model="claude-opus-4-7", max_tokens=64,
        messages=[{"role": "user", "content": "ping"}],
    )
    assert response.content[0].text == "echo: ping"
    assert len(store.get_by_tenant("acme")) == 1
