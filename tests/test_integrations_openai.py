"""Tests for ai_audit.integrations.openai (no real OpenAI SDK required)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from ai_audit import ReceiptAction, ReceiptStore, reset_signing_key
from ai_audit.integrations.openai import (
    AuditedOpenAI,
    emit_chat_completion_receipt,
)

# --- Minimal stand-ins for openai response objects ---

@dataclass
class _Msg:
    content: str = ""


@dataclass
class _Choice:
    message: _Msg
    finish_reason: str = "stop"


@dataclass
class _ChatResponse:
    choices: list[_Choice]


def _make_response(text: str = "Hello!", finish: str = "stop") -> _ChatResponse:
    return _ChatResponse(choices=[_Choice(message=_Msg(content=text), finish_reason=finish)])


@pytest.fixture(autouse=True)
def _reset_keys() -> None:
    reset_signing_key()


def test_emit_chat_completion_receipt_creates_receipt() -> None:
    store = ReceiptStore()
    messages = [{"role": "user", "content": "Hi"}]
    response = _make_response("Hello!")
    receipt_id = emit_chat_completion_receipt(
        store, tenant_id="acme", model="gpt-4o-mini",
        messages=messages, response=response,
    )
    assert receipt_id
    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.ALLOW
    assert receipts[0].model_id == "gpt-4o-mini"
    assert "openai.finish_reason=stop" in receipts[0].reason_codes


def test_content_filter_maps_to_reject() -> None:
    store = ReceiptStore()
    response = _make_response("[redacted]", finish="content_filter")
    emit_chat_completion_receipt(
        store, tenant_id="acme", model="gpt-4o-mini",
        messages=[{"role": "user", "content": "x"}], response=response,
    )
    receipts = store.get_by_tenant("acme")
    assert receipts[0].action == ReceiptAction.REJECT


def test_audited_openai_wrap_emits_receipt() -> None:
    store = ReceiptStore()

    class _FakeCompletions:
        def create(self, *, model: str, messages: list[dict[str, Any]], **kw: Any) -> _ChatResponse:
            return _make_response(f"echo: {messages[-1]['content']}")

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    client = AuditedOpenAI(store=store, tenant_id="acme", client=_FakeClient())
    response = client.chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": "ping"}],
    )
    assert response.choices[0].message.content == "echo: ping"
    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.ALLOW
