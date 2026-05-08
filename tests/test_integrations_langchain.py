"""Tests for ai_audit.integrations.langchain.AuditCallbackHandler."""

from __future__ import annotations

from uuid import uuid4

import pytest

langchain_core = pytest.importorskip("langchain_core")

from langchain_core.outputs import Generation, LLMResult  # noqa: E402

from ai_audit import ReceiptAction, ReceiptStore, reset_signing_key  # noqa: E402
from ai_audit.integrations.langchain import AuditCallbackHandler  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_keys() -> None:
    reset_signing_key()


def test_callback_emits_on_llm_end() -> None:
    store = ReceiptStore()
    handler = AuditCallbackHandler(store=store, tenant_id="acme")
    rid = uuid4()
    handler.on_llm_start(
        {"kwargs": {"model_name": "claude-opus-4-7"}},
        ["What is 2+2?"],
        run_id=rid,
    )
    result = LLMResult(generations=[[Generation(text="4")]])
    handler.on_llm_end(result, run_id=rid)

    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.ALLOW
    assert receipts[0].trace_id == str(rid)
    assert receipts[0].model_id == "claude-opus-4-7"


def test_callback_emits_fail_retry_on_error() -> None:
    store = ReceiptStore()
    handler = AuditCallbackHandler(store=store, tenant_id="acme")
    rid = uuid4()
    handler.on_llm_start({"kwargs": {}}, ["x"], run_id=rid)
    handler.on_llm_error(RuntimeError("boom"), run_id=rid)

    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.FAIL_RETRY
