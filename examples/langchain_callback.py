#!/usr/bin/env python3
"""LangChain integration moved to a real importable module in v0.4.0.

Use::

    from ai_audit.integrations.langchain import AuditCallbackHandler
    from langchain_openai import ChatOpenAI

    handler = AuditCallbackHandler(store=store, tenant_id="acme")
    llm = ChatOpenAI(callbacks=[handler])

This file is kept as a runnable smoke-test that exercises the handler
without making any live API calls.
"""

from __future__ import annotations


def _smoketest() -> None:
    from uuid import uuid4

    from langchain_core.outputs import Generation, LLMResult

    from ai_audit import ReceiptStore
    from ai_audit.integrations.langchain import AuditCallbackHandler

    store = ReceiptStore()
    handler = AuditCallbackHandler(store=store, tenant_id="acme")

    rid = uuid4()
    handler.on_llm_start(
        {"kwargs": {"model_name": "claude-opus-4-7"}},
        ["What is 2+2?"],
        run_id=rid,
    )
    handler.on_llm_end(LLMResult(generations=[[Generation(text="4")]]), run_id=rid)

    print(f"Receipts captured: {len(store.get_by_tenant('acme'))}")
    r = store.get_by_tenant("acme")[0]
    print(f"Model:  {r.model_id}")
    print(f"Action: {r.action}")
    print(f"Trace:  {r.trace_id}")


if __name__ == "__main__":
    _smoketest()
