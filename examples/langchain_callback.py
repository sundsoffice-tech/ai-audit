#!/usr/bin/env python3
"""LangChain callback handler integration for ai-audit-trail.

Automatically creates audit receipts for every LLM call in a LangChain chain.

Usage::

    from langchain_openai import ChatOpenAI
    from examples.langchain_callback import AuditCallbackHandler

    handler = AuditCallbackHandler(tenant_id="acme")
    llm = ChatOpenAI(callbacks=[handler])
    llm.invoke("What is 2+2?")

Requires: pip install langchain-core
"""

from __future__ import annotations

EXAMPLE_CODE = '''
import uuid
from ai_audit import (
    AuditConfig, ReceiptAction, ReceiptCollector, ReceiptStore,
    init_audit_config,
)
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

init_audit_config(AuditConfig.from_env())
store = ReceiptStore()

class AuditCallbackHandler(BaseCallbackHandler):
    """LangChain callback that creates audit receipts for every LLM call."""

    def __init__(self, tenant_id: str = "default", session_id: str = ""):
        self.tenant_id = tenant_id
        self.session_id = session_id
        self._collectors: dict[str, ReceiptCollector] = {}

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        collector = ReceiptCollector(
            trace_id=str(run_id),
            tenant_id=self.tenant_id,
            session_id=self.session_id,
        )
        collector.set_input(prompts[0] if prompts else "")
        collector._receipt.model_id = serialized.get("kwargs", {}).get("model_name", "unknown")
        self._collectors[str(run_id)] = collector

    def on_llm_end(self, response: LLMResult, *, run_id, **kwargs):
        collector = self._collectors.pop(str(run_id), None)
        if collector is None:
            return
        text = response.generations[0][0].text if response.generations else ""
        collector.set_output(text)
        collector.set_action(ReceiptAction.ALLOW)
        collector.emit(store)
        collector.cleanup()

    def on_llm_error(self, error, *, run_id, **kwargs):
        collector = self._collectors.pop(str(run_id), None)
        if collector is None:
            return
        collector.set_output(str(error))
        collector.set_action(ReceiptAction.FAIL_RETRY)
        collector.emit(store)
        collector.cleanup()


# Usage:
# from langchain_openai import ChatOpenAI
# handler = AuditCallbackHandler(tenant_id="acme")
# llm = ChatOpenAI(model="gpt-4", callbacks=[handler])
# result = llm.invoke("What is the meaning of life?")
# print(f"Audited {store.count} LLM calls")
'''

if __name__ == "__main__":
    print("LangChain Audit Callback Handler Example")
    print("=" * 40)
    print(EXAMPLE_CODE)
