#!/usr/bin/env python3
"""FastAPI integration moved to a real importable module in v0.4.0.

Use::

    from ai_audit.integrations.fastapi import AuditMiddleware

This file is kept only as a runnable smoke-test that constructs a
Starlette test app with the middleware and emits one receipt.
"""

from __future__ import annotations


def _smoketest() -> None:
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from ai_audit import ReceiptStore
    from ai_audit.integrations.fastapi import AuditMiddleware

    store = ReceiptStore()

    async def chat(request):  # type: ignore[no-untyped-def]
        return JSONResponse({"answer": "42"})

    app = Starlette(routes=[Route("/v1/ai/chat", chat)])
    app.add_middleware(AuditMiddleware, store=store, tenant_id="acme")

    client = TestClient(app)
    resp = client.get("/v1/ai/chat", headers={"x-trace-id": "demo-trace"})
    print(f"HTTP {resp.status_code}")
    print(f"Receipts captured: {len(store.get_by_tenant('acme'))}")
    print(f"Trace ID propagated: {store.get_by_tenant('acme')[0].trace_id}")


if __name__ == "__main__":
    _smoketest()
