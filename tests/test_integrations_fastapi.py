"""Tests for ai_audit.integrations.fastapi.AuditMiddleware (uses Starlette TestClient)."""

from __future__ import annotations

import pytest

starlette = pytest.importorskip("starlette")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from ai_audit import ReceiptAction, ReceiptStore, reset_signing_key  # noqa: E402
from ai_audit.integrations.fastapi import AuditMiddleware  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_keys() -> None:
    reset_signing_key()


def _build_app(store: ReceiptStore, **mw_kwargs):  # type: ignore[no-untyped-def]
    async def hello(request):  # type: ignore[no-untyped-def]
        return JSONResponse({"ok": True})

    async def boom(request):  # type: ignore[no-untyped-def]
        return JSONResponse({"err": "nope"}, status_code=500)

    app = Starlette(routes=[Route("/v1/ai/hello", hello), Route("/v1/ai/boom", boom)])
    app.add_middleware(AuditMiddleware, store=store, tenant_id="acme", **mw_kwargs)
    return app


def test_middleware_emits_receipt_on_success() -> None:
    store = ReceiptStore()
    app = _build_app(store)
    client = TestClient(app)
    resp = client.get("/v1/ai/hello", headers={"x-trace-id": "trace-1"})
    assert resp.status_code == 200
    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.ALLOW
    assert receipts[0].trace_id == "trace-1"


def test_middleware_emits_reject_on_4xx_or_5xx() -> None:
    store = ReceiptStore()
    app = _build_app(store)
    client = TestClient(app)
    client.get("/v1/ai/boom")
    receipts = store.get_by_tenant("acme")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.REJECT


def test_middleware_skips_non_matching_path() -> None:
    store = ReceiptStore()
    app = _build_app(store, path_prefix="/v1/ai/")

    async def healthz(request):  # type: ignore[no-untyped-def]
        return JSONResponse({"ok": True})

    app.routes.append(Route("/healthz", healthz))
    client = TestClient(app)
    client.get("/healthz")
    assert store.get_by_tenant("acme") == []
