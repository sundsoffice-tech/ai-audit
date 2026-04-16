#!/usr/bin/env python3
"""FastAPI middleware integration for ai-audit-trail.

Wraps every AI endpoint with automatic receipt creation.

Usage::

    from fastapi import FastAPI
    from examples.fastapi_middleware import AuditMiddleware

    app = FastAPI()
    app.add_middleware(AuditMiddleware, tenant_id="acme")

Requires: pip install fastapi
"""

from __future__ import annotations

# --- This is an EXAMPLE file, not a runnable module ---
# It shows the integration pattern without requiring fastapi as a dependency.

EXAMPLE_CODE = '''
import uuid
from ai_audit import (
    AuditConfig, ReceiptAction, ReceiptCollector, ReceiptStore,
    init_audit_config,
)
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Initialize once at startup
init_audit_config(AuditConfig.from_env())
store = ReceiptStore()

class AuditMiddleware(BaseHTTPMiddleware):
    """Automatically creates audit receipts for AI endpoints."""

    def __init__(self, app, tenant_id: str = "default"):
        super().__init__(app)
        self.tenant_id = tenant_id

    async def dispatch(self, request: Request, call_next):
        # Skip non-AI endpoints
        if not request.url.path.startswith("/v1/ai/"):
            return await call_next(request)

        trace_id = request.headers.get("x-trace-id", uuid.uuid4().hex)
        collector = ReceiptCollector(
            trace_id=trace_id,
            tenant_id=self.tenant_id,
            session_id=request.headers.get("x-session-id", ""),
        )

        # Capture input
        body = await request.body()
        collector.set_input(body.decode("utf-8", errors="replace"))

        try:
            response = await call_next(request)

            # Capture output (simplified — real impl would read response body)
            collector.set_output(f"status={response.status_code}")
            collector.set_action(
                ReceiptAction.ALLOW if response.status_code < 400
                else ReceiptAction.REJECT
            )
        except Exception as e:
            collector.set_output(str(e))
            collector.set_action(ReceiptAction.FAIL_RETRY)
            raise
        finally:
            collector.emit(store)
            collector.cleanup()

        return response


# Usage:
app = FastAPI()
app.add_middleware(AuditMiddleware, tenant_id="acme")

@app.post("/v1/ai/chat")
async def chat(request: Request):
    return {"message": "Hello! This request was audited."}
'''

if __name__ == "__main__":
    print("FastAPI Audit Middleware Example")
    print("=" * 40)
    print(EXAMPLE_CODE)
