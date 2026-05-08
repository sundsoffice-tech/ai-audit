"""PostgresColdBackend — JSONB-backed StorageBackend for cold-tier persistence.

The backend stores receipts and batch seals in two simple tables. Schema is
created idempotently via :py:meth:`PostgresColdBackend.ensure_schema`. For very
large deployments, partition the receipts table by ``(tenant_id, timestamp)``
month externally; this module does not manage partitions.

Schema::

    CREATE TABLE IF NOT EXISTS ai_audit_receipts (
        receipt_id  TEXT PRIMARY KEY,
        tenant_id   TEXT NOT NULL,
        timestamp   TIMESTAMPTZ NOT NULL,
        payload     JSONB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ai_audit_receipts_tenant_ts_idx
        ON ai_audit_receipts (tenant_id, timestamp DESC);

    CREATE TABLE IF NOT EXISTS ai_audit_batch_seals (
        batch_id    TEXT PRIMARY KEY,
        sealed_at   TIMESTAMPTZ NOT NULL,
        payload     JSONB NOT NULL
    );

Usage::

    import asyncio, asyncpg
    from ai_audit.backends.postgres import PostgresColdBackend

    pool = asyncio.run(asyncpg.create_pool("postgres://user:pw@host/db"))
    backend = PostgresColdBackend(pool=pool)
    asyncio.run(backend.ensure_schema())
    backend.write_receipt(receipt)            # sync wrapper
    await backend.awrite_receipt(receipt)     # native async

The sync methods (``write_receipt``, ``read_receipt`` …) bridge via
``asyncio.run`` / ``run_until_complete``, so they MUST NOT be called from inside
a running event loop. Use the ``a*`` variants in async code paths.

Optional dep: ``pip install asyncpg>=0.29``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

import orjson

from ai_audit.batch import BatchSeal
from ai_audit.models import DecisionReceipt
from ai_audit.storage import StorageBackend

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


_RECEIPT_DDL = """
CREATE TABLE IF NOT EXISTS ai_audit_receipts (
    receipt_id  TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_audit_receipts_tenant_ts_idx
    ON ai_audit_receipts (tenant_id, timestamp DESC);
"""

_SEAL_DDL = """
CREATE TABLE IF NOT EXISTS ai_audit_batch_seals (
    batch_id    TEXT PRIMARY KEY,
    sealed_at   TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL
);
"""


def _run_sync(coro: Any) -> Any:
    """Run *coro* to completion. Refuses to run inside an active event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError(
        "Sync method called from a running event loop. Use the 'a*' async variant."
    )


class PostgresColdBackend(StorageBackend):
    """Async-first Postgres backend with sync convenience wrappers."""

    def __init__(self, *, pool: Any | None = None, dsn: str | None = None) -> None:
        if pool is None and dsn is None:
            raise ValueError("PostgresColdBackend requires either 'pool' or 'dsn'.")
        self._pool: Any | None = pool
        self._dsn = dsn

    async def _ensure_pool(self) -> Any:
        if self._pool is None:
            try:
                import asyncpg
            except ImportError as e:  # pragma: no cover
                raise ImportError(
                    "PostgresColdBackend requires 'asyncpg>=0.29'. "
                    "Install with: pip install ai-audit-trail[postgres]"
                ) from e
            self._pool = await asyncpg.create_pool(self._dsn)
        return self._pool

    async def ensure_schema(self) -> None:
        """Create receipts + batch_seals tables (idempotent)."""
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            await conn.execute(_RECEIPT_DDL)
            await conn.execute(_SEAL_DDL)

    # ------------------------------------------------------------------ async API

    async def awrite_receipt(self, receipt: DecisionReceipt) -> None:
        pool = await self._ensure_pool()
        payload = orjson.dumps(receipt.model_dump(mode="json")).decode()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO ai_audit_receipts (receipt_id, tenant_id, timestamp, payload) "
                "VALUES ($1, $2, $3, $4::jsonb) "
                "ON CONFLICT (receipt_id) DO NOTHING",
                receipt.receipt_id,
                receipt.tenant_id,
                receipt.timestamp,
                payload,
            )

    async def awrite_batch_seal(self, seal: BatchSeal) -> None:
        from datetime import UTC, datetime

        pool = await self._ensure_pool()
        payload = orjson.dumps(_seal_to_dict(seal)).decode()
        try:
            sealed_at = datetime.fromisoformat(seal.timestamp) if seal.timestamp else datetime.now(UTC)
        except ValueError:
            sealed_at = datetime.now(UTC)
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO ai_audit_batch_seals (batch_id, sealed_at, payload) "
                "VALUES ($1, $2, $3::jsonb) "
                "ON CONFLICT (batch_id) DO NOTHING",
                seal.batch_id,
                sealed_at,
                payload,
            )

    async def aread_receipt(self, receipt_id: str) -> DecisionReceipt | None:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT payload FROM ai_audit_receipts WHERE receipt_id = $1", receipt_id
            )
        return _row_to_receipt(row)

    async def aread_batch_seal(self, batch_id: str) -> BatchSeal | None:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT payload FROM ai_audit_batch_seals WHERE batch_id = $1", batch_id
            )
        return _row_to_seal(row)

    async def aquery_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT payload FROM ai_audit_receipts "
                "WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2",
                tenant_id,
                limit,
            )
        return [r for r in (_row_to_receipt(row) for row in rows) if r is not None]

    async def ahealthcheck(self) -> bool:
        try:
            pool = await self._ensure_pool()
            async with pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("PostgresColdBackend healthcheck failed: %s", exc)
            return False

    # ------------------------------------------------------------------ sync API

    def write_receipt(self, receipt: DecisionReceipt) -> None:
        _run_sync(self.awrite_receipt(receipt))

    def write_batch_seal(self, seal: BatchSeal) -> None:
        _run_sync(self.awrite_batch_seal(seal))

    def read_receipt(self, receipt_id: str) -> DecisionReceipt | None:
        return _run_sync(self.aread_receipt(receipt_id))  # type: ignore[no-any-return]

    def read_batch_seal(self, batch_id: str) -> BatchSeal | None:
        return _run_sync(self.aread_batch_seal(batch_id))  # type: ignore[no-any-return]

    def query_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        return _run_sync(self.aquery_by_tenant(tenant_id, limit))  # type: ignore[no-any-return]

    def healthcheck(self) -> bool:
        return _run_sync(self.ahealthcheck())  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Row <-> object helpers
# ---------------------------------------------------------------------------


def _row_to_receipt(row: Any) -> DecisionReceipt | None:
    if row is None:
        return None
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return DecisionReceipt.model_validate(payload)


def _seal_to_dict(seal: BatchSeal) -> dict[str, Any]:
    return {
        "batch_id": seal.batch_id,
        "merkle_root": seal.merkle_root,
        "leaf_count": seal.leaf_count,
        "prev_batch_root": seal.prev_batch_root,
        "timestamp": seal.timestamp,
        "tenant_id": seal.tenant_id,
        "signature": seal.signature,
        "receipt_ids": list(seal.receipt_ids),
    }


def _row_to_seal(row: Any) -> BatchSeal | None:
    if row is None:
        return None
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return BatchSeal(
        batch_id=payload["batch_id"],
        merkle_root=payload["merkle_root"],
        leaf_count=payload["leaf_count"],
        prev_batch_root=payload.get("prev_batch_root", ""),
        timestamp=payload.get("timestamp", ""),
        tenant_id=payload.get("tenant_id", ""),
        signature=payload.get("signature", ""),
        receipt_ids=list(payload.get("receipt_ids", [])),
    )


__all__ = ["PostgresColdBackend"]
