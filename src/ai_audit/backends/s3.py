"""S3ArchiveBackend — gzipped JSON object storage for long-term archival.

Layout::

    s3://<bucket>/<prefix>receipts/<tenant_id>/<yyyy-mm>/<receipt_id>.json.gz
    s3://<bucket>/<prefix>seals/<batch_id>.json.gz

The backend is append-only by design — ``read_receipt`` requires either the
tenant_id (for an efficient prefix scan) or it falls back to a full-tenant scan.
Use it as the cold tier behind a tiered store; not as your only backend.

Usage::

    from ai_audit.backends.s3 import S3ArchiveBackend
    backend = S3ArchiveBackend(bucket="acme-audit", prefix="prod/")
    backend.write_receipt(receipt)
    by_tenant = backend.query_by_tenant("acme", limit=100)

Optional dep: ``pip install aioboto3>=12.0``.
"""

from __future__ import annotations

import gzip
import json
import logging
from typing import TYPE_CHECKING, Any

import orjson

from ai_audit.batch import BatchSeal
from ai_audit.models import DecisionReceipt
from ai_audit.storage import StorageBackend

if TYPE_CHECKING:
    pass  # boto3 types omitted for slim runtime

logger = logging.getLogger(__name__)


def _receipt_key(prefix: str, receipt: DecisionReceipt) -> str:
    yyyymm = receipt.timestamp.strftime("%Y-%m")
    return f"{prefix}receipts/{receipt.tenant_id}/{yyyymm}/{receipt.receipt_id}.json.gz"


def _tenant_prefix(prefix: str, tenant_id: str) -> str:
    return f"{prefix}receipts/{tenant_id}/"


def _seal_key(prefix: str, seal: BatchSeal) -> str:
    return f"{prefix}seals/{seal.batch_id}.json.gz"


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


def _dict_to_seal(payload: dict[str, Any]) -> BatchSeal:
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


class S3ArchiveBackend(StorageBackend):
    """Cold archive backend backed by S3 (or any S3-compatible store).

    Parameters:
        bucket:        S3 bucket name (must already exist).
        prefix:        Key prefix; trailing slash auto-added if missing.
        client:        Optional pre-built boto3 S3 client. If None, a default
                       client is created lazily via ``boto3.client('s3')``.
        endpoint_url:  Override for S3-compatible stores (MinIO, Wasabi, …).
    """

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        client: Any | None = None,
        endpoint_url: str | None = None,
        region_name: str | None = None,
    ) -> None:
        if prefix and not prefix.endswith("/"):
            prefix = prefix + "/"
        self.bucket = bucket
        self.prefix = prefix
        self._client = client
        self._endpoint_url = endpoint_url
        self._region_name = region_name

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "S3ArchiveBackend requires 'boto3' (or 'aioboto3'). "
                "Install with: pip install ai-audit-trail[s3]"
            ) from e
        kwargs: dict[str, Any] = {}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        if self._region_name:
            kwargs["region_name"] = self._region_name
        self._client = boto3.client("s3", **kwargs)
        return self._client

    # ------------------------------------------------------------------ writes

    def write_receipt(self, receipt: DecisionReceipt) -> None:
        client = self._ensure_client()
        key = _receipt_key(self.prefix, receipt)
        body = gzip.compress(orjson.dumps(receipt.model_dump(mode="json")))
        client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json")

    def write_batch_seal(self, seal: BatchSeal) -> None:
        client = self._ensure_client()
        key = _seal_key(self.prefix, seal)
        body = gzip.compress(orjson.dumps(_seal_to_dict(seal)))
        client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json")

    # ------------------------------------------------------------------ reads

    def read_receipt(self, receipt_id: str) -> DecisionReceipt | None:
        client = self._ensure_client()
        for tenant_prefix in self._list_tenants(client):
            paginator = client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=tenant_prefix):
                for obj in page.get("Contents", []) or []:
                    key = obj["Key"]
                    if key.endswith(f"/{receipt_id}.json.gz"):
                        return self._fetch_receipt(client, key)
        return None

    def read_batch_seal(self, batch_id: str) -> BatchSeal | None:
        client = self._ensure_client()
        key = f"{self.prefix}seals/{batch_id}.json.gz"
        try:
            obj = client.get_object(Bucket=self.bucket, Key=key)
        except Exception:  # noqa: BLE001
            return None
        body = gzip.decompress(obj["Body"].read())
        return _dict_to_seal(json.loads(body))

    def query_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        client = self._ensure_client()
        receipts: list[DecisionReceipt] = []
        prefix = _tenant_prefix(self.prefix, tenant_id)
        paginator = client.get_paginator("list_objects_v2")
        keys: list[tuple[str, Any]] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []) or []:
                keys.append((obj["Key"], obj.get("LastModified")))
        keys.sort(key=lambda kv: kv[1] or "", reverse=True)
        for key, _ in keys[:limit]:
            r = self._fetch_receipt(client, key)
            if r is not None:
                receipts.append(r)
        return receipts

    def healthcheck(self) -> bool:
        try:
            client = self._ensure_client()
            client.head_bucket(Bucket=self.bucket)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("S3ArchiveBackend healthcheck failed: %s", exc)
            return False

    # ------------------------------------------------------------------ helpers

    def _list_tenants(self, client: Any) -> list[str]:
        prefix = f"{self.prefix}receipts/"
        paginator = client.get_paginator("list_objects_v2")
        tenants: set[str] = set()
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []) or []:
                tenants.add(cp["Prefix"])
        return sorted(tenants)

    def _fetch_receipt(self, client: Any, key: str) -> DecisionReceipt | None:
        try:
            obj = client.get_object(Bucket=self.bucket, Key=key)
            body = gzip.decompress(obj["Body"].read())
            return DecisionReceipt.model_validate(json.loads(body))
        except Exception as exc:  # noqa: BLE001
            logger.warning("S3ArchiveBackend: failed to read %s: %s", key, exc)
            return None


__all__ = ["S3ArchiveBackend"]
