"""Tests for ai_audit.backends.s3.S3ArchiveBackend (uses an in-memory fake S3)."""

from __future__ import annotations

import gzip
from datetime import UTC, datetime
from typing import Any

import nacl.signing
import orjson
import pytest

from ai_audit.backends.s3 import S3ArchiveBackend
from ai_audit.batch import BatchSeal
from ai_audit.models import DecisionReceipt


class _FakePaginator:
    def __init__(self, store: dict[str, bytes]) -> None:
        self._store = store

    def paginate(self, *, Bucket: str, Prefix: str = "", Delimiter: str | None = None):  # noqa: N803
        keys = sorted(k for k in self._store if k.startswith(Prefix))
        if Delimiter:
            seen: set[str] = set()
            common: list[dict[str, str]] = []
            for k in keys:
                rest = k[len(Prefix):]
                idx = rest.find(Delimiter)
                if idx >= 0:
                    cp = Prefix + rest[: idx + len(Delimiter)]
                    if cp not in seen:
                        seen.add(cp)
                        common.append({"Prefix": cp})
            yield {"CommonPrefixes": common, "Contents": []}
        else:
            yield {
                "Contents": [
                    {"Key": k, "LastModified": datetime.now(UTC).isoformat()} for k in keys
                ]
            }


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3Client:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **kw: Any) -> None:  # noqa: N803
        self.store[Key] = Body

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        if Key not in self.store:
            raise KeyError(Key)
        return {"Body": _FakeBody(self.store[Key])}

    def head_bucket(self, *, Bucket: str) -> None:  # noqa: N803
        pass

    def get_paginator(self, op: str) -> _FakePaginator:
        return _FakePaginator(self.store)


@pytest.fixture
def backend() -> S3ArchiveBackend:
    return S3ArchiveBackend(bucket="test", prefix="aud", client=_FakeS3Client())


def _make_receipt(tenant: str, idx: int) -> DecisionReceipt:
    sk = nacl.signing.SigningKey.generate()
    r = DecisionReceipt(tenant_id=tenant, trace_id=f"t-{idx}")
    r.seal(sk)
    return r


def test_write_then_read_receipt(backend: S3ArchiveBackend) -> None:
    r = _make_receipt("acme", 1)
    backend.write_receipt(r)
    fetched = backend.read_receipt(r.receipt_id)
    assert fetched is not None
    assert fetched.receipt_id == r.receipt_id
    assert fetched.tenant_id == "acme"


def test_query_by_tenant_returns_only_that_tenant(backend: S3ArchiveBackend) -> None:
    backend.write_receipt(_make_receipt("acme", 1))
    backend.write_receipt(_make_receipt("acme", 2))
    backend.write_receipt(_make_receipt("other", 3))
    acme = backend.query_by_tenant("acme")
    assert len(acme) == 2
    assert all(r.tenant_id == "acme" for r in acme)


def test_batch_seal_round_trip(backend: S3ArchiveBackend) -> None:
    seal = BatchSeal(
        batch_id="b1",
        tenant_id="acme",
        merkle_root="aa" * 32,
        leaf_count=10,
        prev_batch_root="",
        timestamp=datetime.now(UTC).isoformat(),
        receipt_ids=["r1", "r2"],
        signature="bb" * 32,
    )
    backend.write_batch_seal(seal)
    fetched = backend.read_batch_seal("b1")
    assert fetched is not None
    assert fetched.merkle_root == seal.merkle_root
    assert fetched.receipt_ids == ["r1", "r2"]


def test_healthcheck_ok(backend: S3ArchiveBackend) -> None:
    assert backend.healthcheck() is True


def test_payload_is_gzipped(backend: S3ArchiveBackend) -> None:
    r = _make_receipt("acme", 1)
    backend.write_receipt(r)
    raw = next(iter(backend._client.store.values()))  # type: ignore[attr-defined]
    decompressed = gzip.decompress(raw)
    parsed = orjson.loads(decompressed)
    assert parsed["receipt_id"] == r.receipt_id
