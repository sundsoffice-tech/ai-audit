"""Tests for ai_audit.kms.* (Vault + AWS) — uses fakes, no live network."""

from __future__ import annotations

import base64
import json
from typing import Any

import nacl.signing
import pytest

from ai_audit.kms.aws import AWSKMSKeyProvider, AWSSecretsManagerKeyProvider
from ai_audit.kms.vault import VaultKeyProvider


def _make_seed_hex() -> str:
    return nacl.signing.SigningKey.generate().encode().hex()


# --- Vault ---

class _FakeKVv2:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def read_secret_version(self, *, path: str, mount_point: str) -> dict[str, Any]:
        return {"data": {"data": self._payload}}


class _FakeKV:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.v2 = _FakeKVv2(payload)


class _FakeSecrets:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.kv = _FakeKV(payload)


class _FakeVault:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.secrets = _FakeSecrets(payload)


def test_vault_provider_loads_seed() -> None:
    seed_hex = _make_seed_hex()
    client = _FakeVault({"seed_hex": seed_hex})
    provider = VaultKeyProvider(client=client, path="ai-audit/key")  # type: ignore[arg-type]
    sk = provider.get_signing_key()
    assert sk.encode().hex() == seed_hex
    # caching: second call returns same instance
    assert provider.get_signing_key() is sk


def test_vault_provider_rejects_bad_secret_shape() -> None:
    client = _FakeVault({"wrong_field": "abc"})
    provider = VaultKeyProvider(client=client, path="ai-audit/key")  # type: ignore[arg-type]
    with pytest.raises(RuntimeError):
        provider.get_signing_key()


def test_vault_provider_rotate_forces_reload() -> None:
    seed_a, seed_b = _make_seed_hex(), _make_seed_hex()
    client = _FakeVault({"seed_hex": seed_a})
    provider = VaultKeyProvider(client=client, path="ai-audit/key")  # type: ignore[arg-type]
    assert provider.get_signing_key().encode().hex() == seed_a
    client.secrets.kv.v2 = _FakeKVv2({"seed_hex": seed_b})
    provider.rotate()
    assert provider.get_signing_key().encode().hex() == seed_b


# --- AWS Secrets Manager ---

class _FakeSecretsManager:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    def get_secret_value(self, *, SecretId: str) -> dict[str, Any]:  # noqa: N803
        return {"SecretString": self._payload}


def test_secrets_manager_plain_hex() -> None:
    seed_hex = _make_seed_hex()
    fake = _FakeSecretsManager(seed_hex)
    provider = AWSSecretsManagerKeyProvider(secret_id="x", client=fake)
    assert provider.get_signing_key().encode().hex() == seed_hex


def test_secrets_manager_json_payload() -> None:
    seed_hex = _make_seed_hex()
    fake = _FakeSecretsManager(json.dumps({"seed_hex": seed_hex}))
    provider = AWSSecretsManagerKeyProvider(secret_id="x", client=fake)
    assert provider.get_signing_key().encode().hex() == seed_hex


def test_secrets_manager_rejects_bad_length() -> None:
    fake = _FakeSecretsManager("deadbeef")
    provider = AWSSecretsManagerKeyProvider(secret_id="x", client=fake)
    with pytest.raises(RuntimeError):
        provider.get_signing_key()


# --- AWS KMS envelope ---

class _FakeKMS:
    def __init__(self, plaintext: bytes) -> None:
        self._plaintext = plaintext

    def decrypt(self, **kw: Any) -> dict[str, bytes]:
        return {"Plaintext": self._plaintext, "KeyId": kw["KeyId"]}


def test_kms_envelope_decrypt() -> None:
    seed = nacl.signing.SigningKey.generate().encode()
    fake = _FakeKMS(seed)
    provider = AWSKMSKeyProvider(
        kms_key_id="alias/x",
        encrypted_seed_b64=base64.b64encode(b"<ciphertext>").decode(),
        client=fake,
    )
    assert provider.get_signing_key().encode() == seed


def test_kms_envelope_rejects_wrong_size() -> None:
    fake = _FakeKMS(b"too short")
    provider = AWSKMSKeyProvider(
        kms_key_id="alias/x",
        encrypted_seed_b64=base64.b64encode(b"x").decode(),
        client=fake,
    )
    with pytest.raises(RuntimeError):
        provider.get_signing_key()
