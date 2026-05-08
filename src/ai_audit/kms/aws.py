"""AWS KMS / Secrets Manager KeyProvider.

AWS KMS does not export raw private key material, so this provider supports the
two production-realistic patterns:

1. **Secrets Manager** (simplest): the Ed25519 seed (hex) is stored as a
   secret. KMS-at-rest encryption is handled transparently by AWS.

2. **KMS Envelope** (most secure): the Ed25519 seed is wrapped with a
   customer-managed KMS key. The ciphertext blob is provided at startup;
   the provider calls ``kms:Decrypt`` to recover the seed.

Usage — Secrets Manager::

    from ai_audit.kms.aws import AWSSecretsManagerKeyProvider
    from ai_audit import init_key_provider

    provider = AWSSecretsManagerKeyProvider(
        secret_id="prod/ai-audit/signing-seed",
        region_name="us-east-1",
        seed_field="seed_hex",
    )
    init_key_provider(provider)

Usage — KMS envelope::

    from ai_audit.kms.aws import AWSKMSKeyProvider
    provider = AWSKMSKeyProvider(
        kms_key_id="alias/ai-audit",
        encrypted_seed_b64="<base64-of-kms-ciphertext-blob>",
        region_name="us-east-1",
    )
    init_key_provider(provider)

Optional dep: ``pip install boto3``.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from typing import TYPE_CHECKING, Any

import nacl.signing

from ai_audit.keys import KeyProvider

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _import_boto3() -> Any:
    try:
        import boto3
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "AWS KMS providers require 'boto3'. "
            "Install with: pip install ai-audit-trail[aws-kms]"
        ) from e
    return boto3


class AWSKMSKeyProvider(KeyProvider):
    """KeyProvider that decrypts an envelope-wrapped Ed25519 seed via AWS KMS.

    Parameters:
        kms_key_id:         KMS key ARN, ID, or alias used to decrypt the seed.
        encrypted_seed_b64: Base64-encoded KMS ciphertext blob (output of
                            ``kms:Encrypt`` over the 32-byte Ed25519 seed).
        region_name:        AWS region (or rely on default boto3 config).
        client:             Optional pre-built boto3 KMS client (overrides
                            ``region_name``).
        encryption_context: Optional KMS encryption context (must match the
                            value used at encrypt time).
    """

    def __init__(
        self,
        *,
        kms_key_id: str,
        encrypted_seed_b64: str,
        region_name: str | None = None,
        client: Any | None = None,
        encryption_context: dict[str, str] | None = None,
    ) -> None:
        self._kms_key_id = kms_key_id
        self._encrypted_seed = base64.b64decode(encrypted_seed_b64)
        self._region_name = region_name
        self._client = client
        self._encryption_context = encryption_context
        self._key: nacl.signing.SigningKey | None = None
        self._lock = threading.Lock()

    def _ensure_client(self) -> Any:
        if self._client is None:
            boto3 = _import_boto3()
            kwargs: dict[str, Any] = {}
            if self._region_name:
                kwargs["region_name"] = self._region_name
            self._client = boto3.client("kms", **kwargs)
        return self._client

    def _load(self) -> nacl.signing.SigningKey:
        with self._lock:
            if self._key is None:
                client = self._ensure_client()
                kwargs: dict[str, Any] = {
                    "CiphertextBlob": self._encrypted_seed,
                    "KeyId": self._kms_key_id,
                }
                if self._encryption_context:
                    kwargs["EncryptionContext"] = self._encryption_context
                resp = client.decrypt(**kwargs)
                seed = resp["Plaintext"]
                if len(seed) != 32:
                    raise RuntimeError(
                        f"KMS-decrypted seed must be 32 bytes, got {len(seed)}"
                    )
                self._key = nacl.signing.SigningKey(seed)
                logger.info("AWSKMSKeyProvider: signing key decrypted via KMS %s", self._kms_key_id)
            return self._key

    def get_signing_key(self) -> nacl.signing.SigningKey:
        return self._load()

    def get_verify_key_hex(self) -> str:
        return self._load().verify_key.encode().hex()

    def rotate(self) -> None:
        with self._lock:
            self._key = None


class AWSSecretsManagerKeyProvider(KeyProvider):
    """KeyProvider that reads the Ed25519 seed from AWS Secrets Manager.

    The secret may be a plain hex string or a JSON object with a ``seed_field``.

    Parameters:
        secret_id:    The secret ID/ARN.
        region_name:  AWS region.
        seed_field:   If the secret is JSON, the field containing the hex seed.
                      Default ``"seed_hex"``. If the secret is a plain string,
                      this is ignored.
        client:       Optional pre-built boto3 secretsmanager client.
    """

    def __init__(
        self,
        *,
        secret_id: str,
        region_name: str | None = None,
        seed_field: str = "seed_hex",
        client: Any | None = None,
    ) -> None:
        self._secret_id = secret_id
        self._region_name = region_name
        self._seed_field = seed_field
        self._client = client
        self._key: nacl.signing.SigningKey | None = None
        self._lock = threading.Lock()

    def _ensure_client(self) -> Any:
        if self._client is None:
            boto3 = _import_boto3()
            kwargs: dict[str, Any] = {}
            if self._region_name:
                kwargs["region_name"] = self._region_name
            self._client = boto3.client("secretsmanager", **kwargs)
        return self._client

    def _fetch_seed_hex(self) -> str:
        client = self._ensure_client()
        resp = client.get_secret_value(SecretId=self._secret_id)
        raw = resp.get("SecretString")
        if raw is None:
            raise RuntimeError(f"Secret {self._secret_id} has no SecretString payload")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            seed_hex = raw.strip()
        else:
            seed_hex = data.get(self._seed_field, "") if isinstance(data, dict) else ""
        if not isinstance(seed_hex, str) or len(seed_hex) != 64:
            raise RuntimeError(
                f"Secrets Manager value must be a 64-char hex string (or JSON with '{self._seed_field}')"
            )
        return seed_hex

    def _load(self) -> nacl.signing.SigningKey:
        with self._lock:
            if self._key is None:
                self._key = nacl.signing.SigningKey(bytes.fromhex(self._fetch_seed_hex()))
                logger.info(
                    "AWSSecretsManagerKeyProvider: signing key loaded from %s", self._secret_id
                )
            return self._key

    def get_signing_key(self) -> nacl.signing.SigningKey:
        return self._load()

    def get_verify_key_hex(self) -> str:
        return self._load().verify_key.encode().hex()

    def rotate(self) -> None:
        with self._lock:
            self._key = None


__all__ = ["AWSKMSKeyProvider", "AWSSecretsManagerKeyProvider"]
