"""HashiCorp Vault KeyProvider.

Reads the Ed25519 seed (32 bytes, hex-encoded) from a KV-v2 secret in Vault.
The seed is cached in memory after the first read; pass ``refresh=True`` to
``rotate()`` to force a re-read on next call.

Usage::

    import hvac
    from ai_audit.kms.vault import VaultKeyProvider
    from ai_audit import init_key_provider

    vault = hvac.Client(url="https://vault:8200", token="<token>")
    provider = VaultKeyProvider(
        client=vault,
        path="ai-audit/signing-key",   # KV-v2 path
        mount_point="secret",
        seed_field="seed_hex",
    )
    init_key_provider(provider)

The secret is expected to look like::

    {"seed_hex": "<64-character hex string>"}

Optional dep: ``pip install hvac``.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

import nacl.signing

from ai_audit.keys import KeyProvider

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class VaultKeyProvider(KeyProvider):
    """KeyProvider backed by HashiCorp Vault KV-v2.

    Parameters:
        client:       Initialised ``hvac.Client`` (auth must already be done).
        path:         KV-v2 secret path (without the mount point).
        mount_point:  KV-v2 mount; default ``"secret"``.
        seed_field:   Key inside the secret data containing the hex seed.
                      Default ``"seed_hex"``.
    """

    def __init__(
        self,
        *,
        client: Any | None = None,
        path: str,
        mount_point: str = "secret",
        seed_field: str = "seed_hex",
        url: str | None = None,
        token: str | None = None,
    ) -> None:
        if client is None:
            try:
                import hvac
            except ImportError as e:  # pragma: no cover
                raise ImportError(
                    "VaultKeyProvider requires 'hvac'. "
                    "Install with: pip install ai-audit-trail[vault]"
                ) from e
            if url is None:
                raise ValueError("Provide either 'client' or 'url'.")
            client = hvac.Client(url=url, token=token)

        self._client = client
        self._path = path
        self._mount_point = mount_point
        self._seed_field = seed_field
        self._key: nacl.signing.SigningKey | None = None
        self._lock = threading.Lock()

    def _fetch_seed_hex(self) -> str:
        secret = self._client.secrets.kv.v2.read_secret_version(
            path=self._path, mount_point=self._mount_point
        )
        try:
            data: dict[str, Any] = secret["data"]["data"]
        except (KeyError, TypeError) as e:
            raise RuntimeError(
                f"Vault secret at {self._mount_point}/{self._path} has unexpected shape"
            ) from e
        seed_hex = data.get(self._seed_field)
        if not isinstance(seed_hex, str) or len(seed_hex) != 64:
            raise RuntimeError(
                f"Vault secret field '{self._seed_field}' must be a 64-char hex string"
            )
        return seed_hex

    def _load(self) -> nacl.signing.SigningKey:
        with self._lock:
            if self._key is None:
                seed_hex = self._fetch_seed_hex()
                self._key = nacl.signing.SigningKey(bytes.fromhex(seed_hex))
                logger.info(
                    "VaultKeyProvider: signing key loaded from %s/%s",
                    self._mount_point, self._path,
                )
            return self._key

    def get_signing_key(self) -> nacl.signing.SigningKey:
        return self._load()

    def get_verify_key_hex(self) -> str:
        return self._load().verify_key.encode().hex()

    def rotate(self) -> None:
        """Force a re-read of the secret on the next ``get_signing_key`` call."""
        with self._lock:
            self._key = None


__all__ = ["VaultKeyProvider"]
