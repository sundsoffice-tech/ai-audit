"""Anthropic Python SDK adapter — emits Decision Receipts for messages.create calls.

Usage::

    from ai_audit.integrations.anthropic import AuditedAnthropic

    client = AuditedAnthropic(store=store, tenant_id="acme")
    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )
    # receipt emitted automatically

Optional dep: ``pip install anthropic>=0.20``.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from ai_audit.collector import ReceiptCollector
from ai_audit.models import ReceiptAction
from ai_audit.pii import PiiConfig

if TYPE_CHECKING:
    from ai_audit.receipt_store import ReceiptStore

logger = logging.getLogger(__name__)


def _flatten_messages(messages: list[dict[str, Any]], system: str | None = None) -> str:
    parts: list[str] = []
    if system:
        parts.append(f"system: {system}")
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if isinstance(content, list):
            text_parts = [
                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
            ]
            content = "\n".join(text_parts)
        parts.append(f"{role}: {content}")
    return "\n".join(parts)


def _extract_response_text(response: Any) -> str:
    try:
        blocks = response.content or []
        text_parts: list[str] = []
        for b in blocks:
            text = getattr(b, "text", None)
            if text is None and isinstance(b, dict):
                text = b.get("text")
            if text:
                text_parts.append(str(text))
        return "\n".join(text_parts)
    except AttributeError:
        return ""


def _extract_stop_reason(response: Any) -> str:
    return str(getattr(response, "stop_reason", "") or "")


def emit_messages_receipt(
    store: ReceiptStore,
    *,
    tenant_id: str,
    model: str,
    messages: list[dict[str, Any]],
    response: Any,
    system: str | None = None,
    trace_id: str = "",
    session_id: str = "",
    pii_config: PiiConfig | None = None,
) -> str:
    """Emit one Receipt for an Anthropic messages.create call.

    Returns the emitted receipt_id.
    """
    collector = ReceiptCollector(
        trace_id=trace_id or uuid.uuid4().hex,
        tenant_id=tenant_id,
        session_id=session_id,
        model_id=model,
        pii_config=pii_config,
    )
    collector.set_input(_flatten_messages(messages, system))
    collector.set_output(_extract_response_text(response))

    stop = _extract_stop_reason(response)
    if stop:
        collector.add_reason(f"anthropic.stop_reason={stop}")
    if stop == "refusal":
        collector.set_action(ReceiptAction.REJECT)
    elif stop == "max_tokens":
        collector.set_action(ReceiptAction.ALLOW)
        collector.add_reason("truncated_by_length")
    else:
        collector.set_action(ReceiptAction.ALLOW)

    try:
        return collector.emit(store)
    finally:
        collector.cleanup()


class AuditedAnthropic:
    """Lazy proxy around an ``anthropic.Anthropic`` client that emits receipts.

    Usage::

        client = AuditedAnthropic(store=store, tenant_id="acme")
        response = client.messages.create(
            model="claude-opus-4-7", max_tokens=1024,
            messages=[{"role": "user", "content": "Hi"}],
        )
    """

    def __init__(
        self,
        *,
        store: ReceiptStore,
        tenant_id: str = "default",
        client: Any | None = None,
        pii_config: PiiConfig | None = None,
        **anthropic_kwargs: Any,
    ) -> None:
        if client is None:
            try:
                from anthropic import Anthropic
            except ImportError as e:  # pragma: no cover
                raise ImportError(
                    "AuditedAnthropic requires 'anthropic>=0.20'. "
                    "Install with: pip install ai-audit-trail[anthropic]"
                ) from e
            client = Anthropic(**anthropic_kwargs)

        self._client = client
        self._store = store
        self._tenant_id = tenant_id
        self._pii_config = pii_config
        self.messages = _AuditedMessages(self)

    @property
    def raw(self) -> Any:
        return self._client


class _AuditedMessages:
    def __init__(self, parent: AuditedAnthropic) -> None:
        self._parent = parent

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int = 1024,
        system: str | None = None,
        **kwargs: Any,
    ) -> Any:
        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **kwargs,
        }
        if system is not None:
            call_kwargs["system"] = system

        response = self._parent._client.messages.create(**call_kwargs)
        try:
            emit_messages_receipt(
                self._parent._store,
                tenant_id=self._parent._tenant_id,
                model=model,
                messages=messages,
                response=response,
                system=system,
                pii_config=self._parent._pii_config,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("AuditedAnthropic: emit failed: %s", exc)
        return response


__all__ = ["AuditedAnthropic", "emit_messages_receipt"]
