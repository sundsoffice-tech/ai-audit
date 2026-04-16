"""
ai_audit.sprt — Online/Streaming Sequential Probability Ratio Test (SPRT).

Unlike the batch SPRT in ``dashboard.py`` which recomputes over all receipts,
this module provides an incremental ``SPRTMonitor`` that advances the test
with each new receipt — O(1) per update instead of O(N) per query.

Usage::

    from ai_audit.sprt import SPRTMonitor

    monitor = SPRTMonitor(tenant_id="acme")
    monitor.update(is_reject=False)
    monitor.update(is_reject=False)
    monitor.update(is_reject=True)
    print(monitor.state)  # SPRTState(status='MONITORING', ...)

The monitor converges to the same result as ``build_compliance_summary()``
but without reprocessing the entire history.

NB ee9616a5 (CHEF) validated — 2026-04-16.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime

# SPRT parameters (must match dashboard.py for consistency)
_P0 = 0.05   # Null hypothesis: reject rate <= 5%
_P1 = 0.15   # Alternative hypothesis: reject rate >= 15%
_ALPHA = 0.05  # False positive rate
_BETA = 0.10   # False negative rate
_MIN_SAMPLES = 10

# Precomputed boundaries
_LOWER_BOUND = math.log(_BETA / (1 - _ALPHA))
_UPPER_BOUND = math.log((1 - _BETA) / _ALPHA)

# Precomputed per-observation log-likelihood ratios
_LLR_REJECT = math.log(_P1 / max(_P0, 1e-10))
_LLR_ACCEPT = math.log((1 - _P1) / max(1 - _P0, 1e-10))


@dataclass
class SPRTState:
    """Immutable snapshot of a running SPRT.

    Attributes:
        tenant_id:   Tenant this monitor tracks.
        llr:         Cumulative log-likelihood ratio.
        n:           Total observations.
        rejects:     Total reject/escalate observations.
        status:      ``CERTIFIED`` | ``MONITORING`` | ``FLAGGED``.
        confidence:  Compliance confidence (1.0 - reject_rate).
        updated_at:  ISO timestamp of last update.
    """

    tenant_id: str = ""
    llr: float = 0.0
    n: int = 0
    rejects: int = 0
    status: str = "MONITORING"
    confidence: float = 1.0
    updated_at: str = ""


class SPRTMonitor:
    """Online SPRT monitor for a single tenant.

    Each call to :meth:`update` advances the test by one observation.
    The monitor is serialisable via :meth:`state` / :meth:`from_state`
    for persistence across restarts.

    Parameters:
        tenant_id:  Tenant identifier.
        p0:         Null hypothesis reject rate (default: 0.05).
        p1:         Alternative hypothesis reject rate (default: 0.15).
        alpha:      False positive rate (default: 0.05).
        beta:       False negative rate (default: 0.10).
        min_samples: Minimum observations before SPRT kicks in.
    """

    def __init__(
        self,
        tenant_id: str = "",
        *,
        p0: float = _P0,
        p1: float = _P1,
        alpha: float = _ALPHA,
        beta: float = _BETA,
        min_samples: int = _MIN_SAMPLES,
    ) -> None:
        self._tenant_id = tenant_id
        self._p0 = p0
        self._p1 = p1
        self._min_samples = min_samples
        self._lower = math.log(beta / (1 - alpha))
        self._upper = math.log((1 - beta) / alpha)
        self._llr_reject = math.log(p1 / max(p0, 1e-10))
        self._llr_accept = math.log((1 - p1) / max(1 - p0, 1e-10))

        self._llr: float = 0.0
        self._n: int = 0
        self._rejects: int = 0
        self._status: str = "MONITORING"

    def update(self, is_reject: bool) -> SPRTState:
        """Advance the SPRT by one observation.

        Parameters:
            is_reject: True if the receipt action was REJECT or ESCALATE.

        Returns:
            Updated :class:`SPRTState` snapshot.
        """
        self._n += 1
        if is_reject:
            self._rejects += 1
            self._llr += self._llr_reject
        else:
            self._llr += self._llr_accept

        if self._n < self._min_samples:
            self._status = "MONITORING"
        elif self._llr <= self._lower:
            self._status = "CERTIFIED"
        elif self._llr >= self._upper:
            self._status = "FLAGGED"
        else:
            self._status = "MONITORING"

        return self.state

    @property
    def state(self) -> SPRTState:
        """Return an immutable snapshot of the current SPRT state."""
        reject_rate = self._rejects / max(self._n, 1)
        return SPRTState(
            tenant_id=self._tenant_id,
            llr=self._llr,
            n=self._n,
            rejects=self._rejects,
            status=self._status,
            confidence=1.0 - reject_rate,
            updated_at=datetime.now(UTC).isoformat(),
        )

    @classmethod
    def from_state(cls, state: SPRTState) -> SPRTMonitor:
        """Restore a monitor from a persisted :class:`SPRTState`.

        This allows the SPRT to survive process restarts by loading the
        last-known state from Redis, a database, or a file.
        """
        monitor = cls(tenant_id=state.tenant_id)
        monitor._llr = state.llr
        monitor._n = state.n
        monitor._rejects = state.rejects
        monitor._status = state.status
        return monitor

    def reset(self) -> None:
        """Reset the monitor to initial state (e.g. for a new epoch)."""
        self._llr = 0.0
        self._n = 0
        self._rejects = 0
        self._status = "MONITORING"
