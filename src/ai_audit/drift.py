"""
ai_audit.drift — Drift Detection via Jensen-Shannon Divergence.

Monitors action distribution changes over sliding windows to detect
when an AI system's behaviour drifts from its baseline. Pure-Python
implementation — no scipy/numpy required.

Thresholds (configurable):
- ``> 0.05``: ``DRIFTING`` — behaviour shift detected, investigate
- ``> 0.15``: ``CRITICAL_DRIFT`` — significant divergence, alert

Usage::

    from ai_audit.drift import DriftMonitor

    monitor = DriftMonitor(window_size=100)
    for receipt in receipts:
        state = monitor.update(receipt.action.value)
    print(state.status, state.drift_score)

NB ee9616a5 (CHEF) validated — 2026-04-16.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class DriftState:
    """Snapshot of the drift monitor.

    Attributes:
        drift_score:     Jensen-Shannon Divergence (0.0–1.0).
        status:          ``STABLE`` | ``DRIFTING`` | ``CRITICAL_DRIFT``.
        window_size:     Current window size.
        baseline_dist:   Baseline action distribution.
        current_dist:    Current window action distribution.
        updated_at:      ISO 8601 timestamp.
    """

    drift_score: float = 0.0
    status: str = "STABLE"
    window_size: int = 0
    baseline_dist: dict[str, float] | None = None
    current_dist: dict[str, float] | None = None
    updated_at: str = ""


def _kl_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Kullback-Leibler divergence D_KL(P || Q).

    Uses a small epsilon to avoid log(0).
    """
    eps = 1e-10
    all_keys = set(p) | set(q)
    return sum(
        p.get(k, eps) * math.log(p.get(k, eps) / q.get(k, eps))
        for k in all_keys
    )


def _jensen_shannon_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Jensen-Shannon Divergence (symmetric, bounded [0, 1]).

    JSD(P, Q) = 0.5 * D_KL(P || M) + 0.5 * D_KL(Q || M)
    where M = 0.5 * (P + Q)
    """
    all_keys = set(p) | set(q)
    m: dict[str, float] = {}
    for k in all_keys:
        m[k] = 0.5 * (p.get(k, 0.0) + q.get(k, 0.0))

    return 0.5 * _kl_divergence(p, m) + 0.5 * _kl_divergence(q, m)


def _counts_to_distribution(counts: Counter[str]) -> dict[str, float]:
    """Normalise a Counter into a probability distribution."""
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: v / total for k, v in counts.items()}


class DriftMonitor:
    """Online drift monitor using Jensen-Shannon Divergence.

    Compares a rolling window of recent actions against a frozen baseline.
    The baseline is established from the first ``window_size`` observations.

    Parameters:
        window_size:       Size of the sliding window (default: 100).
        drift_threshold:   JSD above this = DRIFTING (default: 0.05).
        critical_threshold: JSD above this = CRITICAL_DRIFT (default: 0.15).
    """

    def __init__(
        self,
        *,
        window_size: int = 100,
        drift_threshold: float = 0.05,
        critical_threshold: float = 0.15,
    ) -> None:
        self._window_size = window_size
        self._drift_threshold = drift_threshold
        self._critical_threshold = critical_threshold
        self._window: deque[str] = deque(maxlen=window_size)
        self._baseline: Counter[str] = Counter()
        self._baseline_frozen = False
        self._total_observations = 0

    def update(self, action: str) -> DriftState:
        """Add an observation and return the updated drift state.

        Parameters:
            action: The action string (e.g. "allow", "reject", "escalate").

        Returns:
            Updated :class:`DriftState`.
        """
        self._total_observations += 1
        self._window.append(action)

        # Freeze baseline after first full window
        if not self._baseline_frozen:
            self._baseline[action] += 1
            if self._total_observations >= self._window_size:
                self._baseline_frozen = True
            return self.state

        return self.state

    @property
    def state(self) -> DriftState:
        """Current drift state."""
        if not self._baseline_frozen or len(self._window) < self._window_size:
            return DriftState(
                drift_score=0.0,
                status="STABLE",
                window_size=len(self._window),
                updated_at=datetime.now(UTC).isoformat(),
            )

        baseline_dist = _counts_to_distribution(self._baseline)
        current_counts = Counter(self._window)
        current_dist = _counts_to_distribution(current_counts)

        jsd = _jensen_shannon_divergence(baseline_dist, current_dist)

        if jsd > self._critical_threshold:
            status = "CRITICAL_DRIFT"
        elif jsd > self._drift_threshold:
            status = "DRIFTING"
        else:
            status = "STABLE"

        return DriftState(
            drift_score=jsd,
            status=status,
            window_size=len(self._window),
            baseline_dist=baseline_dist,
            current_dist=current_dist,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def reset_baseline(self) -> None:
        """Freeze the current window as the new baseline."""
        self._baseline = Counter(self._window)
        self._baseline_frozen = True
