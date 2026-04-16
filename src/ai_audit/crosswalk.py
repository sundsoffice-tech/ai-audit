"""
ai_audit.crosswalk — ISO 42001 / NIST AI RMF Compliance Mapping.

Translates technical audit data (hashes, scores, actions) into
recognised management controls so external auditors can map
Decision Receipts directly to compliance frameworks.

Supported frameworks:
- **ISO/IEC 42001:2023** — AI Management System
- **NIST AI RMF 1.0** — AI Risk Management Framework

Usage::

    from ai_audit.crosswalk import build_crosswalk, nist_function_map

    crosswalk = build_crosswalk(receipts, chain_intact=True)
    for entry in crosswalk:
        print(f"{entry.framework} {entry.control_id}: {entry.status}")

    nist = nist_function_map(receipts)
    print(nist["GOVERN"])  # List of evidence entries

NB 409cad95 (Enterprise) validated — 2026-04-16.
NB ee9616a5 (CHEF) correction: evidence_pointers field added.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ai_audit.models import DecisionReceipt, ReceiptAction


class ControlStatus(StrEnum):
    """Compliance control evaluation status."""

    PASS = "PASS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    NOT_APPLICABLE = "N/A"


@dataclass
class ComplianceCrosswalk:
    """A single compliance control mapping.

    Attributes:
        framework:        Standard name (e.g. "ISO 42001", "NIST AI RMF").
        control_id:       Control identifier (e.g. "A.6.2.8", "GOVERN-1.1").
        control_name:     Human-readable control name.
        description:      What this control requires.
        evidence_fields:  Which receipt fields provide evidence.
        evidence_pointers: Specific receipt_ids or epoch_ids that demonstrate compliance.
        coverage:         Percentage of evidence available (0.0–1.0).
        status:           PASS / PARTIAL / FAIL / N/A.
        notes:            Additional auditor notes.
    """

    framework: str = ""
    control_id: str = ""
    control_name: str = ""
    description: str = ""
    evidence_fields: list[str] = field(default_factory=list)
    evidence_pointers: list[str] = field(default_factory=list)
    coverage: float = 0.0
    status: ControlStatus = ControlStatus.NOT_APPLICABLE
    notes: str = ""


def _evaluate_coverage(receipts: list[DecisionReceipt], required_fields: list[str]) -> float:
    """Calculate what fraction of receipts have non-empty values for required fields."""
    if not receipts:
        return 0.0
    filled = 0
    for r in receipts:
        data = r.model_dump()
        if all(data.get(f) for f in required_fields):
            filled += 1
    return filled / len(receipts)


def _collect_evidence_pointers(receipts: list[DecisionReceipt], limit: int = 10) -> list[str]:
    """Collect a sample of receipt_ids as evidence pointers."""
    sorted_receipts = sorted(receipts, key=lambda r: r.timestamp)
    # First, last, and evenly spaced samples
    if len(sorted_receipts) <= limit:
        return [r.receipt_id for r in sorted_receipts]
    step = max(1, len(sorted_receipts) // limit)
    return [sorted_receipts[i].receipt_id for i in range(0, len(sorted_receipts), step)][:limit]


# ---------------------------------------------------------------------------
# ISO/IEC 42001:2023 Controls
# ---------------------------------------------------------------------------

def _iso_a628(receipts: list[DecisionReceipt], chain_intact: bool) -> ComplianceCrosswalk:
    """A.6.2.8 — Logging of AI system activities."""
    coverage = 1.0 if receipts else 0.0
    has_hashes = all(r.receipt_hash for r in receipts) if receipts else False
    has_sigs = all(r.signature for r in receipts) if receipts else False

    status = ControlStatus.PASS if (coverage > 0 and has_hashes and has_sigs and chain_intact) else (
        ControlStatus.PARTIAL if coverage > 0 else ControlStatus.FAIL
    )

    return ComplianceCrosswalk(
        framework="ISO 42001",
        control_id="A.6.2.8",
        control_name="Logging of AI system activities",
        description="The organization shall log AI system activities to support traceability and accountability.",
        evidence_fields=["receipt_hash", "signature", "timestamp", "action"],
        evidence_pointers=_collect_evidence_pointers(receipts),
        coverage=coverage,
        status=status,
        notes=f"Chain intact: {chain_intact}. {len(receipts)} receipts with Ed25519 signatures.",
    )


def _iso_a75(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """A.7.5 — Data provenance."""
    coverage = _evaluate_coverage(receipts, ["input_c14n", "output_hash"])
    status = ControlStatus.PASS if coverage >= 0.9 else (
        ControlStatus.PARTIAL if coverage > 0 else ControlStatus.FAIL
    )

    return ComplianceCrosswalk(
        framework="ISO 42001",
        control_id="A.7.5",
        control_name="Data provenance",
        description="The organization shall maintain records of data provenance for AI system inputs and outputs.",
        evidence_fields=["input_c14n", "output_hash", "state_digest"],
        evidence_pointers=_collect_evidence_pointers(receipts),
        coverage=coverage,
        status=status,
        notes=f"{coverage:.0%} of receipts have input/output hashes.",
    )


def _iso_a626(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """A.6.2.6 — AI system performance evaluation."""
    has_checks = [r for r in receipts if r.checks]
    coverage = len(has_checks) / len(receipts) if receipts else 0.0
    status = ControlStatus.PASS if coverage >= 0.8 else (
        ControlStatus.PARTIAL if coverage > 0 else ControlStatus.FAIL
    )

    return ComplianceCrosswalk(
        framework="ISO 42001",
        control_id="A.6.2.6",
        control_name="AI system performance evaluation",
        description="The organization shall evaluate AI system performance including quality checks.",
        evidence_fields=["checks", "action", "reason_codes"],
        evidence_pointers=_collect_evidence_pointers(has_checks),
        coverage=coverage,
        status=status,
        notes=f"{len(has_checks)}/{len(receipts)} receipts include check records.",
    )


def _iso_a84(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """A.8.4 — AI system output controls."""
    reject_count = sum(1 for r in receipts if r.action in (ReceiptAction.REJECT, ReceiptAction.ESCALATE))
    coverage = 1.0 if receipts else 0.0
    status = ControlStatus.PASS if coverage > 0 else ControlStatus.FAIL

    return ComplianceCrosswalk(
        framework="ISO 42001",
        control_id="A.8.4",
        control_name="AI system output controls",
        description="The organization shall implement controls for AI system outputs.",
        evidence_fields=["action", "reason_codes", "nist_tags"],
        evidence_pointers=_collect_evidence_pointers(receipts),
        coverage=coverage,
        status=status,
        notes=f"{reject_count} outputs rejected/escalated out of {len(receipts)}.",
    )


def _iso_a53(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """A.5.3 — AI risk assessment."""
    has_nist = [r for r in receipts if r.nist_tags]
    coverage = len(has_nist) / len(receipts) if receipts else 0.0

    status = ControlStatus.PASS if coverage >= 0.5 else (
        ControlStatus.PARTIAL if coverage > 0 else ControlStatus.NOT_APPLICABLE
    )

    return ComplianceCrosswalk(
        framework="ISO 42001",
        control_id="A.5.3",
        control_name="AI risk assessment",
        description="The organization shall conduct AI risk assessments with documented evidence.",
        evidence_fields=["nist_tags", "checks", "reason_codes"],
        evidence_pointers=_collect_evidence_pointers(has_nist),
        coverage=coverage,
        status=status,
        notes=f"{len(has_nist)} receipts tagged with NIST risk categories.",
    )


# ---------------------------------------------------------------------------
# NIST AI RMF 1.0 Functions
# ---------------------------------------------------------------------------

def _nist_govern(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """GOVERN — Policies, accountability, and oversight."""
    has_config = [r for r in receipts if r.config_digest]
    coverage = len(has_config) / len(receipts) if receipts else 0.0

    return ComplianceCrosswalk(
        framework="NIST AI RMF",
        control_id="GOVERN",
        control_name="Governance and accountability",
        description="Establish policies, accountability structures, and culture for AI risk management.",
        evidence_fields=["config_digest", "nist_tags", "tenant_id"],
        evidence_pointers=_collect_evidence_pointers(receipts),
        coverage=coverage,
        status=ControlStatus.PASS if coverage >= 0.5 else ControlStatus.PARTIAL,
        notes=f"{len(has_config)} receipts include config_digest (governance traceability).",
    )


def _nist_map(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """MAP — Context and risk identification."""
    has_model = [r for r in receipts if r.model_id]
    coverage = len(has_model) / len(receipts) if receipts else 0.0

    return ComplianceCrosswalk(
        framework="NIST AI RMF",
        control_id="MAP",
        control_name="Context and risk identification",
        description="Identify and document AI system context, capabilities, and risks.",
        evidence_fields=["model_id", "checks", "input_c14n"],
        evidence_pointers=_collect_evidence_pointers(has_model),
        coverage=coverage,
        status=ControlStatus.PASS if coverage >= 0.5 else ControlStatus.PARTIAL,
        notes=f"{len(has_model)} receipts include model provenance (model_id).",
    )


def _nist_measure(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """MEASURE — Quantitative assessment."""
    has_scores = [r for r in receipts if any(c.score > 0 for c in r.checks)]
    coverage = len(has_scores) / len(receipts) if receipts else 0.0

    return ComplianceCrosswalk(
        framework="NIST AI RMF",
        control_id="MEASURE",
        control_name="Quantitative risk measurement",
        description="Employ quantitative methods to analyze, assess, and track AI risks.",
        evidence_fields=["checks.score", "checks.threshold", "checks.fired"],
        evidence_pointers=_collect_evidence_pointers(has_scores),
        coverage=coverage,
        status=ControlStatus.PASS if coverage >= 0.5 else ControlStatus.PARTIAL,
        notes=f"{len(has_scores)} receipts include quantitative check scores (SPRT-eligible).",
    )


def _nist_manage(receipts: list[DecisionReceipt]) -> ComplianceCrosswalk:
    """MANAGE — Risk response and monitoring."""
    risk_actions = (ReceiptAction.REJECT, ReceiptAction.ESCALATE, ReceiptAction.FAIL_RETRY)
    managed = [r for r in receipts if r.action in risk_actions]
    coverage = 1.0 if receipts else 0.0

    return ComplianceCrosswalk(
        framework="NIST AI RMF",
        control_id="MANAGE",
        control_name="Risk response and monitoring",
        description="Manage AI risks through response strategies, action plans, and continuous monitoring.",
        evidence_fields=["action", "reason_codes", "nist_tags"],
        evidence_pointers=_collect_evidence_pointers(managed if managed else receipts),
        coverage=coverage,
        status=ControlStatus.PASS if receipts else ControlStatus.FAIL,
        notes=f"{len(managed)} risk-managed actions (reject/escalate/retry) out of {len(receipts)}.",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_crosswalk(
    receipts: list[DecisionReceipt],
    *,
    chain_intact: bool = True,
) -> list[ComplianceCrosswalk]:
    """Build a complete compliance crosswalk for ISO 42001 + NIST AI RMF.

    Parameters:
        receipts:      Decision Receipts to evaluate.
        chain_intact:  Whether the hash-chain is intact.

    Returns:
        List of :class:`ComplianceCrosswalk` entries covering all controls.
    """
    return [
        # ISO 42001
        _iso_a628(receipts, chain_intact),
        _iso_a75(receipts),
        _iso_a626(receipts),
        _iso_a84(receipts),
        _iso_a53(receipts),
        # NIST AI RMF
        _nist_govern(receipts),
        _nist_map(receipts),
        _nist_measure(receipts),
        _nist_manage(receipts),
    ]


def nist_function_map(
    receipts: list[DecisionReceipt],
) -> dict[str, ComplianceCrosswalk]:
    """Map receipts to NIST AI RMF functions.

    Returns:
        Dictionary keyed by function name (GOVERN, MAP, MEASURE, MANAGE).
    """
    return {
        "GOVERN": _nist_govern(receipts),
        "MAP": _nist_map(receipts),
        "MEASURE": _nist_measure(receipts),
        "MANAGE": _nist_manage(receipts),
    }
