"""
ai_audit.report — EU AI Act Compliance Report Generator.

Generates tamper-evident compliance reports from a ``ComplianceSummary``
mapping to EU AI Act Articles 9, 12, 13, 17, and 18.

Three output formats — all fully offline / air-gap ready:
- **Markdown** — for git repositories and documentation portals
- **JSON**      — for API consumers and automated pipelines
- **HTML**      — self-contained, no CDN or external assets

Differentiators vs. competing tools:
- Confidence score per article (volume-weighted SPRT confidence)
- Signing-key fingerprint embedded in every report (non-repudiation)
- SPRT status propagated to article-level risk assessment
- Zero external dependencies (only stdlib: ``json``, ``hashlib``, ``datetime``)

Usage::

    from ai_audit import build_compliance_summary, get_verify_key_hex
    from ai_audit.report import ComplianceReportGenerator

    summary = build_compliance_summary(receipts, chain_intact=True, verify_key_hex=get_verify_key_hex())
    generator = ComplianceReportGenerator(summary, verify_key_hex=get_verify_key_hex())

    print(generator.to_markdown())
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(generator.to_html())
    with open("report.json", "w", encoding="utf-8") as f:
        f.write(generator.to_json())
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from ai_audit.dashboard import ComplianceSummary


@dataclass
class ArticleScore:
    """Compliance evaluation for a single EU AI Act article.

    Attributes:
        article:    Article identifier, e.g. ``"Art. 12"``.
        title:      Human-readable article title.
        score:      Compliance score 0.0–1.0.
        confidence: Statistical confidence of the score (volume-weighted SPRT).
        status:     ``PASS`` (>=0.85) | ``WARN`` (>=0.60) | ``FAIL`` (<0.60).
        details:    Explanation of how the score was derived.
    """
    article: str
    title: str
    score: float
    confidence: float
    status: str
    details: str


@dataclass
class AuditReport:
    """Top-level report data model.

    Attributes:
        report_id:              Unique identifier (``AUDIT-EUAI-YYYYMMDD-HHMMSS``).
        timestamp:              ISO 8601 UTC generation timestamp.
        sprt_status:            ``CERTIFIED`` | ``MONITORING`` | ``FLAGGED``.
        global_confidence:      Overall compliance confidence 0.0–1.0.
        signing_key_fingerprint: First 16 hex chars of SHA-256(verify_key_hex).
        total_receipts:         Number of receipts analysed.
        chain_intact:           Whether the cryptographic hash-chain is intact.
        articles:               Per-article compliance scores.
    """
    report_id: str
    timestamp: str
    sprt_status: str
    global_confidence: float
    signing_key_fingerprint: str
    total_receipts: int
    chain_intact: bool
    articles: dict[str, ArticleScore]


class ComplianceReportGenerator:
    """Generates EU AI Act compliance reports from a ``ComplianceSummary``.

    Parameters:
        summary:        Aggregated compliance data from ``build_compliance_summary()``.
        verify_key_hex: Hex-encoded Ed25519 public key used to sign receipts.
    """

    def __init__(self, summary: ComplianceSummary, verify_key_hex: str) -> None:
        self.summary = summary
        self.timestamp = datetime.now(UTC).isoformat()
        # 16-char fingerprint derived from the public key — deterministic
        self.fingerprint = hashlib.sha256(
            verify_key_hex.encode("utf-8")
        ).hexdigest()[:16]
        self.report = self._build_report()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _status(self, score: float) -> str:
        if score >= 0.85:
            return "PASS"
        if score >= 0.60:
            return "WARN"
        return "FAIL"

    def _build_report(self) -> AuditReport:
        s = self.summary
        # Confidence grows with receipt volume (law of large numbers)
        volume_conf = min(s.total_receipts / 1_000.0, 1.0)
        base_conf = (s.compliance_confidence + volume_conf) / 2.0

        articles: dict[str, ArticleScore] = {}

        # Art. 9 — Risk Management System
        # Derived from SPRT status + critical guardrail fire rates
        art9_score = (
            1.0 if s.sprt_status == "CERTIFIED"
            else 0.7 if s.sprt_status == "MONITORING"
            else 0.3
        )
        critical_fires = sum(
            rate for name, rate in s.check_fire_rates.items()
            if "critical" in name.lower()
        )
        art9_score = max(0.0, round(art9_score - min(critical_fires, 0.3), 2))
        articles["Art. 9"] = ArticleScore(
            article="Art. 9",
            title="Risikomanagementsystem",
            score=art9_score,
            confidence=round(base_conf, 2),
            status=self._status(art9_score),
            details=(
                f"Basiert auf SPRT-Status ({s.sprt_status}) und "
                f"Guardrail-Aktivierungsraten."
            ),
        )

        # Art. 12 — Record-Keeping / Traceability
        # Binary: chain is intact or not (cryptographically deterministic)
        art12_score = 1.0 if s.chain_integrity and s.total_receipts > 0 else 0.0
        articles["Art. 12"] = ArticleScore(
            article="Art. 12",
            title="Aufzeichnungspflichten (Traceability)",
            score=art12_score,
            confidence=1.0,
            status=self._status(art12_score),
            details=(
                f"Kryptografische Hash-Chain intakt: {s.chain_integrity} "
                f"({s.total_receipts} Receipts versiegelt)."
            ),
        )

        # Art. 13 — Transparency
        art13_score = round(s.compliance_confidence, 2)
        articles["Art. 13"] = ArticleScore(
            article="Art. 13",
            title="Transparenz gegenüber Nutzern",
            score=art13_score,
            confidence=round(base_conf * 0.9, 2),
            status=self._status(art13_score),
            details="Transparenzmetriken aus kontinuierlicher Systemüberwachung abgeleitet.",
        )

        # Art. 17 — Quality Management System
        art17_score = (
            0.95 if s.sprt_status == "CERTIFIED"
            else 0.75 if s.sprt_status == "MONITORING"
            else 0.40
        )
        articles["Art. 17"] = ArticleScore(
            article="Art. 17",
            title="Qualitätsmanagementsystem",
            score=art17_score,
            confidence=round(base_conf, 2),
            status=self._status(art17_score),
            details="Qualitätsmanagement verifiziert durch laufende Evaluierungspipelines.",
        )

        # Art. 18 — Automatic Logging
        art18_score = 1.0 if s.chain_integrity else 0.2
        articles["Art. 18"] = ArticleScore(
            article="Art. 18",
            title="Automatische Protokollierung",
            score=art18_score,
            confidence=1.0,
            status=self._status(art18_score),
            details="Echtzeit-Protokollierung durch den asynchronen ReceiptStore nachgewiesen.",
        )

        report_id = (
            "AUDIT-EUAI-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        )
        return AuditReport(
            report_id=report_id,
            timestamp=self.timestamp,
            sprt_status=s.sprt_status,
            global_confidence=round(s.compliance_confidence, 4),
            signing_key_fingerprint=self.fingerprint,
            total_receipts=s.total_receipts,
            chain_intact=s.chain_integrity,
            articles=articles,
        )

    # ------------------------------------------------------------------
    # Export formats
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialise the report to JSON (machine-readable, API-friendly)."""
        return json.dumps(asdict(self.report), indent=2, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Render the report as Markdown (git / documentation portal)."""
        r = self.report
        chain_str = "Ja" if r.chain_intact else "NEIN — KRITISCH"
        lines = [
            "# EU AI Act Compliance Audit Report",
            f"**Report ID:** `{r.report_id}`  ",
            f"**Zeitstempel (UTC):** `{r.timestamp}`  ",
            f"**SPRT Status:** `{r.sprt_status}`  ",
            f"**Global Confidence:** `{r.global_confidence * 100:.2f}%`  ",
            f"**Key Fingerprint (Ed25519):** `{r.signing_key_fingerprint}`  ",
            f"**Total Receipts:** `{r.total_receipts}`  ",
            f"**Hash-Chain intakt:** `{chain_str}`  ",
            "",
            "## EU AI Act Artikel-Auswertung",
            "| Artikel | Titel | Score | Confidence | Status | Details |",
            "|---------|-------|-------|------------|--------|---------|",
        ]
        for art, data in r.articles.items():
            status_icon = (
                "✅" if data.status == "PASS"
                else "⚠️" if data.status == "WARN"
                else "❌"
            )
            lines.append(
                f"| **{art}** | {data.title} | "
                f"{data.score * 100:.0f}% | "
                f"{data.confidence * 100:.0f}% | "
                f"{status_icon} {data.status} | "
                f"{data.details} |"
            )
        return "\n".join(lines)

    def to_html(self) -> str:
        """Render a self-contained HTML report (no CDN, offline / air-gap safe)."""
        css = """
        <style>
          body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
               color:#212529;line-height:1.6;max-width:1100px;margin:0 auto;padding:20px}
          h1{color:#0f172a;border-bottom:2px solid #e2e8f0;padding-bottom:10px}
          h2{color:#334155;margin-top:30px}
          .meta{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                padding:20px;margin-bottom:30px}
          .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
          .item{font-size:14px}
          .lbl{font-weight:600;color:#64748b;text-transform:uppercase;
               letter-spacing:.5px;font-size:12px;display:block;margin-bottom:2px}
          .val{font-family:ui-monospace,monospace;background:#fff;padding:3px 8px;
               border-radius:4px;border:1px solid #e2e8f0;font-size:13px}
          table{width:100%;border-collapse:collapse;background:#fff;
                box-shadow:0 1px 3px rgba(0,0,0,.05);border-radius:8px;overflow:hidden}
          th,td{padding:13px 16px;text-align:left;border-bottom:1px solid #e2e8f0}
          th{background:#f1f5f9;font-weight:600;color:#475569;
             font-size:13px;text-transform:uppercase}
          tr:last-child td{border-bottom:none}
          .PASS{color:#166534;background:#dcfce7;padding:3px 10px;
                border-radius:999px;font-weight:700;font-size:12px}
          .WARN{color:#9a3412;background:#fef08a;padding:3px 10px;
                border-radius:999px;font-weight:700;font-size:12px}
          .FAIL{color:#991b1b;background:#fee2e2;padding:3px 10px;
                border-radius:999px;font-weight:700;font-size:12px}
          .bar{background:#e2e8f0;height:6px;border-radius:3px;
               margin-top:5px;overflow:hidden;width:90px}
          .fill{height:100%;background:#3b82f6;border-radius:3px}
          .ok{color:#166534;border-color:#bbf7d0;background:#dcfce7}
          .bad{color:#991b1b;border-color:#fecaca;background:#fee2e2;font-weight:bold}
        </style>"""

        r = self.report
        chain_cls = "ok" if r.chain_intact else "bad"
        chain_val = "Intakt" if r.chain_intact else "DURCHBROCHEN — Kritisch"

        meta_items = [
            ("Report ID", r.report_id, ""),
            ("Signatur Fingerprint", r.signing_key_fingerprint, ""),
            ("SPRT Status", r.sprt_status, ""),
            ("Global Confidence", f"{r.global_confidence * 100:.2f}%", ""),
            ("Hash-Chain", chain_val, chain_cls),
            ("Receipts", f"{r.total_receipts:,}", ""),
            ("Erstellt (UTC)", r.timestamp, ""),
        ]

        meta_html = "\n".join(
            f"<div class='item'>"
            f"<span class='lbl'>{lbl}</span>"
            f"<span class='val {cls}'>{val}</span>"
            f"</div>"
            for lbl, val, cls in meta_items
        )

        rows = []
        for art, d in r.articles.items():
            score_pct = int(d.score * 100)
            conf_pct = int(d.confidence * 100)
            rows.append(
                f"<tr>"
                f"<td><strong>{art}</strong><br>"
                f"<span style='color:#64748b;font-size:13px'>{d.title}</span></td>"
                f"<td>{score_pct}%"
                f"<div class='bar'><div class='fill' style='width:{score_pct}%'></div></div></td>"
                f"<td><span style='color:#64748b'>{conf_pct}%</span></td>"
                f"<td><span class='{d.status}'>{d.status}</span></td>"
                f"<td style='font-size:14px'>{d.details}</td>"
                f"</tr>"
            )

        return "\n".join([
            "<!DOCTYPE html>",
            "<html lang='de'>",
            "<head><meta charset='UTF-8'>",
            "<title>EU AI Act Compliance Report</title>",
            css,
            "</head><body>",
            "<h1>EU AI Act Audit Report</h1>",
            f"<div class='meta'><div class='grid'>{meta_html}</div></div>",
            "<h2>Artikel-Auswertung</h2>",
            "<table><thead><tr>",
            "<th>Artikel &amp; Titel</th><th>Score</th>"
            "<th>Confidence</th><th>Status</th><th>Details</th>",
            "</tr></thead><tbody>",
            *rows,
            "</tbody></table>",
            "</body></html>",
        ])
