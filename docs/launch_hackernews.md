# Show HN Post

---

**Title:** Show HN: ai-audit-trail – Cryptographic audit trail for AI agents (Ed25519, hash-chains, ISO 42001)

**URL:** https://github.com/sundsoffice-tech/ai-audit-trail

**Text:**

Hi HN,

I built ai-audit-trail because the EU AI Act (mandatory Aug 2026) requires tamper-evident logs for high-risk AI systems, and normal logging doesn't cut it — logs can be edited after the fact.

ai-audit-trail wraps every AI decision in a Decision Receipt: Ed25519 signed, SHA-256 hashed, hash-chained to its predecessor. Same integrity model as Certificate Transparency (RFC 6962), but for AI pipelines instead of TLS certificates.

What's in the box:
- Decision Receipts with 3-stage verification (signature + hash + chain)
- PII redaction before hashing (GDPR Art. 17)
- Merkle-Tree batch sealing for 10k+ req/s
- ISO 42001 / NIST AI RMF compliance crosswalk with evidence pointers
- Evidence Package export (signed ZIP, offline-verifiable by auditors)
- Sequential Probability Ratio Test (SPRT) for continuous certification
- Agent Behavioral Contracts with (p, delta, k)-satisfaction metrics
- Cryptographic tool-call receipts for agent API calls
- Multi-agent trace graphs (DAG, not linear logs)
- Provenance tracking (proves WHERE information came from)
- Crypto-shredding for GDPR erasure (AES-256-GCM, destroy key = destroy data)
- OpenTelemetry instrumentation (optional, graceful no-op)
- Storage backend ABCs (bring your own database)

196 tests, mypy strict, zero external services required. Works air-gapped.

pip install ai-audit-trail

I'd appreciate feedback on the architecture and any edge cases I might have missed.
