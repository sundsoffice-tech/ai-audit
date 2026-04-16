# Why Normal AI Logs Are Not Enough for Audits

*And how cryptographic receipts solve this.*

---

## The problem with normal logging

Every AI team logs their model calls. Input, output, latency, tokens, maybe a trace ID. It goes into Elasticsearch, Datadog, or a plain JSON file.

Then an auditor asks: "Prove that this decision was made correctly and that nobody changed the log afterwards."

And you can't.

Normal logs have no integrity guarantees. A database admin can edit a row. A log rotation script can delete entries. A misconfigured pipeline can drop events silently. There is no cryptographic proof that what you're showing today is what actually happened six months ago.

For most applications, this doesn't matter. For AI systems under the EU AI Act (mandatory August 2026), it's a compliance failure.

## What the EU AI Act actually requires

Article 12 of the EU AI Act mandates that high-risk AI systems maintain logs that enable:

- **Traceability** — what happened, in what order
- **Monitoring** — ongoing quality and safety assessment
- **Post-market surveillance** — investigating incidents after deployment

The key word is *tamper-evident*. Not just logged. Provably unmodified.

## How cryptographic receipts work

Instead of writing a log line, you create a **Decision Receipt** for every AI decision:

1. **Hash the content** — SHA-256 of the canonical payload (input hash, output hash, check scores, action taken, model ID)
2. **Sign it** — Ed25519 signature proves who created the receipt and when
3. **Chain it** — each receipt includes the hash of the previous receipt, forming a hash-chain

If anyone modifies a receipt after creation, the hash changes. The signature becomes invalid. The chain breaks. All three are independently verifiable.

This is the same principle behind Certificate Transparency (RFC 6962) and Git commits — applied to AI decisions instead of TLS certificates or code.

## What this looks like in Python

```python
from ai_audit import ReceiptCollector, ReceiptStore, verify_chain, get_verify_key_hex

store = ReceiptStore()
collector = ReceiptCollector(trace_id="req-1", tenant_id="acme")
collector.set_input("What is our refund policy?")
collector.add_check("safety", score=0.02, threshold=0.8)
collector.set_output("Our refund policy allows...")
collector.set_action("allow")
collector.emit(store)

# Later: verify the entire chain
result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
assert result.valid
```

Three lines to create a receipt. One line to verify the chain. No external services.

## Beyond logging: what auditors actually need

Auditors don't want your Elasticsearch dashboard. They want:

1. **Offline verification** — they verify on their own laptop, without accessing your systems
2. **Compliance mappings** — which ISO 42001 controls are covered, with what evidence
3. **Evidence packages** — a self-contained bundle they can archive and re-verify years later

`ai-audit-trail` provides all three:

```python
# Export a signed evidence bundle
from ai_audit.export import export_evidence_package
export_evidence_package(receipts, verify_key, signing_key, "audit_2026.zip")

# Auditor verifies offline:
# python -m ai_audit verify audit_2026.zip
```

## The agentic AI challenge

Logging gets harder when AI agents call tools, delegate to sub-agents, and make multi-step decisions. A linear log doesn't capture the actual decision topology.

`ai-audit-trail` addresses this with:

- **Cryptographic tool-call receipts** — every API call an agent makes is Ed25519 signed
- **Multi-agent trace graphs** — a DAG, not a flat log, capturing delegation and parallel execution
- **Provenance tracking** — proves WHERE each piece of information came from (system prompt vs. retrieved document vs. user input)
- **Behavioral contracts** — formal guarantees that an agent satisfies hard and soft constraints

## Getting started

```bash
pip install ai-audit-trail
```

196 tests. 26 modules. mypy strict. MIT licensed. No external services required.

[GitHub: sundsoffice-tech/ai-audit-trail](https://github.com/sundsoffice-tech/ai-audit-trail)

---

*Created by S&S Connect. Building trust infrastructure for autonomous AI systems.*
