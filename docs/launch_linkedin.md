# LinkedIn Launch Post

---

**I built an open-source audit trail for AI agents. Here's why.**

The EU AI Act becomes mandatory in August 2026. It requires tamper-evident logs for high-risk AI systems.

Most teams are solving this with normal logging. But normal logs can be edited. Deleted. Backdated. They prove nothing in an audit.

So I built **ai-audit-trail** — a Python library that wraps every AI decision in a cryptographically signed, hash-chained receipt.

**What it does in 3 lines:**
- Ed25519 signature proves WHO created it
- SHA-256 hash proves the content wasn't changed
- Hash-chain proves nothing was inserted or deleted

Same principle as blockchain — without the blockchain.

**What makes it different:**
- Fully offline-verifiable (no SaaS, no vendor lock-in)
- ISO 42001 + NIST AI RMF compliance mappings built in
- Evidence Package export that auditors verify on their own laptop
- Agent Behavioral Contracts with formal (p, delta, k)-satisfaction
- Cryptographic tool-call receipts for every API call an agent makes
- GDPR crypto-shredding: destroy the key, data is gone, chain stays intact

**196 tests. 26 modules. mypy strict. MIT licensed.**

pip install ai-audit-trail

If you're building AI systems that need to prove what they did:
https://github.com/sundsoffice-tech/ai-audit-trail

---

*#AIAudit #EUAIAct #Compliance #OpenSource #Python #Cryptography #AgenticAI #Governance*
