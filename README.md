# ai-audit

**Tamper-evident AI pipeline audit trail — EU AI Act Art. 12 compliant.**

Every AI pipeline decision gets a cryptographically signed, hash-chained receipt.
Drop-in for any Python AI application. No framework lock-in.

```python
from ai_audit import AuditConfig, init_audit_config, ReceiptCollector, ReceiptStore, verify_chain, get_verify_key_hex

# Configure once at startup
init_audit_config(AuditConfig.from_env())

# Wrap each request
store = ReceiptStore()
collector = ReceiptCollector(trace_id="req-1", tenant_id="acme")
collector.set_input("What is the capital of France?")
collector.add_check("safety", score=0.02, threshold=0.8, fired=False)
collector.set_output("The capital of France is Paris.")
collector.set_action("allow")
receipt_id = collector.emit(store)
collector.cleanup()

# Verify the chain (compliance audit)
result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
assert result.valid  # Ed25519 + SHA-256 + hash-chain all verified
```

## What it does

Each `DecisionReceipt` captures:
- **Input hash** — SHA-256 of NFKC-normalised input (semantic deduplication)
- **Output hash** — SHA-256 of generated response (bit-exact)
- **Check records** — scored gates (safety, routing, quality, etc.)
- **Terminal action** — `ALLOW / REJECT / ESCALATE / CACHE_HIT / FAIL_RETRY`
- **Model provenance** — which model was used
- **Ed25519 signature** — non-repudiation via libsodium (< 0.1ms)
- **SHA-256 hash-chain** — append-only, tamper-evident (like a blockchain)

Three-stage verification:
1. Ed25519 signature — detects forgery
2. SHA-256 self-hash — detects corruption
3. Hash-chain linkage — detects insertions/deletions

## Why

The **EU AI Act Art. 12** requires high-risk AI systems to maintain automatic
logs that demonstrate correct operation — and those logs must be tamper-evident.

`ai-audit` provides exactly that. There is no comparable standalone Python
package on PyPI.

## Installation

```bash
pip install ai-audit

# With Redis persistence
pip install "ai-audit[redis]"

# With Prometheus metrics
pip install "ai-audit[prometheus]"
```

## Configuration

```python
from ai_audit import AuditConfig, init_audit_config

# Option 1: Explicit
init_audit_config(AuditConfig(
    is_production=True,
    signing_key_hex="your-32-byte-hex-key",  # see below
))

# Option 2: From environment variables
# AI_AUDIT_ENV=production
# AI_AUDIT_SIGNING_KEY=<hex>
init_audit_config(AuditConfig.from_env())
```

Generate a persistent signing key:
```bash
python -c "import nacl.signing; print(nacl.signing.SigningKey.generate().encode().hex())"
```

## Redis persistence (optional)

```python
import redis
from ai_audit import ReceiptStore

r = redis.Redis(host="localhost", port=6379)
store = ReceiptStore(redis_client=r, ttl=2_592_000)  # 30-day TTL
```

## Prometheus monitoring (optional)

```python
from ai_audit import verify_chain, get_verify_key_hex
from prometheus_client import Counter

CHAIN_BREAKS = Counter("audit_chain_breaks_total", "Hash-chain breaks", ["tenant_id"])

result = verify_chain(
    receipts,
    get_verify_key_hex(),
    on_chain_break=lambda tenant_id: CHAIN_BREAKS.labels(tenant_id=tenant_id).inc(),
)
```

## Compliance summary (SPRT)

```python
from ai_audit import build_compliance_summary, verify_chain, get_verify_key_hex

receipts = store.get_by_tenant("acme", limit=1000)
chain_result = verify_chain(receipts, get_verify_key_hex())
summary = build_compliance_summary(receipts, chain_intact=chain_result.valid)

print(summary.sprt_status)           # CERTIFIED | MONITORING | FLAGGED
print(summary.compliance_confidence) # 0.0 - 1.0
print(summary.check_fire_rates)      # {"safety": 0.02, "routing": 0.0, ...}
```

SPRT (Sequential Probability Ratio Test) continuously monitors reject rates
with statistical confidence, flagging when reject rate exceeds 15%.

## Receipt schema

```python
@dataclass
class DecisionReceipt:
    receipt_id: str          # UUID hex
    timestamp: datetime      # UTC
    trace_id: str            # Request correlation ID
    session_id: str          # Chat session ID
    tenant_id: str           # Multi-tenant scope
    input_c14n: str          # SHA-256 of normalised input
    state_digest: str        # SHA-256 of context state
    output_hash: str         # SHA-256 of output
    checks: list[CheckRecord]
    action: ReceiptAction    # ALLOW | REJECT | ESCALATE | ...
    reason_codes: list[str]
    nist_tags: list[str]     # e.g. "AU-3", "AC-6"
    model_id: str
    prev_receipt_hash: str   # Hash-chain linkage
    receipt_hash: str        # SHA-256 self-hash
    signature: str           # Ed25519 signature (hex)
```

## Production Considerations

*Written by NB 409cad95 (Enterprise AI 2026: Scaling, Governance, and Performance Laws)*

### 1. Persistent signing key — mandatory

Ed25519 keys sign every DecisionReceipt. If the private key is lost, historical
chains can no longer be verified — breaking regulatory traceability (EU AI Act Art. 12).
Always use a persistent key in production:

```python
init_audit_config(AuditConfig(is_production=True, signing_key_hex="your-hex-key"))
```

For Enterprise, use a KMS-backed `KeyProvider` (see below).

### 2. GDPR Art. 17 (Right to Erasure) vs. Append-Only chain

The `ReceiptStore` is an append-only log — deleting a single entry breaks the
cryptographic chain. Use the built-in PII-Redaction hook so personal data never
enters the hash (see [PII-Redaction](#pii-redaction-gdpr-art-17) below):

```python
from ai_audit import PiiConfig, PiiMode, PiiType

collector = ReceiptCollector(
    tenant_id="acme",
    pii_config=PiiConfig(
        enabled_types=frozenset({PiiType.EMAIL, PiiType.IP}),
        mode=PiiMode.REDACT,
    ),
)
collector.set_input("Contact alice@example.com")  # stored hash: hash("[EMAIL]")
```

### 3. High-throughput Redis: use Lua mode

At 1k+ req/s, the default `MULTI/EXEC` mode can cause Redis connection-pool
exhaustion. Enable the Lua script mode for single-roundtrip atomic commits:

```python
store = ReceiptStore(redis_client=r, use_lua=True)
```

### 4. KMS integration via `KeyProvider` ABC

For production key management (Vault, AWS KMS, GCP KMS):

```python
from ai_audit import KeyProvider, init_key_provider
import nacl.signing

class VaultKeyProvider(KeyProvider):
    def get_signing_key(self) -> nacl.signing.SigningKey:
        secret = vault_client.secrets.kv.read_secret("secret/ai-audit/key")
        return nacl.signing.SigningKey(bytes.fromhex(secret["data"]["key"]))

    def get_verify_key_hex(self) -> str:
        return self.get_signing_key().verify_key.encode().hex()

init_key_provider(VaultKeyProvider())
```

### 5. Per-tenant chain isolation — already built-in

Each tenant gets its own independent hash chain. No cross-tenant metadata
leakage during audits. Set `tenant_id` in every `ReceiptCollector` call.

## PII-Redaction (GDPR Art. 17)

Strip personal data **before** SHA-256 hashing — the stored hash never reflects
raw PII, so GDPR Right to Erasure is satisfied without breaking the chain.

```python
from ai_audit import PiiConfig, PiiMode, PiiType, ReceiptCollector, ReceiptStore

config = PiiConfig(
    enabled_types=frozenset({PiiType.EMAIL, PiiType.PHONE, PiiType.IP, PiiType.IBAN}),
    mode=PiiMode.REDACT,   # or HASH (SHA-256 hex) or MASK (a***m)
)

store = ReceiptStore()
collector = ReceiptCollector(tenant_id="acme", pii_config=config)
collector.set_input("Call +49-89-123456 or email bob@corp.com")
# stored hash = canonicalize_input("Call [PHONE] or email [EMAIL]")
```

**Supported types:** `EMAIL`, `PHONE`, `IP`, `IBAN`, `CREDIT_CARD`, `CUSTOM` (regex)

**Modes:**
| Mode | Example output |
|------|---------------|
| `REDACT` | `[EMAIL]` |
| `HASH` | `3d4e5f…` (SHA-256 hex) |
| `MASK` | `b**@c**.com` |

Zero external dependencies — only `re` and `hashlib`. Async via `aobfuscate_text()`.

## EU AI Act Compliance Reports

Generate tamper-evident compliance reports mapped to EU AI Act Articles 9, 12,
13, 17, and 18 — fully offline, no internet required.

```python
from ai_audit import (
    build_compliance_summary, get_verify_key_hex, verify_chain,
)
from ai_audit.report import ComplianceReportGenerator

receipts = store.get_by_tenant("acme")
chain_result = verify_chain(receipts, get_verify_key_hex())
summary = build_compliance_summary(receipts, chain_intact=chain_result.valid,
                                   verify_key_hex=get_verify_key_hex())

gen = ComplianceReportGenerator(summary, verify_key_hex=get_verify_key_hex())

# Choose your format
print(gen.to_markdown())                          # Git / docs portal
with open("report.json", "w") as f:
    f.write(gen.to_json())                        # API / automated pipelines
with open("report.html", "w") as f:
    f.write(gen.to_html())                        # Self-contained HTML (air-gap safe)
```

Each report includes:
- **Compliance score + statistical confidence** per article (volume-weighted SPRT)
- **SPRT status** (`CERTIFIED` / `MONITORING` / `FLAGGED`) at the top level
- **Ed25519 signing-key fingerprint** for non-repudiation
- **Article-level detail** — Art. 9 Risk Management, Art. 12/18 Record-Keeping,
  Art. 13 Transparency, Art. 17 Quality Management

## License

MIT
