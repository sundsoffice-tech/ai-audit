# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-04-16

### Added
- **Epistemic Integrity / Unforgeable Provenance** (`provenance.py`)
  - `ProvenanceRecord` with `SourceType` (SYSTEM/USER/DOCUMENT/TOOL/AGENT/MEMORY/UNKNOWN)
  - `ProvenanceChain` with hash-based integrity verification
  - `TrustSummary`: avg/min trust, injection detection, system-grounded check
  - Addresses the "Lethal Trifecta" — proves *where* information came from
- 7 cross-module integration tests (lifecycle, concurrent emit, SPRT+drift+contract pipeline, Merkle batch, epochs, tool-call+provenance, empty store)
- Benchmark regression job in GitHub Actions CI

### Security
- **FIX(CRITICAL) TOCTOU**: `ReceiptStore.atomic_seal_and_append()` with per-tenant
  `threading.Lock`; `ReceiptCollector.emit()` now uses the atomic path — no more
  chain forking under concurrent access (4-thread integration test included).
- **FIX**: `contracts.py` — `_recovery_k` is reset on a new violation (stale
  recovery-distance bug).

### Quality
- 196/196 tests passing, ruff clean, mypy strict 0 errors across 26 modules.

## [0.3.0] - 2026-04-16

### Added
- **Agent Behavioral Contracts** with (p,δ,k)-Satisfaction and Reliability Index Θ
- **Cryptographic Tool-Call-Receipts** — Ed25519-signed audit trail for every agent API call
- **Multi-Agent Trace-Graphs (DAG)** — delegation, handoff, parallel orchestration audit
- CONTRIBUTING.md with Shared Responsibility Model and architecture invariants
- CI upgraded to mypy --strict

### Security
- FIX(CRITICAL): ZIP path traversal in verify_evidence_package() (CWE-22)
- FIX(HIGH): AuditBuffer silent data eviction removed (fail-closed enforced)
- FIX(HIGH): DEKStore destroy_dek() — documented Python bytes immutability limitation

## [0.1.2] - 2026-04-16

### Fixed
- **C1 (Critical):** `aappend()` — new async method with real `await` for Redis writes.
  `fail_on_redis_error=True` now actually propagates exceptions to the caller.
- **C2 (Critical):** `aget_chain_tip()` — new async method with Redis fallback.
  After LRU eviction or process restart, the hash-chain tip is recovered from Redis.
- **I4 (Important):** `seal()` ToCToU fix — `seal_payload()` called once and cached;
  hash and Ed25519 signature computed over the exact same bytes.
- **I7 (Important):** `verify_chain([])` now returns `valid=False` (fail-closed)
  instead of `valid=True` (fail-open).
- **I5 (Important):** `DefaultKeyProvider._load()` is now thread-safe via `threading.Lock`.
- mypy strict now passes cleanly (added `ignore_missing_imports` for optional `redis`).

### Added
- 3 new tests: empty chain verification, LRU eviction chain tip, seal payload consistency.

## [0.1.1] - 2026-04-15

### Fixed
- CI: Reverted `environment: pypi` — Trusted Publisher not configured with environment.

### Changed
- Version bump for PyPI release.

## [0.1.0] - 2026-04-14

### Added
- Initial release on PyPI as `ai-audit-trail`.
- `DecisionReceipt` Pydantic model with Ed25519 signing and SHA-256 hash-chain.
- `ReceiptCollector` for ergonomic receipt creation.
- `ReceiptStore` with in-memory LRU + optional Redis persistence (Lua mode).
- `verify_chain()` — 3-stage verification (Ed25519 + SHA-256 + chain linkage).
- `build_compliance_summary()` with SPRT statistical certification.
- `ComplianceReportGenerator` for EU AI Act Art. 9/12/13/17/18 reports.
- `PiiConfig` with REDACT/HASH/MASK modes for GDPR compliance.
- `KeyProvider` ABC for KMS integration (HashiCorp Vault, AWS KMS, etc.).
- `canonicalize_input()` / `hash_output()` for deterministic hashing.
- SECURITY.md with vulnerability disclosure policy.
- 71 tests, mypy strict, ruff clean.

### Security
- P0: `assert` statements replaced with `TypeError` raises.
- P0: Redis fail-closed mode with precise exception handling.
- Tamper-detection tests (forged signature, hash mismatch, chain break, insertion).

[Unreleased]: https://github.com/sundsoffice-tech/ai-audit-trail/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/sundsoffice-tech/ai-audit-trail/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sundsoffice-tech/ai-audit-trail/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sundsoffice-tech/ai-audit-trail/releases/tag/v0.1.0
