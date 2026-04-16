# Contributing to ai-audit-trail

Thank you for your interest in contributing to ai-audit-trail. This document explains the rules, process, and architectural invariants that govern contributions.

## Architecture Invariants (Non-Negotiable)

These invariants are enforced by CI and must never be violated:

1. **Zero Application Logic.** `ai-audit-trail` is a universal protocol. No RBAC, no tenant management, no API routes, no framework dependencies. Application logic belongs in the host application, not in this library.

2. **Minimal Dependencies.** Core dependencies: `pydantic`, `PyNaCl`, `orjson`, `cryptography`. Everything else is optional. Adding a new required dependency needs explicit approval and a compelling justification.

3. **Fail-Closed by Default.** When in doubt, raise an exception rather than silently continuing. Silent data loss in an audit trail is a compliance violation.

4. **Cryptographic Correctness.** All hashing uses SHA-256. All signing uses Ed25519 (libsodium via PyNaCl). No custom crypto. No "clever" shortcuts. Hash-chain integrity must be verifiable offline.

5. **Type Safety.** `mypy --strict` must pass with zero errors. All public functions have complete type annotations.

## Shared Responsibility Model

| Responsibility | Library | Deployer |
|---|:---:|:---:|
| Ed25519 signing + SHA-256 hashing | X | |
| Hash-chain integrity | X | |
| PII redaction (REDACT/HASH/MASK) | X | |
| Merkle-Tree batch sealing (RFC 6962) | X | |
| SPRT compliance certification | X | |
| ISO 42001 / NIST AI RMF mapping | X | |
| Evidence Package export + offline verification | X | |
| Crypto-Shredding (GDPR Art. 17) | X | |
| Agent Behavioral Contracts | X | |
| Tool-Call cryptographic receipts | X | |
| Multi-Agent Trace-Graphs | X | |
| OpenTelemetry metrics (optional) | X | |
| **Secure key storage (HSM/Vault)** | | X |
| **PII type configuration** | | X |
| **Durable storage backend** | | X |
| **Access controls / RBAC** | | X |
| **Human oversight (Art. 14)** | | X |
| **Clock synchronization (NTP)** | | X |
| **Incident response** | | X |
| **Regulatory compliance certification** | | X |

> **This library provides cryptographically verifiable evidence of conformity.
> It does not, by itself, ensure or guarantee regulatory compliance.**

## Development Setup

```bash
git clone https://github.com/sundsoffice-tech/ai-audit-trail.git
cd ai-audit-trail
pip install uv
uv sync --all-extras --dev
uv run pytest tests/ -q          # Run tests
uv run ruff check src/ tests/    # Lint
uv run mypy src/ai_audit/ --strict  # Type check
```

## Pull Request Process

1. **Branch from `main`.** Use descriptive branch names: `feat/merkle-batch`, `fix/chain-tip-eviction`.
2. **All tests must pass.** `uv run pytest tests/ -q` — zero failures.
3. **Linter clean.** `uv run ruff check src/ tests/` — zero errors.
4. **Type check clean.** `uv run mypy src/ai_audit/ --strict` — zero errors.
5. **Add tests.** Every new feature needs tests. Every bug fix needs a regression test.
6. **Update CHANGELOG.md.** Follow [Keep a Changelog](https://keepachangelog.com/) format.
7. **One concern per PR.** Don't bundle unrelated changes.

## Versioning Policy

This project follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR (x.0.0):** Breaking API changes (removed exports, changed signatures).
- **MINOR (0.x.0):** New features, new exports. Backwards-compatible.
- **PATCH (0.0.x):** Bug fixes. Backwards-compatible.

**Deprecation policy:** No public API symbol will be removed without at least two minor release cycles of deprecation warnings.

## Code Style

- Line length: 120 characters.
- Formatting: `ruff format`.
- Import sorting: `ruff check --select I`.
- Docstrings: Google style. Required for all public classes and functions.
- No emojis in code or commit messages.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the full threat model.
