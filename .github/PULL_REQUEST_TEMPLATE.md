<!--
Thanks for the PR. A few short prompts so reviewers can move fast.
Delete sections that don't apply.
-->

## What changes

<!-- One paragraph: what does this PR do, and why now? -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing public API)
- [ ] Documentation only
- [ ] Build / CI / tooling

## Testing

- [ ] `uv run pytest` passes locally
- [ ] `uv run ruff check src/ai_audit tests` clean
- [ ] `uv run mypy src/ai_audit/` strict, 0 errors
- [ ] Added or updated tests covering the change (if behaviour changed)

## Compliance / security implications

<!--
ai-audit-trail handles tamper-evidence and cryptographic signatures. If the
change touches: signing, hashing, chain linkage, key handling, evidence-package
format, or PII redaction — describe the threat-model impact here. Otherwise
write "none".
-->

## Documentation

- [ ] README updated if behaviour or install instructions changed
- [ ] CHANGELOG.md updated under `## [Unreleased]`
- [ ] Public API additions exported in `src/ai_audit/__init__.py`

## Breaking changes

<!-- If yes: list them and propose the migration step. If not, delete this section. -->
