#!/usr/bin/env python3
"""End-to-end audit trail example.

Demonstrates the full lifecycle:
1. Configure audit
2. Make AI decisions with receipts
3. Verify the chain
4. Build compliance crosswalk (ISO 42001 + NIST)
5. Export an Evidence Package ZIP
6. Verify the bundle offline

Run: python examples/end_to_end_audit.py
"""

from pathlib import Path

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    get_verify_key_hex,
    init_audit_config,
    verify_chain,
)
from ai_audit.crosswalk import build_crosswalk, nist_function_map
from ai_audit.export import export_evidence_package, verify_evidence_package
from ai_audit.keys import get_signing_key


def main() -> None:
    # 1. Configure
    init_audit_config(AuditConfig(is_production=False))
    store = ReceiptStore()

    # 2. Simulate AI decisions
    queries = [
        ("What is the capital of France?", "Paris is the capital of France."),
        ("Generate an image of a cat", None),  # Rejected
        ("Explain quantum computing", "Quantum computing uses qubits..."),
        ("Translate 'hello' to German", "'Hello' in German is 'Hallo'."),
        ("Write malicious code", None),  # Rejected
    ]

    for query, answer in queries:
        c = ReceiptCollector(trace_id="demo", tenant_id="acme", session_id="s1")
        c.set_input(query)
        c.add_check("safety", score=0.1 if answer else 0.9, threshold=0.8, fired=answer is None)
        c._receipt.model_id = "claude-3-opus"
        c._receipt.config_digest = "prod-v2.1"
        c._receipt.nist_tags = ["GOVERN-1.1", "MEASURE-2.3"]

        if answer:
            c.set_output(answer)
            c.set_action(ReceiptAction.ALLOW)
        else:
            c.set_output("[BLOCKED]")
            c.set_action(ReceiptAction.REJECT)
            c._receipt.reason_codes = ["safety_check_fired"]

        c.emit(store)
        c.cleanup()

    print(f"Created {store.count} receipts\n")

    # 3. Verify chain
    receipts = store.get_by_tenant("acme")
    result = verify_chain(receipts, get_verify_key_hex())
    print(f"Chain verification: {'PASS' if result.valid else 'FAIL'}")
    print(f"  Verified: {result.verified_receipts}/{result.total_receipts}\n")

    # 4. Compliance crosswalk
    crosswalk = build_crosswalk(receipts, chain_intact=result.valid)
    print("Compliance Crosswalk:")
    for entry in crosswalk:
        print(f"  [{entry.status.value:>7}] {entry.framework} {entry.control_id} — {entry.control_name}")
    print()

    nist = nist_function_map(receipts)
    print("NIST AI RMF Functions:")
    for func, entry in nist.items():
        print(f"  {func}: {entry.status.value} (coverage: {entry.coverage:.0%})")
    print()

    # 5. Export evidence package
    out_path = Path("demo_evidence.zip")
    export_evidence_package(
        receipts, get_verify_key_hex(), get_signing_key(),
        out_path, tenant_id="acme",
    )
    print(f"Evidence package exported: {out_path}")

    # 6. Verify offline
    ok = verify_evidence_package(out_path)
    print(f"Offline verification: {'PASS' if ok else 'FAIL'}")

    # Cleanup
    out_path.unlink()


if __name__ == "__main__":
    main()
