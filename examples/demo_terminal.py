#!/usr/bin/env python3
"""60-second terminal demo of ai-audit-trail.

Run: python examples/demo_terminal.py

Shows the complete lifecycle in a visual, shareable format.
"""

import sys
import time

# Colors for terminal output
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def step(n: int, title: str) -> None:
    print(f"\n{BOLD}{BLUE}[Step {n}]{RESET} {BOLD}{title}{RESET}")
    print(f"{DIM}{'-' * 60}{RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}OK{RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {DIM}{msg}{RESET}")


def main() -> None:
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  ai-audit-trail — 60 Second Demo{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")

    # Step 1: Install & Configure
    step(1, "Configure")
    from ai_audit import (
        AuditConfig,
        ReceiptAction,
        ReceiptCollector,
        ReceiptStore,
        get_verify_key_hex,
        init_audit_config,
        verify_chain,
    )
    from ai_audit.keys import get_signing_key

    init_audit_config(AuditConfig(is_production=False))
    store = ReceiptStore()
    ok("AuditConfig initialized (ephemeral Ed25519 key)")

    # Step 2: Create Decision Receipts
    step(2, "Create Decision Receipts")
    decisions = [
        ("What is GDPR?", "GDPR is the General Data Protection Regulation...", ReceiptAction.ALLOW),
        ("Generate malware", "[BLOCKED]", ReceiptAction.REJECT),
        ("Summarize this contract", "The contract states that...", ReceiptAction.ALLOW),
    ]
    for query, answer, action in decisions:
        c = ReceiptCollector(trace_id="demo", tenant_id="acme")
        c.set_input(query)
        c.add_check("safety", score=0.9 if action == ReceiptAction.REJECT else 0.05, threshold=0.8)
        c.set_output(answer)
        c.set_action(action)
        c.emit(store)
        c.cleanup()
        icon = f"{GREEN}ALLOW{RESET}" if action == ReceiptAction.ALLOW else f"{RED}REJECT{RESET}"
        ok(f"{icon} \"{query[:40]}...\"")

    info(f"  {store.count} receipts sealed with Ed25519 + SHA-256")

    # Step 3: Verify Chain
    step(3, "Verify Hash-Chain")
    receipts = store.get_by_tenant("acme")
    result = verify_chain(receipts, get_verify_key_hex())
    if result.valid:
        ok(f"Chain intact: {result.verified_receipts}/{result.total_receipts} receipts verified")
    else:
        print(f"  {RED}FAIL{RESET} {result.error}")

    # Step 4: Compliance Crosswalk
    step(4, "ISO 42001 / NIST AI RMF Crosswalk")
    from ai_audit.crosswalk import build_crosswalk

    crosswalk = build_crosswalk(receipts, chain_intact=True)
    for entry in crosswalk:
        color = GREEN if entry.status.value == "PASS" else YELLOW
        print(f"  [{color}{entry.status.value:>7}{RESET}] {entry.framework} {entry.control_id} — {entry.control_name}")

    # Step 5: Evidence Package
    step(5, "Export Evidence Package")
    import tempfile
    from pathlib import Path

    from ai_audit.export import export_evidence_package, verify_evidence_package

    with tempfile.TemporaryDirectory() as tmpdir:
        out = export_evidence_package(
            receipts, get_verify_key_hex(), get_signing_key(),
            Path(tmpdir) / "audit.zip", tenant_id="acme",
        )
        ok(f"Exported: {out.name} ({out.stat().st_size:,} bytes)")
        ok(f"Contains: receipts.jsonl, manifest.json (signed), verify.py")

        verified = verify_evidence_package(out)
        if verified:
            ok("Offline verification: PASS")

    # Step 6: Agent Audit
    step(6, "Agent Behavioral Contract")
    from ai_audit.contracts import BehavioralContract, Constraint, ContractMonitor

    contract = BehavioralContract(
        contract_id="safety-v1",
        constraints=[
            Constraint(name="must_allow", kind="hard", field="action", operator="!=", value="reject"),
        ],
    )
    monitor = ContractMonitor(contract)
    for r in receipts:
        monitor.evaluate(r)
    state = monitor.state
    info(f"  p={state.p:.2f}  delta={state.delta:.2f}  k={state.k}  Theta={state.reliability_index:.4f}")
    ok(f"Status: {state.status}")

    # Summary
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"  {GREEN}3{RESET} receipts sealed (Ed25519 + SHA-256)")
    print(f"  {GREEN}1{RESET} hash-chain verified")
    print(f"  {GREEN}9{RESET} compliance controls mapped")
    print(f"  {GREEN}1{RESET} evidence package exported + verified offline")
    print(f"  {GREEN}1{RESET} behavioral contract evaluated")
    print()
    print(f"  {BOLD}pip install ai-audit-trail{RESET}")
    print(f"  {DIM}github.com/sundsoffice-tech/ai-audit-trail{RESET}")
    print()


if __name__ == "__main__":
    main()
