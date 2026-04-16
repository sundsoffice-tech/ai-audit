"""CLI entry point: ``python -m ai_audit verify <bundle.zip>``."""

from __future__ import annotations

import sys


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] != "verify" or len(args) < 2:
        print("Usage: python -m ai_audit verify <bundle.zip>")
        print("  Verify an Evidence Package ZIP bundle offline.")
        sys.exit(2)

    zip_path = args[1]
    verbose = "--verbose" in args or "-v" in args

    from ai_audit.export import verify_evidence_package

    if verbose:
        print(f"Verifying: {zip_path}")

    ok = verify_evidence_package(zip_path)
    if ok:
        print(f"PASS: {zip_path} — all checks passed")
    else:
        print(f"FAIL: {zip_path} — verification failed")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
