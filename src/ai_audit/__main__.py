"""CLI entry point for ai_audit.

Subcommands:
    verify <bundle.zip>     Verify an Evidence Package ZIP bundle offline.
    gen-key                 Generate a fresh Ed25519 signing key (hex-encoded seed).
    info                    Print package version and configured keys.
"""

from __future__ import annotations

import sys


def _cmd_verify(args: list[str]) -> int:
    if len(args) < 1:
        print("Usage: python -m ai_audit verify <bundle.zip> [--verbose]")
        return 2
    zip_path = args[0]
    verbose = "--verbose" in args or "-v" in args

    from ai_audit.export import verify_evidence_package

    if verbose:
        print(f"Verifying: {zip_path}")
    ok = verify_evidence_package(zip_path)
    if ok:
        print(f"PASS: {zip_path} - all checks passed")
    else:
        print(f"FAIL: {zip_path} - verification failed")
    return 0 if ok else 1


def _cmd_gen_key(args: list[str]) -> int:
    """Print a fresh hex-encoded Ed25519 seed (32 bytes / 64 hex chars).

    Use for AI_AUDIT_SIGNING_KEY env-var or AuditConfig(signing_key_hex=...).
    """
    import nacl.signing

    sk = nacl.signing.SigningKey.generate()
    seed_hex = sk.encode().hex()
    verify_hex = sk.verify_key.encode().hex()

    if "--quiet" in args or "-q" in args:
        print(seed_hex)
        return 0

    print("# Ed25519 signing key (KEEP SECRET)")
    print(f"AI_AUDIT_SIGNING_KEY={seed_hex}")
    print()
    print("# Public verification key (safe to share / commit)")
    print(f"AI_AUDIT_VERIFY_KEY={verify_hex}")
    print()
    print("# Usage:")
    print("#   export AI_AUDIT_SIGNING_KEY=<seed>")
    print("#   export AI_AUDIT_ENV=production")
    print("#   from ai_audit import AuditConfig, init_audit_config")
    print("#   init_audit_config(AuditConfig.from_env())")
    return 0


def _cmd_info(args: list[str]) -> int:
    from ai_audit import __version__

    print(f"ai-audit-trail {__version__}")
    print(f"Python: {sys.version.split()[0]}")
    try:
        import nacl  # noqa: F401

        print("PyNaCl: available")
    except ImportError:
        print("PyNaCl: MISSING")
    return 0


def _print_help() -> None:
    print("Usage: python -m ai_audit <command> [args]")
    print()
    print("Commands:")
    print("  verify <bundle.zip>   Verify an Evidence Package ZIP bundle offline.")
    print("  gen-key               Generate a fresh Ed25519 signing key (hex seed).")
    print("  info                  Print package version and runtime info.")


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
        sys.exit(0 if args else 2)

    cmd, rest = args[0], args[1:]
    handlers = {
        "verify": _cmd_verify,
        "gen-key": _cmd_gen_key,
        "genkey": _cmd_gen_key,
        "info": _cmd_info,
    }
    handler = handlers.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}")
        _print_help()
        sys.exit(2)
    sys.exit(handler(rest))


if __name__ == "__main__":
    main()
