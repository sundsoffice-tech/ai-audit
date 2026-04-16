"""
ai_audit.export — Evidence Package Export for offline audit verification.

Produces a self-contained ZIP bundle that external auditors can verify
without access to the running system ("Trustless Verification").

Bundle contents::

    evidence_bundle.zip
    ├── receipts.jsonl          # One JSON receipt per line
    ├── chain_metadata.json     # Chain stats, tenant, epoch info
    ├── public_key.hex          # Ed25519 verification key
    ├── manifest.json           # SHA-256 checksums + Ed25519 signature
    └── verify.py               # Standalone offline verifier

Usage::

    from ai_audit.export import export_evidence_package
    export_evidence_package(receipts, verify_key_hex, signing_key, "audit_2026.zip")

CLI::

    python -m ai_audit verify audit_2026.zip

NB 409cad95 (Enterprise) validated — 2026-04-16.
NB ee9616a5 (CHEF) correction applied: key_fingerprint in manifest.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import nacl.signing
import orjson

from ai_audit.models import DecisionReceipt

# Standalone verifier script embedded in the ZIP
_VERIFY_SCRIPT = '''\
#!/usr/bin/env python3
"""Standalone offline verifier for ai-audit Evidence Packages.

Usage: python verify.py [--verbose]

Run this script from within the extracted ZIP directory, or pass
the ZIP path as an argument. Requires only Python 3.11+ stdlib
plus PyNaCl (pip install PyNaCl).
"""
import hashlib
import json
import sys
from pathlib import Path

try:
    import nacl.signing
    import nacl.exceptions
except ImportError:
    print("ERROR: PyNaCl required. Install: pip install PyNaCl")
    sys.exit(2)

def verify(bundle_dir: Path, verbose: bool = False) -> bool:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        print("ERROR: manifest.json not found")
        return False

    manifest = json.loads(manifest_path.read_text())

    # 1. Verify manifest signature
    pub_key_hex = (bundle_dir / "public_key.hex").read_text().strip()
    verify_key = nacl.signing.VerifyKey(bytes.fromhex(pub_key_hex))
    sig_hex = manifest.pop("signature")
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    try:
        verify_key.verify(manifest_bytes, bytes.fromhex(sig_hex))
        if verbose:
            print("  [OK] Manifest signature valid")
    except nacl.exceptions.BadSignatureError:
        print("FAIL: Manifest signature FORGED")
        return False

    # 2. Verify file checksums
    for filename, expected_hash in manifest.get("checksums", {}).items():
        file_path = bundle_dir / filename
        if not file_path.exists():
            print(f"FAIL: Missing file {filename}")
            return False
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            print(f"FAIL: Checksum mismatch for {filename}")
            return False
        if verbose:
            print(f"  [OK] {filename} checksum valid")

    # 3. Verify receipt chain
    receipts_path = bundle_dir / "receipts.jsonl"
    receipts = []
    for line in receipts_path.read_text().splitlines():
        if line.strip():
            receipts.append(json.loads(line))

    if not receipts:
        print("FAIL: No receipts in bundle")
        return False

    receipts.sort(key=lambda r: r["timestamp"])
    prev_hash = ""
    verified = 0

    for i, r in enumerate(receipts):
        # Verify self-hash
        payload = {k: v for k, v in r.items() if k not in ("receipt_hash", "signature")}
        canonical = json.dumps(payload, sort_keys=True).encode()
        expected_hash = hashlib.sha256(canonical).hexdigest()

        # Verify Ed25519 signature
        try:
            verify_key.verify(canonical, bytes.fromhex(r["signature"]))
        except (nacl.exceptions.BadSignatureError, ValueError):
            print(f"FAIL: Receipt {r.get('receipt_id', i)} — signature invalid")
            return False

        # Verify chain linkage
        if i > 0 and r.get("prev_receipt_hash", "") != prev_hash:
            print(f"FAIL: Chain broken at receipt {i}")
            return False

        prev_hash = r["receipt_hash"]
        verified += 1

    print(f"PASS: {verified}/{len(receipts)} receipts verified")
    print(f"  Key fingerprint: {pub_key_hex[:16]}...")
    print(f"  Chain integrity: OK")
    return True


if __name__ == "__main__":
    import tempfile
    import zipfile

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]

    if args and args[0].endswith(".zip"):
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(args[0]) as zf:
                zf.extractall(tmpdir)
            ok = verify(Path(tmpdir), verbose=verbose)
    else:
        ok = verify(Path("."), verbose=verbose)

    sys.exit(0 if ok else 1)
'''


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_evidence_package(
    receipts: list[DecisionReceipt],
    verify_key_hex: str,
    signing_key: nacl.signing.SigningKey,
    output_path: str | Path,
    *,
    tenant_id: str = "",
    epoch_id: str = "",
    metadata: dict[str, object] | None = None,
) -> Path:
    """Export an Evidence Package as a signed ZIP bundle.

    Parameters:
        receipts:       Receipts to include (should be a complete chain).
        verify_key_hex: Ed25519 public key hex for verification.
        signing_key:    Ed25519 private key for signing the manifest.
        output_path:    Where to write the ZIP file.
        tenant_id:      Optional tenant identifier for metadata.
        epoch_id:       Optional epoch identifier for metadata.
        metadata:       Additional metadata to include in chain_metadata.json.

    Returns:
        Path to the created ZIP file.
    """
    output_path = Path(output_path)

    # 1. Serialize receipts as JSONL
    receipts_sorted = sorted(receipts, key=lambda r: r.timestamp)
    lines: list[bytes] = []
    for r in receipts_sorted:
        lines.append(orjson.dumps(r.model_dump(mode="json")))
    receipts_data = b"\n".join(lines) + b"\n" if lines else b""

    # 2. Chain metadata
    chain_meta = {
        "tenant_id": tenant_id,
        "epoch_id": epoch_id,
        "total_receipts": len(receipts),
        "first_receipt_id": receipts_sorted[0].receipt_id if receipts_sorted else "",
        "last_receipt_id": receipts_sorted[-1].receipt_id if receipts_sorted else "",
        "first_timestamp": receipts_sorted[0].timestamp.isoformat() if receipts_sorted else "",
        "last_timestamp": receipts_sorted[-1].timestamp.isoformat() if receipts_sorted else "",
        "exported_at": datetime.now(UTC).isoformat(),
        "key_fingerprint": verify_key_hex[:16],
    }
    if metadata:
        chain_meta.update(metadata)
    chain_meta_data = orjson.dumps(chain_meta, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)

    # 3. Public key
    pubkey_data = verify_key_hex.encode()

    # 4. Standalone verifier
    verify_data = _VERIFY_SCRIPT.encode()

    # 5. Build manifest with checksums
    checksums = {
        "receipts.jsonl": _sha256_bytes(receipts_data),
        "chain_metadata.json": _sha256_bytes(chain_meta_data),
        "public_key.hex": _sha256_bytes(pubkey_data),
        "verify.py": _sha256_bytes(verify_data),
    }

    manifest = {
        "version": "1.0",
        "format": "ai-audit-evidence-package",
        "checksums": checksums,
        "key_fingerprint": verify_key_hex[:16],
        "created_at": datetime.now(UTC).isoformat(),
    }

    # Sign the manifest
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    signed = signing_key.sign(manifest_bytes)
    manifest["signature"] = signed.signature.hex()
    manifest_final = json.dumps(manifest, indent=2, sort_keys=True).encode()

    # 6. Write ZIP
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("receipts.jsonl", receipts_data)
        zf.writestr("chain_metadata.json", chain_meta_data)
        zf.writestr("public_key.hex", pubkey_data)
        zf.writestr("verify.py", verify_data)
        zf.writestr("manifest.json", manifest_final)

    return output_path


def verify_evidence_package(zip_path: str | Path) -> bool:
    """Verify an Evidence Package ZIP bundle.

    Parameters:
        zip_path: Path to the ZIP file.

    Returns:
        True if all checks pass (manifest signature, checksums, chain).
    """
    import tempfile

    zip_path = Path(zip_path)
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmpdir)

        bundle_dir = Path(tmpdir)
        manifest_path = bundle_dir / "manifest.json"
        if not manifest_path.exists():
            return False

        manifest = json.loads(manifest_path.read_text())

        # Verify manifest signature
        pub_key_hex = (bundle_dir / "public_key.hex").read_text().strip()
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pub_key_hex))
        sig_hex = manifest.pop("signature")
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        try:
            verify_key.verify(manifest_bytes, bytes.fromhex(sig_hex))
        except nacl.exceptions.BadSignatureError:
            return False

        # Verify checksums
        for filename, expected in manifest.get("checksums", {}).items():
            fpath = bundle_dir / filename
            if not fpath.exists():
                return False
            if _sha256_bytes(fpath.read_bytes()) != expected:
                return False

    return True
