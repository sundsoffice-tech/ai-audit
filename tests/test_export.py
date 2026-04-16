"""Tests for Evidence Package Export."""

import tempfile
from pathlib import Path

from ai_audit import (
    AuditConfig,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    get_verify_key_hex,
    init_audit_config,
    reset_signing_key,
)
from ai_audit.export import export_evidence_package, verify_evidence_package
from ai_audit.keys import get_signing_key


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def _make_chain(count: int = 5) -> tuple[ReceiptStore, list]:
    store = ReceiptStore()
    for i in range(count):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"query {i}")
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()
    return store, store.get_by_tenant("acme")


def test_export_creates_zip() -> None:
    """Export should create a valid ZIP file with all expected entries."""
    import zipfile

    _, receipts = _make_chain()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = export_evidence_package(
            receipts, get_verify_key_hex(), get_signing_key(),
            Path(tmpdir) / "test.zip", tenant_id="acme",
        )
        assert out.exists()
        with zipfile.ZipFile(out) as zf:
            names = zf.namelist()
            assert "receipts.jsonl" in names
            assert "chain_metadata.json" in names
            assert "public_key.hex" in names
            assert "manifest.json" in names
            assert "verify.py" in names


def test_export_verify_roundtrip() -> None:
    """Exported package must pass verification."""
    _, receipts = _make_chain()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = export_evidence_package(
            receipts, get_verify_key_hex(), get_signing_key(),
            Path(tmpdir) / "test.zip", tenant_id="acme",
        )
        assert verify_evidence_package(out)


def test_tampered_package_fails() -> None:
    """Modifying a file inside the ZIP must fail verification."""
    import zipfile

    _, receipts = _make_chain()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = export_evidence_package(
            receipts, get_verify_key_hex(), get_signing_key(),
            Path(tmpdir) / "test.zip", tenant_id="acme",
        )

        # Tamper: overwrite receipts.jsonl
        tampered = Path(tmpdir) / "tampered.zip"
        with zipfile.ZipFile(out, "r") as zf_in, zipfile.ZipFile(tampered, "w") as zf_out:
            for item in zf_in.infolist():
                data = zf_in.read(item.filename)
                if item.filename == "receipts.jsonl":
                    data = b"TAMPERED\n"
                zf_out.writestr(item, data)

        assert not verify_evidence_package(tampered)


def test_cli_verify() -> None:
    """CLI entry point should work."""
    _, receipts = _make_chain()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = export_evidence_package(
            receipts, get_verify_key_hex(), get_signing_key(),
            Path(tmpdir) / "test.zip", tenant_id="acme",
        )

        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "ai_audit", "verify", str(out)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
