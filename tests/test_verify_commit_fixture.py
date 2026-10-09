"""Findings 11, 12: ci/verify_commit_fixture.sh accepts a well-formed RSA
fixture (OpenSSL 3 headings, required entropy_length_bytes) end to end, and
still rejects raw-entropy fields and non-RSA keys.

Follow-up 1: the ingested node record (whose node_id is pinned) must be
exactly the statement the signature verifies."""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ledger_testutil import REPO

pytestmark = pytest.mark.skipif(
    any(shutil.which(t) is None for t in ("bash", "openssl", "jq", "base64"))
    or (shutil.which("sha256sum") is None and shutil.which("shasum") is None),
    reason="fixture checker needs bash, openssl, jq, base64 and sha256sum/shasum",
)


def _openssl(*args: str) -> bytes:
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


def _layout(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "ci").mkdir(parents=True)
    (root / "commit-fixtures").mkdir()
    for rel in ("ci/verify_commit_fixture.sh", "ci/assert_node_id.py", "ingest_root_entropy.py"):
        shutil.copyfile(REPO / rel, root / rel)
    shutil.copytree(REPO / "canon", root / "canon", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _keypair(tmp_path: Path, *genpkey_args: str) -> tuple:
    key = tmp_path / "ak.key"
    pub = tmp_path / "ak.pub"
    _openssl("genpkey", *genpkey_args, "-out", str(key))
    _openssl("pkey", "-in", str(key), "-pubout", "-out", str(pub))
    return key, pub


def _ingest(root: Path, fixture_path: Path) -> dict:
    """Run the layout's own ingest_root_entropy.py, as a fixture author would."""
    proc = subprocess.run(
        [sys.executable, str(root / "ingest_root_entropy.py"), str(fixture_path)],
        capture_output=True, text=True, check=True, timeout=60,
    )
    return json.loads(proc.stdout)


def _fixture(root: Path, tmp_path: Path, key: Path, pub: Path, name: str = "commit_test", **overrides) -> str:
    """Write a fixture whose signature covers the canonical no-quote statement
    (real AK fingerprint, null quote hashes) and whose .node_id pins whatever
    record ingest produces. With ``overrides`` that is exactly the review's
    attack: altered record fields, original signature, re-pinned node_id."""
    sys.path.insert(0, str(root))
    try:
        from canon.ids import canon_json_bytes
    finally:
        sys.path.remove(str(root))

    ak_fp = hashlib.sha256(_openssl("pkey", "-pubin", "-in", str(pub), "-outform", "DER")).hexdigest()
    fixture = {
        "algorithm": "sha256",
        "entropy_length_bytes": 32,
        "root_hash": hashlib.sha256(b"root").hexdigest(),
        "ak_pubkey_fp_sha256": ak_fp,
        "ak_public_pem_base64": base64.b64encode(pub.read_bytes()).decode(),
        "tpm_quote_sha256": None,
        "tpm_quote_nonce_sha256": None,
    }
    fixture.update(overrides)
    statement = {
        "v": 1,
        "node_type": "root_entropy",
        "algorithm": fixture["algorithm"],
        "entropy_length_bytes": int(fixture["entropy_length_bytes"]),
        "root_hash": fixture["root_hash"],
        "ak_pubkey_fp_sha256": ak_fp,
        "tpm_quote_sha256": None,
        "tpm_quote_nonce_sha256": None,
    }
    stmt = tmp_path / "statement.bin"
    stmt.write_bytes(canon_json_bytes(statement))
    sig = _openssl("dgst", "-sha256", "-sign", str(key), str(stmt))
    fixture["signature_base64"] = base64.b64encode(sig).decode()

    fixture_path = root / "commit-fixtures" / f"{name}.json"
    fixture_path.write_text(json.dumps(fixture, indent=2))
    pinned = _ingest(root, fixture_path)["node_id"]
    (root / "commit-fixtures" / f"{name}.node_id").write_text(pinned + "\n")
    return name


def _check(root: Path, name: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(root / "ci" / "verify_commit_fixture.sh"), name],
        capture_output=True, text=True, timeout=120,
    )


def test_valid_rsa_fixture_with_entropy_length_passes(tmp_path: Path) -> None:
    root = _layout(tmp_path)
    key, pub = _keypair(tmp_path, "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
    proc = _check(root, _fixture(root, tmp_path, key, pub))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "AK key is RSA" in proc.stdout
    assert "No suspicious field names found" in proc.stdout
    assert "Signature covers the ingested node record" in proc.stdout
    assert "All verification checks PASSED" in proc.stdout


@pytest.mark.parametrize(
    "extra",
    [{"raw_entropy": "00ff"}, {"entropy_base64": "AAAA"}, {"meta": {"Seed": "x"}}, {"meta": {"entropy_length_bytes": "AAAA"}}],
    ids=["raw_entropy", "entropy_base64", "nested-seed", "nested-entropy-length"],
)
def test_raw_entropy_fields_still_rejected(tmp_path: Path, extra: dict) -> None:
    root = _layout(tmp_path)
    key, pub = _keypair(tmp_path, "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
    proc = _check(root, _fixture(root, tmp_path, key, pub, **extra))
    assert proc.returncode != 0
    assert "Suspicious field name suggests raw entropy leakage" in proc.stderr


def test_entropy_length_must_be_positive_integer(tmp_path: Path) -> None:
    root = _layout(tmp_path)
    key, pub = _keypair(tmp_path, "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
    proc = _check(root, _fixture(root, tmp_path, key, pub, entropy_length_bytes="32"))
    assert proc.returncode != 0
    assert "entropy_length_bytes must be a positive integer" in proc.stderr


def test_non_rsa_key_rejected(tmp_path: Path) -> None:
    root = _layout(tmp_path)
    key, pub = _keypair(tmp_path, "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    proc = _check(root, _fixture(root, tmp_path, key, pub))
    assert proc.returncode != 0
    assert "AK key is not RSA" in proc.stderr


def _rsa(tmp_path: Path) -> tuple:
    return _keypair(tmp_path, "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")


def _signed_bytes_match_record(root: Path, tmp_path: Path, name: str) -> bool:
    sys.path.insert(0, str(root))
    try:
        from canon.ids import canon_json_bytes
    finally:
        sys.path.remove(str(root))
    record = _ingest(root, root / "commit-fixtures" / f"{name}.json")["node_record"]
    return canon_json_bytes(record) == (tmp_path / "statement.bin").read_bytes()


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"ak_pubkey_fp_sha256": "0" * 64}, "ak_pubkey_fp_sha256 must equal the AK public key fingerprint"),
        ({"ak_pubkey_fp_sha256": None}, "ak_pubkey_fp_sha256 must equal the AK public key fingerprint"),
        ({"tpm_quote_sha256": "e" * 64}, "tpm_quote_sha256 must be null for a no-quote fixture"),
        ({"tpm_quote_nonce_sha256": "e" * 64}, "tpm_quote_nonce_sha256 must be null for a no-quote fixture"),
        ({"tpm_quote_sha256": ""}, "tpm_quote_sha256 must be null for a no-quote fixture"),
        ({"tpm_quote_nonce_sha256": ""}, "tpm_quote_nonce_sha256 must be null for a no-quote fixture"),
    ],
    ids=[
        "tampered-fingerprint", "missing-fingerprint", "tampered-quote-hash",
        "tampered-quote-nonce-hash", "empty-quote-hash", "empty-quote-nonce-hash",
    ],
)
def test_unsigned_record_fields_are_rejected(tmp_path: Path, overrides: dict, message: str) -> None:
    root = _layout(tmp_path)
    key, pub = _rsa(tmp_path)
    name = _fixture(root, tmp_path, key, pub, **overrides)
    # Attack precondition: the signature is valid for the original statement and
    # the altered record is pinned, but the two are different bytes.
    assert not _signed_bytes_match_record(root, tmp_path, name)

    proc = _check(root, name)
    assert proc.returncode != 0
    assert "Inconsistent no-quote metadata" in proc.stderr
    assert message in proc.stderr
    assert "All verification checks PASSED" not in proc.stdout


def test_signature_must_cover_the_ingested_record_bytes(tmp_path: Path) -> None:
    # Fixture metadata is consistent, but ingest emits a record that differs
    # from the signed statement (simulated drift between the two constructions).
    # Only the step-8 byte-binding check can catch this.
    root = _layout(tmp_path)
    ingest = root / "ingest_root_entropy.py"
    src = ingest.read_text(encoding="utf-8")
    needle = '"node_type": "root_entropy",'
    assert src.count(needle) == 1
    ingest.write_text(src.replace(needle, '"node_type": "root_entropy_unsigned",'), encoding="utf-8")

    key, pub = _rsa(tmp_path)
    name = _fixture(root, tmp_path, key, pub)
    assert not _signed_bytes_match_record(root, tmp_path, name)

    proc = _check(root, name)
    assert proc.returncode != 0
    assert "No-quote metadata matches the signed statement" in proc.stdout
    assert "node_id verified" in proc.stdout  # pinned id alone is not enough
    assert "Ingested node record does not match the signed statement" in proc.stderr
    assert "All verification checks PASSED" not in proc.stdout
