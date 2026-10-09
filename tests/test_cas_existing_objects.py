"""Follow-up 3: an object already present at a digest's CAS path must be a
regular file with that digest before admit/derive relies on it. Corrupt
entries are rejected without being overwritten and without writing a record."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ledger.assurance import PROFILES, evaluate
from ledger.cas import CasIntegrityError, CasPaths, sha256_bytes, store_blob

from ledger_testutil import admit, check, concat_transform, init_repo, put_blob, put_blob_at, run_cli


def _no_records(root: Path) -> bool:
    return list((root / "ledger" / "records").iterdir()) == []


def test_admit_rejects_corrupt_existing_artifact_object(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"correct")
    obj = put_blob_at(root, sha256_bytes(b"correct"), b"incorrect")

    proc = run_cli(root, "admit", "input", "--statement", "s")
    assert proc.returncode != 0
    assert "existing CAS object is corrupt" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert obj.read_bytes() == b"incorrect"  # not silently replaced
    assert _no_records(root)


def test_derive_rejects_corrupt_existing_transform_blob(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    before = set((root / "ledger" / "records").iterdir())
    tf = root / "concat.py"
    tf.write_bytes(concat_transform())
    t_digest = sha256_bytes(concat_transform())
    t_obj = put_blob_at(root, t_digest, b"# substituted transform\n")
    (root / "out").write_bytes(b"hello!")

    proc = run_cli(root, "derive", "out", "--input", a, "--transform-file", str(tf), "--params-json", '{"suffix": "!"}')
    assert proc.returncode != 0
    assert "existing CAS object is corrupt" in proc.stderr and t_digest in proc.stderr
    assert t_obj.read_bytes() == b"# substituted transform\n"
    assert set((root / "ledger" / "records").iterdir()) == before
    # Checked before anything was written: no orphaned output object either.
    assert not CasPaths.from_repo_root(root).object_path(sha256_bytes(b"hello!")).exists()


@pytest.mark.parametrize("kind", ["directory", "symlink"])
def test_admit_rejects_non_regular_cas_entry(tmp_path: Path, kind: str) -> None:
    root = init_repo(tmp_path / "repo")
    (root / "input").write_bytes(b"data")
    obj = CasPaths.from_repo_root(root).object_path(sha256_bytes(b"data"))
    obj.parent.mkdir(parents=True)
    if kind == "directory":
        obj.mkdir()
    else:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_bytes(b"data")  # correct bytes, but not stored in the CAS
        try:
            os.symlink(elsewhere, obj)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")

    proc = run_cli(root, "admit", "input", "--statement", "s")
    assert proc.returncode != 0
    assert "not a regular file" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert obj.is_symlink() if kind == "symlink" else obj.is_dir()
    assert _no_records(root)


def test_derive_reuses_valid_existing_objects(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    tf = root / "concat.py"
    tf.write_bytes(concat_transform())
    put_blob(root, concat_transform())
    put_blob(root, b"hello!")
    (root / "out").write_bytes(b"hello!")

    proc = run_cli(root, "derive", "out", "--input", a, "--transform-file", str(tf), "--params-json", '{"suffix": "!"}')
    assert proc.returncode == 0, proc.stderr
    assert evaluate(check(root, proc.stdout.strip(), replay=True), PROFILES["replay"]).satisfied


def test_store_blob_never_overwrites_an_existing_entry(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    cas = CasPaths.from_repo_root(root)
    src = root / "src.bin"
    src.write_bytes(b"correct")
    digest = sha256_bytes(b"correct")
    obj = put_blob_at(root, digest, b"incorrect")

    with pytest.raises(CasIntegrityError, match="corrupt"):
        store_blob(src, cas, digest)
    assert obj.read_bytes() == b"incorrect"
    assert issubclass(CasIntegrityError, ValueError)

    obj.write_bytes(b"correct")
    assert store_blob(src, cas, digest) == obj
