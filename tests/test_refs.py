"""Finding 7: ref names must stay inside ledger/refs.

Follow-up 2: the boundary is fixed before following symlinks, so a symlinked
refs root (or a records directory aliased onto refs) cannot expose records."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ledger.records import record_path

from ledger_testutil import admit, init_repo, run_cli


def test_ref_traversal_cannot_overwrite_immutable_record(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    node = admit(root, b"ref")
    manifest = record_path(root, node)
    before = manifest.read_bytes()

    proc = run_cli(root, "refs", "set", f"../records/{node}.json", node)
    assert proc.returncode != 0
    assert "invalid ref name" in proc.stderr
    assert manifest.read_bytes() == before

    got = run_cli(root, "refs", "get", f"../records/{node}.json")
    assert got.returncode != 0
    assert node not in got.stdout


def test_absolute_ref_name_rejected(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    node = admit(root, b"ref")
    outside = tmp_path / "outside.txt"

    proc = run_cli(root, "refs", "set", str(outside), node)
    assert proc.returncode != 0
    assert "invalid ref name" in proc.stderr
    assert not outside.exists()


@pytest.mark.parametrize("name", ["", ".", "a/../../x"])
def test_degenerate_ref_names_rejected(tmp_path: Path, name: str) -> None:
    root = init_repo(tmp_path)
    node = admit(root, b"ref")
    proc = run_cli(root, "refs", "set", name, node)
    assert proc.returncode != 0 and "invalid ref name" in proc.stderr


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, root / "ledger" / "refs" / "escape", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    node = admit(root, b"ref")
    proc = run_cli(root, "refs", "set", "escape/latest", node)
    assert proc.returncode != 0
    assert "resolves outside ledger/refs" in proc.stderr
    assert not (outside / "latest").exists()


def test_nested_ref_names_still_work(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    node = admit(root, b"ref")

    assert run_cli(root, "refs", "set", "team/release/latest", node).returncode == 0
    assert (root / "ledger" / "refs" / "team" / "release" / "latest").read_text() == node + "\n"
    got = run_cli(root, "refs", "get", "team/release/latest")
    assert got.returncode == 0 and got.stdout.strip() == node


def _symlink_dir(link: Path, target) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def _ledger_without_refs(root: Path) -> Path:
    for name in ("records", "objects"):
        (root / "ledger" / name).mkdir(parents=True, exist_ok=True)
    return root


def test_symlinked_refs_root_cannot_overwrite_or_read_records(tmp_path: Path) -> None:
    # Review reproduction: ledger/refs -> nodes made the "refs" boundary the
    # immutable storage directory (now ledger/records).
    root = _ledger_without_refs(tmp_path)
    _symlink_dir(root / "ledger" / "refs", "records")
    node = admit(root, b"ref")
    manifest = record_path(root, node)
    before = manifest.read_bytes()

    proc = run_cli(root, "refs", "set", f"{node}.json", node)
    assert proc.returncode != 0
    assert "is a symlink" in proc.stderr
    assert manifest.read_bytes() == before

    got = run_cli(root, "refs", "get", f"{node}.json")
    assert got.returncode != 0
    assert "is a symlink" in got.stderr
    assert got.stdout == ""

    fresh = run_cli(root, "refs", "set", "latest", node)
    assert fresh.returncode != 0 and "is a symlink" in fresh.stderr
    assert sorted(p.name for p in (root / "ledger" / "records").iterdir()) == [manifest.name]


def test_refs_root_symlink_to_outside_rejected(tmp_path: Path) -> None:
    root = _ledger_without_refs(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "existing").write_text("keep\n")
    _symlink_dir(root / "ledger" / "refs", outside)

    node = admit(root, b"ref")
    for name in ("latest", "existing"):
        proc = run_cli(root, "refs", "set", name, node)
        assert proc.returncode != 0 and "is a symlink" in proc.stderr
    got = run_cli(root, "refs", "get", "existing")
    assert got.returncode != 0 and got.stdout == ""
    assert sorted(p.name for p in outside.iterdir()) == ["existing"]
    assert (outside / "existing").read_text() == "keep\n"


def test_records_aliased_onto_refs_cannot_be_written_through_refs(tmp_path: Path) -> None:
    root = tmp_path
    (root / "ledger" / "refs").mkdir(parents=True)
    (root / "ledger" / "objects").mkdir()
    _symlink_dir(root / "ledger" / "records", "refs")
    node = admit(root, b"aliased")
    manifest = record_path(root, node)
    before = manifest.read_bytes()

    proc = run_cli(root, "refs", "set", f"{node}.json", node)
    assert proc.returncode != 0
    assert "immutable ledger/records" in proc.stderr
    assert manifest.read_bytes() == before


def test_symlinked_ledger_dir_and_internal_ref_links_still_work(tmp_path: Path) -> None:
    store = init_repo(tmp_path / "store")
    repo = tmp_path / "repo"
    repo.mkdir()
    _symlink_dir(repo / "ledger", store / "ledger")
    node = admit(store, b"ref")

    assert run_cli(repo, "refs", "set", "team/latest", node).returncode == 0
    assert (store / "ledger" / "refs" / "team" / "latest").read_text() == node + "\n"
    _symlink_dir(store / "ledger" / "refs" / "alias", "team")
    got = run_cli(repo, "refs", "get", "alias/latest")
    assert got.returncode == 0 and got.stdout.strip() == node


@pytest.mark.parametrize("value", ["latest", "A" * 64, "a" * 63, "../x"])
def test_ref_value_must_be_a_record_id(tmp_path: Path, value: str) -> None:
    root = init_repo(tmp_path)
    proc = run_cli(root, "refs", "set", "latest", value)
    assert proc.returncode != 0 and "invalid record ID" in proc.stderr
    assert not (root / "ledger" / "refs" / "latest").exists()


@pytest.mark.parametrize("problem", ["missing-record", "corrupt-record", "missing-artifact"])
def test_ref_target_must_exist_and_pass_integrity(tmp_path: Path, problem: str) -> None:
    root = init_repo(tmp_path)
    node = admit(root, b"target")
    if problem == "missing-record":
        target = "7" * 64
    elif problem == "corrupt-record":
        target = node
        record_path(root, node).write_bytes(b"{}")
    else:
        target = node
        for obj in (root / "ledger" / "objects").rglob("*"):
            if obj.is_file():
                obj.unlink()
    proc = run_cli(root, "refs", "set", "latest", target)
    assert proc.returncode != 0
    assert "do not satisfy the integrity profile" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert not (root / "ledger" / "refs" / "latest").exists()
