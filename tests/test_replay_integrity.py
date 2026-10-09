"""Findings 2, 8, 14: replay verifies CAS inputs before execution, only trusts
output produced by the current run, and honours keep=True."""
from __future__ import annotations

import shutil
from pathlib import Path

from ledger.cas import sha256_bytes
from ledger.replay import replay_node
from ledger.verify import verify_node, verify_reachable

from ledger_testutil import (
    PYTHON,
    admit,
    concat_transform,
    derive,
    init_repo,
    manifest_dict,
    marker_transform,
    put_blob,
    put_blob_at,
    run_cli,
    write_manifest_raw,
)


def _derived_with_marker(root: Path, marker: Path, child_bytes: bytes = b"child", **transform):
    parent = admit(root, b"parent")
    child = put_blob(root, child_bytes)
    t = put_blob(root, marker_transform(marker, child_bytes))
    write_manifest_raw(root, child, manifest_dict(child, [parent], digest=t, runner=[PYTHON], **transform))
    return parent, child, t


def test_substituted_transform_is_rejected_and_never_executed(tmp_path: Path) -> None:
    # Review reproduction: bytes at the transform's CAS path do not hash to the
    # declared digest but would emit the expected child.
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    parent = admit(root, b"parent")
    child = put_blob(root, b"child")
    claimed = sha256_bytes(b"# expected transform code\n")
    put_blob_at(root, claimed, marker_transform(marker, b"child"))
    write_manifest_raw(root, child, manifest_dict(child, [parent], digest=claimed, runner=[PYTHON]))

    rr = replay_node(root, child)
    assert not rr.ok
    assert any("transform definition hash mismatch" in e for e in rr.errors)

    vr = verify_reachable(root, child, replay=True)
    assert not vr.ok
    assert not verify_node(root, child, replay=True).ok
    assert run_cli(root, "replay", child).returncode == 2
    assert not marker.exists()


def test_tampered_parent_object_is_rejected_before_execution(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    parent, child, _ = _derived_with_marker(root, marker)
    put_blob_at(root, parent, b"tampered parent")

    rr = replay_node(root, child)
    assert not rr.ok
    assert any(f"parent object {parent} hash mismatch" in e for e in rr.errors)
    assert not marker.exists()


def test_environment_blob_integrity_is_checked(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    env_digest = sha256_bytes(b"lockfile v1\n")
    _, child, _ = _derived_with_marker(root, marker, env_digest=env_digest)

    rr = replay_node(root, child)
    assert not rr.ok and any("missing environment description" in e for e in rr.errors)

    put_blob_at(root, env_digest, b"lockfile v2 (substituted)\n")
    rr = replay_node(root, child)
    assert not rr.ok and any("environment description hash mismatch" in e for e in rr.errors)
    assert not marker.exists()

    put_blob_at(root, env_digest, b"lockfile v1\n")
    assert replay_node(root, child).ok
    assert marker.exists()


def test_stale_out_bin_in_reused_workdir_is_not_accepted(tmp_path: Path) -> None:
    # Review reproduction: a no-op transform passed when --workdir already held
    # an out.bin with the expected child bytes.
    root = init_repo(tmp_path)
    parent = admit(root, b"parent")
    child = put_blob(root, b"child")
    noop = put_blob(root, b"# exits successfully without writing output\n")
    write_manifest_raw(root, child, manifest_dict(child, [parent], digest=noop, runner=[PYTHON]))
    wd = tmp_path / "workdir"
    wd.mkdir()
    (wd / "out.bin").write_bytes(b"child")

    reused = replay_node(root, child, workdir=wd)
    assert not reused.ok
    assert any("missing out.bin" in e for e in reused.errors)
    assert not replay_node(root, child).ok
    assert (wd / "out.bin").read_bytes() == b"child"  # user files left alone


def test_workdir_can_still_be_reused_for_valid_replays(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    p = admit(root, b"hello")
    child = derive(root, b"hello!", [p], concat_transform(), params={"suffix": "!"})
    wd = tmp_path / "workdir"

    first = replay_node(root, child, workdir=wd)
    second = replay_node(root, child, workdir=wd)
    assert first.ok and second.ok
    assert first.workdir != second.workdir
    for r in (first, second):
        assert r.workdir is not None and r.workdir.parent == wd.resolve()
        assert (r.workdir / "out.bin").read_bytes() == b"hello!"


def test_keep_preserves_auto_created_workdir(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    p = admit(root, b"hello")
    child = derive(root, b"hello!", [p], concat_transform(), params={"suffix": "!"})

    kept = replay_node(root, child, keep=True)
    try:
        assert kept.ok
        assert kept.workdir is not None and kept.workdir.is_dir()
        assert (kept.workdir / "out.bin").read_bytes() == b"hello!"
    finally:
        if kept.workdir is not None:
            shutil.rmtree(kept.workdir, ignore_errors=True)

    transient = replay_node(root, child)
    assert transient.ok
    assert transient.workdir is not None and not transient.workdir.exists()


def test_cli_replay_keep_reports_existing_workdir(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    p = admit(root, b"hello")
    child = derive(root, b"hello!", [p], concat_transform(), params={"suffix": "!"})

    proc = run_cli(root, "replay", child, "--keep")
    assert proc.returncode == 0 and proc.stdout.strip() == "OK"
    lines = [l for l in proc.stderr.splitlines() if l.startswith("workdir: ")]
    assert len(lines) == 1
    kept = Path(lines[0][len("workdir: "):])
    try:
        assert (kept / "out.bin").read_bytes() == b"hello!"
    finally:
        shutil.rmtree(kept, ignore_errors=True)
