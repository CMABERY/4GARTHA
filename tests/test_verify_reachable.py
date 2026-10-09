"""Finding 6: reachable verification must reject cycles (and still accept DAGs)."""
from __future__ import annotations

from pathlib import Path

from ledger.cas import sha256_bytes
from ledger.verify import verify_reachable, verify_reachable_many

from ledger_testutil import (
    PYTHON,
    admit,
    concat_transform,
    derive,
    identity_marker_transform,
    init_repo,
    manifest_dict,
    marker_transform,
    put_blob,
    run_cli,
    write_manifest_raw,
)


def test_self_parent_with_copying_transform_is_rejected(tmp_path: Path) -> None:
    # Exact review reproduction: concat_parents.py with one parent and no
    # suffix copies the parent, so a node naming itself "replays" correctly.
    root = init_repo(tmp_path)
    child = put_blob(root, b"cycle")
    t = put_blob(root, concat_transform())
    write_manifest_raw(root, child, manifest_dict(child, [child], digest=t))

    r = verify_reachable(root, child, replay=True)
    assert not r.ok
    assert any("itself as a parent" in e for e in r.errors)
    assert run_cli(root, "verify-reachable", child, "--replay").returncode == 2


def test_self_parent_cycle_executes_nothing(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    child = put_blob(root, b"cycle")
    t = put_blob(root, identity_marker_transform(marker))
    write_manifest_raw(root, child, manifest_dict(child, [child], digest=t, runner=[PYTHON]))

    assert not verify_reachable(root, child, replay=True).ok
    assert not marker.exists()


def test_two_node_cycle_rejected_before_any_replay(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    t = put_blob(root, identity_marker_transform(marker))
    a = put_blob(root, b"same bytes A")
    b = put_blob(root, b"same bytes B")
    write_manifest_raw(root, a, manifest_dict(a, [b], digest=t, runner=[PYTHON]))
    write_manifest_raw(root, b, manifest_dict(b, [a], digest=t, runner=[PYTHON]))

    for start in (a, b):
        r = verify_reachable(root, start, replay=True)
        assert not r.ok
        assert any("cycle detected" in e for e in r.errors)
    assert not marker.exists()


def test_longer_cycle_reports_the_cycle_path(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a, b, c = (put_blob(root, s) for s in (b"a", b"b", b"c"))
    write_manifest_raw(root, a, manifest_dict(a, [b]))
    write_manifest_raw(root, b, manifest_dict(b, [c]))
    write_manifest_raw(root, c, manifest_dict(c, [a]))

    r = verify_reachable(root, a)
    assert not r.ok
    assert any(f"{a} -> {b} -> {c} -> {a}" in e for e in r.errors)


def test_shared_ancestors_are_not_cycles(tmp_path: Path) -> None:
    # Diamond: R -> X, R -> Y, (X, Y) -> Z ; plus R listed twice by W.
    root = init_repo(tmp_path)
    r = admit(root, b"R")
    x = derive(root, b"RX", [r], concat_transform(), params={"suffix": "X"})
    y = derive(root, b"RY", [r], concat_transform(), params={"suffix": "Y"})
    z = derive(root, b"RXRY", [x, y], concat_transform())
    w = derive(root, b"RR", [r, r], concat_transform())

    assert verify_reachable(root, z, replay=True).ok
    assert verify_reachable(root, w, replay=True).ok
    assert verify_reachable_many(root, [z, w, x, r], replay=True).ok


def test_no_replay_when_any_reachable_node_is_invalid(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    bad_parent = put_blob(root, b"parent")
    write_manifest_raw(root, bad_parent, manifest_dict("f" * 64, []))  # id not bound
    child_bytes = b"child"
    child = put_blob(root, child_bytes)
    t = put_blob(root, marker_transform(marker, child_bytes))
    write_manifest_raw(root, child, manifest_dict(child, [bad_parent], digest=t, runner=[PYTHON]))

    r = verify_reachable(root, child, replay=True)
    assert not r.ok
    assert any(e.startswith(bad_parent) and "manifest id mismatch" in e for e in r.errors)
    assert not marker.exists()


def test_missing_ancestor_object_detected(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    ghost = sha256_bytes(b"never stored")
    write_manifest_raw(root, ghost, manifest_dict(ghost, []))
    child = derive(root, b"never stored!", [ghost], concat_transform(), params={"suffix": "!"})

    r = verify_reachable(root, child)
    assert not r.ok
    assert any(e.startswith(ghost) and "missing object" in e for e in r.errors)
