"""Finding 3: manifests must match the node schema and be bound to their id.

Follow-up 4: every digest (id, parents, transform.digest, transform.env_digest)
is exactly 64 lowercase hex chars; Python's `$` alone admits a trailing newline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ledger.manifest import Node, Transform, node_manifest_path, write_node_manifest
from ledger.replay import replay_node
from ledger.verify import verify_node, verify_reachable

from ledger_testutil import (
    ADMIT_DIGEST,
    REPO,
    admit,
    concat_transform,
    derive,
    init_repo,
    manifest_dict,
    put_blob,
    run_cli,
    write_manifest_raw,
)


def test_packaged_schema_matches_repository_schema() -> None:
    packaged = json.loads((REPO / "src" / "ledger" / "node.schema.json").read_text(encoding="utf-8"))
    documented = json.loads((REPO / "ledger" / "schema" / "node.schema.json").read_text(encoding="utf-8"))
    assert packaged == documented


def test_empty_manifest_fails_verification(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"valid bytes")
    write_manifest_raw(root, digest, {})

    r = verify_node(root, digest)
    assert not r.ok
    assert any("'id' is a required property" in e for e in r.errors)
    assert any("'parents' is a required property" in e for e in r.errors)
    assert any("'transform' is a required property" in e for e in r.errors)
    assert not verify_reachable(root, digest, replay=True).ok
    assert not replay_node(root, digest).ok


def test_manifest_id_must_equal_requested_id(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"valid bytes")
    write_manifest_raw(root, digest, manifest_dict("0" * 64, []))

    r = verify_node(root, digest)
    assert not r.ok
    assert any("manifest id mismatch" in e for e in r.errors)
    assert not verify_reachable(root, digest, replay=True).ok


def test_missing_parents_is_not_a_root_admission(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"valid bytes")
    m = manifest_dict(digest, [])
    del m["parents"]
    write_manifest_raw(root, digest, m)

    assert not verify_node(root, digest).ok
    # Replay used to treat the missing list as "no parents" and report OK.
    rr = replay_node(root, digest)
    assert not rr.ok
    assert any("'parents' is a required property" in e for e in rr.errors)


@pytest.mark.parametrize("field", ["digest", "params", "name"])
def test_transform_required_fields(tmp_path: Path, field: str) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"valid bytes")
    m = manifest_dict(digest, [])
    del m["transform"][field]
    write_manifest_raw(root, digest, m)

    r = verify_node(root, digest)
    assert not r.ok
    assert any(f"'{field}' is a required property" in e for e in r.errors)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(parents=["not-a-digest"]),
        lambda m: m["transform"].update(digest="ABC"),
        lambda m: m["transform"].update(params=[]),
        lambda m: m["transform"].update(runner="python3"),
        lambda m: m.update(unexpected=True),
    ],
    ids=["bad-parent", "bad-digest", "params-not-object", "runner-not-array", "extra-field"],
)
def test_schema_shape_violations_fail(tmp_path: Path, mutate) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"valid bytes")
    m = manifest_dict(digest, [])
    mutate(m)
    write_manifest_raw(root, digest, m)
    assert not verify_node(root, digest).ok


def test_malformed_json_is_a_verification_failure_not_a_crash(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"valid bytes")
    write_manifest_raw(root, digest, "{not json")

    r = verify_node(root, digest)
    assert not r.ok
    assert any("unreadable manifest" in e for e in r.errors)
    assert not verify_reachable(root, digest).ok

    proc = run_cli(root, "verify", digest)
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr


def test_invalid_node_id_is_rejected_without_path_lookup(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    r = verify_node(root, "../../etc/passwd")
    assert not r.ok
    assert any("invalid node id" in e for e in r.errors)
    assert not replay_node(root, "../../etc/passwd").ok


def test_valid_root_and_derived_nodes_still_verify(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    p1 = admit(root, b"hello")
    p2 = admit(root, b"world")
    child = derive(root, b"helloworld!", [p1, p2], concat_transform(), params={"suffix": "!"})

    assert verify_node(root, p1).ok
    assert verify_node(root, child, replay=True).ok
    assert verify_reachable(root, child, replay=True).ok
    assert run_cli(root, "verify-reachable", child, "--replay").stdout.strip() == "OK"


def test_writer_rejects_invalid_manifests(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    digest = put_blob(root, b"x")

    with pytest.raises(ValueError, match="itself as a parent"):
        write_node_manifest(root, Node(digest, [digest], Transform("t", ADMIT_DIGEST, {})))
    with pytest.raises(ValueError, match="schema"):
        write_node_manifest(root, Node(digest, ["nope"], Transform("t", ADMIT_DIGEST, {})))
    with pytest.raises(ValueError, match="schema"):
        write_node_manifest(root, Node("../escape", [], Transform("t", ADMIT_DIGEST, {})))
    assert not node_manifest_path(root, digest).exists()
    assert not (root / "ledger" / "escape.json").exists()

    write_node_manifest(root, Node(digest, [], Transform("t", ADMIT_DIGEST, {})))
    with pytest.raises(FileExistsError):
        write_node_manifest(root, Node(digest, [], Transform("t", ADMIT_DIGEST, {})))


DIGEST_FIELDS = {
    "id": "manifest.id",
    "parent": "manifest.parents[0]",
    "transform.digest": "manifest.transform.digest",
    "transform.env_digest": "manifest.transform.env_digest",
}


@pytest.mark.parametrize("field", list(DIGEST_FIELDS))
def test_trailing_newline_digest_fails_verification(tmp_path: Path, field: str) -> None:
    root = init_repo(tmp_path)
    node = put_blob(root, b"node")
    parent = admit(root, b"parent")
    m = manifest_dict(node, [parent], env_digest="c" * 64)
    if field == "id":
        m["id"] = node + "\n"
    elif field == "parent":
        m["parents"] = [parent + "\n"]
    elif field == "transform.digest":
        m["transform"]["digest"] = "b" * 64 + "\n"  # review case: 65 chars
    else:
        m["transform"]["env_digest"] = "c" * 64 + "\n"
    write_manifest_raw(root, node, m)

    r = verify_node(root, node)
    assert not r.ok
    assert any(e.startswith(f"schema: {DIGEST_FIELDS[field]}:") and "too long" in e for e in r.errors), r.errors
    assert not verify_reachable(root, node).ok


@pytest.mark.parametrize("field", list(DIGEST_FIELDS))
def test_writer_rejects_trailing_newline_digest(tmp_path: Path, field: str) -> None:
    root = init_repo(tmp_path)
    node_id, parents, digest, env = "a" * 64, ["d" * 64], "b" * 64, "c" * 64
    if field == "id":
        node_id += "\n"  # review case: file was written, then unverifiable
    elif field == "parent":
        parents = [parents[0] + "\n"]
    elif field == "transform.digest":
        digest += "\n"
    else:
        env += "\n"

    with pytest.raises(ValueError, match="invalid node manifest"):
        write_node_manifest(root, Node(node_id, parents, Transform("t", digest, {}, env_digest=env)))
    assert list((root / "ledger" / "nodes").iterdir()) == []


def test_exact_digests_are_still_accepted(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    node = put_blob(root, b"node")
    write_node_manifest(root, Node(node, [], Transform("t", "b" * 64, {}, env_digest="c" * 64)))
    assert verify_node(root, node).ok
