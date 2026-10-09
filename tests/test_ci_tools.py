"""Findings 4, 5, 10: CI governance tools.

- replay_new_nodes.py verifies new nodes and reachable ancestors before replay
- push events are compared against the pre-push commit (ci_diff_base.py)
- Git paths are parsed NUL-delimited, so quoted names cannot bypass checks
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ledger.cas import sha256_bytes

from ledger_testutil import (
    PYTHON,
    REPO,
    admit,
    cli_env,
    commit_all,
    concat_transform,
    derive,
    git,
    init_repo,
    manifest_dict,
    marker_transform,
    put_blob,
    put_blob_at,
    write_manifest_raw,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")

TOOLS = REPO / "tools"


def _git_repo(root: Path) -> Path:
    init_repo(root)
    for keep in ("nodes", "objects", "refs"):
        (root / "ledger" / keep / ".keep").write_text("")
    # replay_new_nodes.py treats the parent of its own tools/ dir as the repo.
    (root / "tools").mkdir()
    for name in ("replay_new_nodes.py", "_gitdiff.py"):
        shutil.copyfile(TOOLS / name, root / "tools" / name)
    git(root, "init", "-q")
    commit_all(root, "baseline")
    return root


def _run(root: Path, script: Path, *args: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, str(script), *args], cwd=root, capture_output=True, text=True, timeout=120,
        env=env if env is not None else cli_env(),
    )


def _replay_tool(root: Path, *args: str) -> subprocess.CompletedProcess:
    return _run(root, root / "tools" / "replay_new_nodes.py", *args)


def _append_only(root: Path, *args: str) -> subprocess.CompletedProcess:
    return _run(root, TOOLS / "check_append_only.py", *args)


# --- replay_new_nodes.py (finding 4) ---------------------------------------


def test_replay_tool_rejects_root_manifest_without_object(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    ghost = "a" * 64
    write_manifest_raw(root, ghost, manifest_dict(ghost, []))
    commit_all(root, "root node without object")

    proc = _replay_tool(root, "HEAD~1")
    assert proc.returncode == 2, proc.stdout
    assert "missing object" in proc.stderr
    assert "OK" not in proc.stdout


def test_replay_tool_verifies_preexisting_ancestors(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    ghost = sha256_bytes(b"ghost")
    write_manifest_raw(root, ghost, manifest_dict(ghost, []))  # slipped in earlier
    commit_all(root, "old incomplete root")
    derive(root, b"ghost!", [ghost], concat_transform(), params={"suffix": "!"})
    commit_all(root, "new derived node")

    proc = _replay_tool(root, "HEAD~1")
    assert proc.returncode == 2
    assert f"{ghost}: missing object" in proc.stderr


def test_replay_tool_rejects_substituted_transform_without_running_it(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    marker = tmp_path / "ran"
    parent = admit(root, b"parent")
    child = put_blob(root, b"child")
    claimed = sha256_bytes(b"# reviewed transform\n")
    put_blob_at(root, claimed, marker_transform(marker, b"child"))
    write_manifest_raw(root, child, manifest_dict(child, [parent], digest=claimed, runner=[PYTHON]))
    commit_all(root, "derivation with substituted transform")

    proc = _replay_tool(root, "HEAD~1")
    assert proc.returncode == 2
    assert "transform definition hash mismatch" in proc.stderr
    assert not marker.exists()


def test_replay_tool_accepts_valid_new_nodes(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    p = admit(root, b"hello")
    derive(root, b"hello!", [p], concat_transform(), params={"suffix": "!"})
    commit_all(root, "valid nodes")

    proc = _replay_tool(root, "HEAD~1")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "replay check: OK (2 new node(s))"
    assert _replay_tool(root, "HEAD").stdout.strip() == "replay check: no new nodes"


def test_replay_tool_flags_noncanonical_node_paths(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    (root / "ledger" / "nodes" / ("A" * 64 + ".json")).write_text("{}")
    commit_all(root, "uppercase node name")

    proc = _replay_tool(root, "HEAD~1")
    assert proc.returncode == 2
    assert "non-canonical node manifest path" in proc.stderr


# --- check_append_only.py: NUL-delimited paths (finding 10) -------------------


@pytest.mark.parametrize("name", ["bad\tname", "bad\nname", 'bad"name', "café", "back\\slash"])
def test_append_only_sees_names_git_would_quote(tmp_path: Path, name: str) -> None:
    root = _git_repo(tmp_path)
    protected = root / "ledger" / "objects" / name
    protected.write_bytes(b"original")
    commit_all(root, "add odd name")

    protected.write_bytes(b"rewritten")
    git(root, "add", "-A")
    staged = _append_only(root, "--cached")
    assert staged.returncode == 2, staged.stdout
    assert "append-only invariant violated" in staged.stderr

    commit_all(root, "rewrite odd name")
    assert _append_only(root, "HEAD~1").returncode == 2

    protected.unlink()
    git(root, "add", "-A")
    assert _append_only(root, "--cached").returncode == 2


def test_append_only_allows_additions_and_unprotected_changes(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    admit(root, b"new node")
    (root / "README").write_text("docs")
    (root / "ledger" / "refs" / "latest").write_text("x\n")
    git(root, "add", "-A")
    assert _append_only(root, "--cached").returncode == 0
    commit_all(root, "additions")
    (root / "ledger" / "refs" / "latest").write_text("y\n")
    commit_all(root, "move ref")
    proc = _append_only(root, "HEAD~2")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "append-only check: OK"


# --- push range / diff base resolution (finding 5) ---------------------------


def _resolve(root: Path, event_name: str, payload: dict, tmp_path: Path):
    event = tmp_path / f"{event_name}-event.json"
    event.write_text(json.dumps(payload))
    out_file = tmp_path / "github_output"
    out_file.write_text("")
    env = cli_env({"GITHUB_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(out_file)})
    proc = _run(root, TOOLS / "ci_diff_base.py", env=env)
    outputs = dict(line.split("=", 1) for line in out_file.read_text().splitlines() if "=" in line)
    return proc, outputs


def _gate(root: Path, outputs: dict) -> tuple:
    args = [a for a in outputs["diff_args"].split() if a] + [outputs["base"]]
    return _append_only(root, *args), _replay_tool(root, *args)


def test_push_compares_against_before_sha_not_origin_main(tmp_path: Path) -> None:
    # Review reproduction: origin/main == HEAD after a push, so the old
    # workflow compared HEAD with itself and passed a protected rewrite.
    root = _git_repo(tmp_path)
    protected = root / "ledger" / "nodes" / ("a" * 64 + ".json")
    protected.write_text("original")
    before = commit_all(root, "baseline node")
    protected.write_text("rewritten")
    commit_all(root, "rewrite protected file")
    commit_all(root, "later commit in the same push")
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    assert _append_only(root, "origin/main").returncode == 0  # the old, empty comparison

    proc, outputs = _resolve(root, "push", {"before": before, "after": git(root, "rev-parse", "HEAD")}, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert outputs == {"base": before, "diff_args": "--direct"}
    append_only, _ = _gate(root, outputs)
    assert append_only.returncode == 2
    assert "a" * 64 in append_only.stderr


def test_push_range_covers_new_nodes_for_replay(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    before = git(root, "rev-parse", "HEAD")
    ghost = "b" * 64
    write_manifest_raw(root, ghost, manifest_dict(ghost, []))
    commit_all(root, "first pushed commit adds incomplete node")
    (root / "README").write_text("unrelated")
    commit_all(root, "second pushed commit")

    proc, outputs = _resolve(root, "push", {"before": before}, tmp_path)
    assert proc.returncode == 0, proc.stderr
    append_only, replay = _gate(root, outputs)
    assert append_only.returncode == 0
    assert replay.returncode == 2 and "missing object" in replay.stderr


def test_force_push_deleting_a_node_is_detected(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    node = admit(root, b"will vanish")
    before = commit_all(root, "node")
    git(root, "reset", "-q", "--hard", "HEAD~1")
    (root / "README").write_text("rewritten history")
    commit_all(root, "rewritten main")

    proc, outputs = _resolve(root, "push", {"before": before, "forced": True}, tmp_path)
    assert proc.returncode == 0, proc.stderr
    append_only, _ = _gate(root, outputs)
    assert append_only.returncode == 2
    assert node in append_only.stderr


@pytest.mark.parametrize("event_name,payload", [("push", {"before": "0" * 40}), ("workflow_dispatch", {})])
def test_initial_push_and_manual_runs_audit_everything(tmp_path: Path, event_name: str, payload: dict) -> None:
    root = _git_repo(tmp_path)
    p = admit(root, b"hello")
    derive(root, b"hello!", [p], concat_transform(), params={"suffix": "!"})
    commit_all(root, "nodes")
    empty_tree = git(root, "hash-object", "-t", "tree", "/dev/null")

    proc, outputs = _resolve(root, event_name, payload, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert outputs == {"base": empty_tree, "diff_args": "--direct"}
    append_only, replay = _gate(root, outputs)
    assert append_only.returncode == 0, append_only.stderr
    assert replay.returncode == 0, replay.stderr
    assert replay.stdout.strip() == "replay check: OK (2 new node(s))"

    ghost = "c" * 64
    write_manifest_raw(root, ghost, manifest_dict(ghost, []))
    commit_all(root, "incomplete node")
    _, replay = _gate(root, outputs)
    assert replay.returncode == 2


def test_pull_request_uses_base_sha_and_merge_base(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    base = git(root, "rev-parse", "HEAD")
    git(root, "checkout", "-q", "-b", "feature")
    ghost = "d" * 64
    write_manifest_raw(root, ghost, manifest_dict(ghost, []))
    commit_all(root, "PR adds incomplete node")

    proc, outputs = _resolve(root, "pull_request", {"pull_request": {"base": {"sha": base}}}, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert outputs == {"base": base, "diff_args": ""}
    append_only, replay = _gate(root, outputs)
    assert append_only.returncode == 0
    assert replay.returncode == 2 and "missing object" in replay.stderr


@pytest.mark.parametrize(
    "event_name,payload",
    [
        ("schedule", {}),
        ("push", {}),
        ("push", {"before": "main"}),
        ("pull_request", {"pull_request": {"base": {"ref": "main"}}}),
        ("push", {"before": "e" * 40}),  # well-formed but absent object
    ],
    ids=["unknown-event", "push-no-before", "push-symbolic-before", "pr-no-sha", "missing-object"],
)
def test_resolver_fails_closed(tmp_path: Path, event_name: str, payload: dict) -> None:
    root = _git_repo(tmp_path)
    proc, outputs = _resolve(root, event_name, payload, tmp_path)
    assert proc.returncode != 0
    assert outputs == {}


def test_resolver_rejects_sha_with_trailing_newline(tmp_path: Path) -> None:
    root = _git_repo(tmp_path)
    head = git(root, "rev-parse", "HEAD")
    proc, outputs = _resolve(root, "push", {"before": head + "\n"}, tmp_path)
    assert proc.returncode != 0
    assert "not a full object id" in proc.stderr
    assert outputs == {}


def test_workflow_uses_event_resolved_base() -> None:
    wf = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python tools/ci_diff_base.py" in wf
    assert wf.count("steps.diffbase.outputs.base") == 2
    assert "origin/${{ github.base_ref" not in wf
