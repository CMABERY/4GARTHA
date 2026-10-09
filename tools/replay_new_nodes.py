from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from _gitdiff import diff_name_status
from ledger.manifest import is_node_id
from ledger.replay import replay_node
from ledger.verify import verify_reachable_many

NODES_PREFIX = "ledger/nodes/"


def _repo_root() -> Path:
    # tools/replay_new_nodes.py -> repo root is parent of tools/
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Verify node manifests added in a diff range (integrity of each new node and every "
            "reachable ancestor), then replay their derivations"
        ),
    )
    ap.add_argument(
        "base_ref",
        help="Base commit/tree. Default range is <base_ref>...HEAD (changes since the merge-base).",
    )
    ap.add_argument(
        "--direct",
        action="store_true",
        help="Compare <base_ref> and HEAD directly (git diff <base_ref> HEAD). Use for push ranges and the empty tree.",
    )
    args = ap.parse_args(argv)

    repo_root = _repo_root()

    try:
        # --no-renames: a manifest moved into ledger/nodes/ must count as added.
        entries = diff_name_status(args.base_ref, direct=args.direct, extra_args=["--no-renames"])
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        print(f"failed running git diff: {e}", file=sys.stderr)
        return 3

    new_node_ids: set[str] = set()
    bad_paths: list[str] = []
    for status, paths in entries:
        if status[:1] != "A":
            continue
        for p in paths:
            if not p.startswith(NODES_PREFIX) or not p.endswith(".json"):
                continue
            node_id = p[len(NODES_PREFIX) : -len(".json")]
            if is_node_id(node_id):
                new_node_ids.add(node_id)
            else:
                # Would otherwise never be verified.
                bad_paths.append(p)

    if bad_paths:
        print("replay check FAILED: non-canonical node manifest path(s)", file=sys.stderr)
        for p in bad_paths:
            print(f"  {p!r} (expected ledger/nodes/<64 lowercase hex>.json)", file=sys.stderr)
        return 2

    if not new_node_ids:
        print("replay check: no new nodes")
        return 0

    ordered = sorted(new_node_ids)

    # 1) Integrity first: manifests, objects, parents and every reachable
    #    ancestor (with cycle detection). Nothing is executed unless this passes.
    vr = verify_reachable_many(repo_root, ordered, replay=False)
    if not vr.ok:
        print("replay check FAILED (integrity verification)", file=sys.stderr)
        for e in vr.errors:
            print(f"  {e}", file=sys.stderr)
        return 2

    # 2) Replay derivations of the new nodes (root/admission nodes have none).
    failures: list[tuple[str, list[str]]] = []
    for nid in ordered:
        rr = replay_node(repo_root, nid)
        if not rr.ok:
            failures.append((nid, rr.errors))

    if failures:
        print("replay check FAILED", file=sys.stderr)
        for nid, errs in failures:
            print(f"  node: {nid}", file=sys.stderr)
            for e in errs:
                print(f"    {e}", file=sys.stderr)
        return 2

    print(f"replay check: OK ({len(ordered)} new node(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
