from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from ledger.replay import replay_node


def _parse_name_status_line(line: str) -> tuple[str, list[str]]:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        parts = line.split()
    status = parts[0]
    paths = [p for p in parts[1:] if p]
    return status, paths


def _repo_root() -> Path:
    # tools/replay_new_nodes.py -> repo root is parent of tools/
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Replay derivations for node manifests added in a diff range",
    )
    ap.add_argument(
        "base_ref",
        help="Base ref for diff range <base_ref>...HEAD (e.g. origin/main)",
    )
    args = ap.parse_args(argv)

    repo_root = _repo_root()

    diff_range = f"{args.base_ref}...HEAD"
    try:
        out = subprocess.check_output(["git", "diff", "--name-status", diff_range], text=True)
    except Exception as e:
        print(f"failed running git diff: {e}", file=sys.stderr)
        return 3

    new_node_ids: list[str] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        status, paths = _parse_name_status_line(line)
        status_code = status[:1]
        if status_code != "A":
            continue
        for p in paths:
            if not p.startswith("ledger/nodes/"):
                continue
            if not p.endswith(".json"):
                continue
            node_id = Path(p).stem
            if len(node_id) == 64:
                new_node_ids.append(node_id)

    if not new_node_ids:
        print("replay check: no new nodes")
        return 0

    failures: list[tuple[str, list[str]]] = []
    for nid in sorted(set(new_node_ids)):
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

    print(f"replay check: OK ({len(set(new_node_ids))} new node(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
