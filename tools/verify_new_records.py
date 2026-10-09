"""Verify ledger records added in a diff range (CI gate).

Default (CI): verify-only. Every new record and its entire lineage is checked
against the `integrity` profile; NO TRANSFORM CODE IS EXECUTED. Derivation
replay is disabled in CI until replay runs inside an enforced isolation
boundary (ASSURANCE.md, "P0: no transform execution in CI").

--replay (local use only) additionally replays derivations and requires the
`replay-if-derived` profile. It executes transform code without isolation.

Also enforces the identity-model freeze: legacy v0 node manifests
(ledger/nodes/*) are not admissible, and every path added under
ledger/records/ must be <64 lowercase hex>.json.

Exit: 0 profile satisfied (or nothing new); 2 not satisfied / inadmissible
paths; 3 inconclusive (ERROR) or git failure.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from _gitdiff import diff_name_status
from ledger import records
from ledger.assurance import PROFILES, Dimension, evaluate
from ledger.verifier import verify

RECORDS_PREFIX = "ledger/records/"
LEGACY_NODES_PREFIX = "ledger/nodes/"
KEEP = ".keep"


def _repo_root() -> Path:
    # tools/verify_new_records.py -> repo root is the parent of tools/
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("base_ref", help="Base commit/tree. Default range is <base_ref>...HEAD.")
    ap.add_argument(
        "--direct",
        action="store_true",
        help="Compare <base_ref> and HEAD directly. Use for push ranges and the empty tree.",
    )
    ap.add_argument(
        "--replay",
        action="store_true",
        help="Also replay derivations (EXECUTES CODE, no isolation). Never used in CI.",
    )
    args = ap.parse_args(argv)
    repo_root = _repo_root()

    try:
        # --no-renames: a file moved into ledger/records/ must count as added.
        entries = diff_name_status(args.base_ref, direct=args.direct, extra_args=["--no-renames"])
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        print(f"failed running git diff: {e}", file=sys.stderr)
        return 3

    new_ids: set[str] = set()
    bad: list[str] = []
    for status, paths in entries:
        if status[:1] != "A":
            continue
        for p in paths:
            if p.startswith(LEGACY_NODES_PREFIX) and p != LEGACY_NODES_PREFIX + KEEP:
                bad.append(f"{p!r}: legacy v0 node manifests are not admissible (use 4gartha.record/1 records)")
            elif p.startswith(RECORDS_PREFIX) and p != RECORDS_PREFIX + KEEP:
                name = p[len(RECORDS_PREFIX):]
                rid = name[: -len(".json")] if name.endswith(".json") else None
                if rid is not None and records.is_digest(rid):
                    new_ids.add(rid)
                else:
                    bad.append(f"{p!r}: expected ledger/records/<64 lowercase hex>.json")

    if bad:
        print("record check FAILED: inadmissible path(s)", file=sys.stderr)
        for b in bad:
            print(f"  {b}", file=sys.stderr)
        return 2

    if not new_ids:
        print("record check: no new records")
        return 0

    profile = PROFILES["replay-if-derived" if args.replay else "integrity"]
    report = verify(repo_root, sorted(new_ids), replay=args.replay)
    result = evaluate(report, profile)

    stream = sys.stdout if result.satisfied else sys.stderr
    verdict = "SATISFIED" if result.satisfied else "NOT SATISFIED"
    print(f"record check: {len(new_ids)} new record(s), {report.records_checked} in lineage; "
          f"profile {profile.name}: {verdict}", file=stream)
    for dim in Dimension:
        oc = report.outcomes[dim]
        print(f"  {dim.value:<24} {oc.status.value:<15} {oc.detail}", file=stream)
        for prob in oc.problems:
            for line in prob.splitlines():
                print(f"      {line}", file=stream)
    if not args.replay:
        print("  (derivation replay is disabled here: no transform code was executed)", file=stream)
    if result.satisfied:
        return 0
    return 3 if result.error else 2


if __name__ == "__main__":
    raise SystemExit(main())
