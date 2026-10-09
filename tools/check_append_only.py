from __future__ import annotations

import argparse
import subprocess
import sys

from _gitdiff import diff_name_status

# ledger/nodes/ is the retired v0 location; kept protected so it stays empty.
PROTECTED_PREFIXES = ("ledger/objects/", "ledger/records/", "ledger/nodes/")


def _touches_protected(paths: list[str]) -> bool:
    return any(p.startswith(PROTECTED_PREFIXES) for p in paths)


def main() -> int:
    # This script is deliberately conservative: it rejects any *modification* or *deletion*
    # within protected prefixes.
    #
    # Allowed:
    #   A  ledger/objects/...
    #   A  ledger/records/...
    # Anything else within those prefixes => fail.
    #
    # Paths come from `git diff --name-status -z`, so names containing tabs,
    # newlines or quotes are compared verbatim (never as Git's quoted form).
    ap = argparse.ArgumentParser(description="Enforce add-only invariant for ledger/objects, ledger/records and ledger/nodes")
    ap.add_argument(
        "base_ref",
        nargs="?",
        help="Base commit/tree. Default range is <base_ref>...HEAD (changes since the merge-base); default base HEAD~1.",
    )
    ap.add_argument(
        "--direct",
        action="store_true",
        help="Compare <base_ref> and HEAD directly (git diff <base_ref> HEAD). Use for push ranges and the empty tree.",
    )
    ap.add_argument(
        "--cached",
        action="store_true",
        help="Check staged changes (for use in a pre-commit hook).",
    )
    args = ap.parse_args()

    if args.cached and (args.base_ref or args.direct):
        print("error: pass either base_ref [--direct] OR --cached, not both", file=sys.stderr)
        return 3

    try:
        entries = diff_name_status(args.base_ref, cached=args.cached, direct=args.direct)
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        print(f"failed running git diff: {e}", file=sys.stderr)
        return 3

    bad: list[tuple[str, list[str]]] = []
    for status, paths in entries:
        status_code = status[:1]  # e.g. "R" from "R100"

        if _touches_protected(paths):
            # Only additions are allowed under protected prefixes.
            # Renames/copies report two paths; treat those as violations.
            if status_code != "A":
                bad.append((status, paths))
            elif len(paths) != 1:
                # Extremely defensive: an "A" line is expected to have a single path.
                bad.append((status, paths))

    if bad:
        print("append-only invariant violated (objects/records must be add-only):", file=sys.stderr)
        for status, paths in bad:
            if len(paths) == 1:
                print(f"  {status}\t{paths[0]!r}", file=sys.stderr)
            else:
                joined = "\t".join(repr(p) for p in paths)
                print(f"  {status}\t{joined}", file=sys.stderr)
        return 2

    print("append-only check: OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
