from __future__ import annotations

import argparse
import subprocess
import sys

PROTECTED_PREFIXES = ("ledger/objects/", "ledger/nodes/")


def _touches_protected(paths: list[str]) -> bool:
    return any(p.startswith(PROTECTED_PREFIXES) for p in paths)


def _parse_name_status_line(line: str) -> tuple[str, list[str]]:
    """Parse a single `git diff --name-status` line.

    Expected formats (tab-delimited):
      - "M\tpath"
      - "A\tpath"
      - "D\tpath"
      - "R100\told\tnew" (rename)
      - "C100\told\tnew" (copy)
    """
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        # Extremely defensive: fall back to whitespace split.
        parts = line.split()
    status = parts[0]
    paths = [p for p in parts[1:] if p]
    return status, paths

def main() -> int:
    # In CI on GitHub Actions, base SHA is available in GITHUB_BASE_REF context only for PRs.
    # We'll diff against origin/<base> when present; otherwise diff against HEAD~1.
    # This script is deliberately conservative: it rejects any *modification* or *deletion*
    # within protected prefixes.
    #
    # Allowed:
    #   A  ledger/objects/...
    #   A  ledger/nodes/...
    # Anything else within those prefixes => fail.

    # Determine diff range.
    # If running in a PR checkout, 'origin/<base>' exists.
    ap = argparse.ArgumentParser(description="Enforce add-only invariant for ledger/nodes and ledger/objects")
    ap.add_argument("base_ref", nargs="?", help="Base ref for diff range <base_ref>...HEAD")
    ap.add_argument(
        "--cached",
        action="store_true",
        help="Check staged changes (for use in a pre-commit hook).",
    )
    args = ap.parse_args()

    if args.cached and args.base_ref:
        print("error: pass either base_ref OR --cached, not both", file=sys.stderr)
        return 3

    if args.cached:
        diff_cmd = ["git", "diff", "--cached", "--name-status"]
    else:
        if args.base_ref:
            diff_range = f"{args.base_ref}...HEAD"
        else:
            diff_range = "HEAD~1...HEAD"
        diff_cmd = ["git", "diff", "--name-status", diff_range]

    try:
        out = subprocess.check_output(diff_cmd, text=True)
    except Exception as e:
        print(f"failed running git diff: {e}", file=sys.stderr)
        return 3

    bad: list[tuple[str, list[str]]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        status, paths = _parse_name_status_line(line)
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
        print("append-only invariant violated (nodes/objects must be add-only):", file=sys.stderr)
        for status, paths in bad:
            if len(paths) == 1:
                print(f"  {status}\t{paths[0]}", file=sys.stderr)
            else:
                joined = "\t".join(paths)
                print(f"  {status}\t{joined}", file=sys.stderr)
        return 2

    print("append-only check: OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
