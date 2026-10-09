"""Shared `git diff --name-status -z` helpers for the governance tools.

Paths are read NUL-delimited so Git never quotes or escapes them (tabs,
newlines, quotes and non-ASCII bytes all arrive verbatim). They are decoded
with os.fsdecode so non-UTF-8 names round-trip instead of crashing.
"""
from __future__ import annotations

import os
import subprocess
from typing import List, Optional, Sequence, Tuple

Entry = Tuple[str, List[str]]  # (status, paths); renames/copies carry [old, new]


def parse_name_status_z(out: bytes) -> List[Entry]:
    tokens = out.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    entries: List[Entry] = []
    i = 0
    while i < len(tokens):
        status = tokens[i].decode("ascii")
        npaths = 2 if status[:1] in ("R", "C") else 1
        paths = [os.fsdecode(t) for t in tokens[i + 1 : i + 1 + npaths]]
        if len(paths) != npaths:
            raise ValueError(f"truncated git diff -z record for status {status!r}")
        entries.append((status, paths))
        i += 1 + npaths
    return entries


def diff_name_status(
    base_ref: Optional[str] = None,
    *,
    cached: bool = False,
    direct: bool = False,
    extra_args: Sequence[str] = (),
) -> List[Entry]:
    """Return (status, paths) entries for the requested comparison.

    - cached: staged changes (index vs HEAD)
    - direct: compare the trees of <base_ref> and HEAD (`git diff base HEAD`);
      works with a bare tree such as the empty tree and sees deletions caused
      by rewritten history
    - otherwise: changes since merge-base(<base_ref>, HEAD) (`base...HEAD`)
    """
    cmd = ["git", "-c", "core.quotePath=false", "diff", "--name-status", "-z", *extra_args]
    if cached:
        cmd.append("--cached")
    elif direct:
        cmd += [base_ref or "HEAD~1", "HEAD"]
    else:
        cmd.append(f"{base_ref or 'HEAD~1'}...HEAD")
    cmd.append("--")
    out = subprocess.check_output(cmd)
    return parse_name_status_z(out)
