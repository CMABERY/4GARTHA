"""Resolve the immutable diff base for the ledger governance gates in CI.

Reads the GitHub Actions event (GITHUB_EVENT_NAME, GITHUB_EVENT_PATH) and
emits ``base=<sha>`` and ``diff_args=<flags>`` for check_append_only.py and
verify_new_records.py (to stdout, and to $GITHUB_OUTPUT when set):

  pull_request       base = pull_request.base.sha; range base...HEAD
                     (the PR's own changes, measured from the merge-base)
  push               base = event.before; compared directly with HEAD
                     (--direct) so the whole pushed range is covered,
                     including deletions from rewritten history
  push (new branch)  before is all zeros -> base = empty tree, --direct
                     (every file at HEAD counts as added)
  workflow_dispatch  base = empty tree, --direct: full audit of every node
                     manifest at HEAD (there is no event-provided base)

Any other event fails closed. The base must be a full hex object id and
must exist locally (one fetch attempt is made otherwise).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, Tuple

_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")  # use fullmatch: `$` allows a trailing newline


class ResolveError(Exception):
    pass


def _git(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", *args], capture_output=True, text=True, env=env)


def _empty_tree() -> str:
    proc = subprocess.run(
        ["git", "hash-object", "-t", "tree", "--stdin"], input="", capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise ResolveError(f"cannot compute empty tree id: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _require_sha(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ResolveError(f"{what} is missing or not a full object id: {value!r}")
    return value


def resolve(event_name: str, event: Dict[str, Any]) -> Tuple[str, str]:
    """Return (base, diff_args)."""
    if event_name == "pull_request":
        pr = event.get("pull_request") or {}
        base = _require_sha((pr.get("base") or {}).get("sha"), "pull_request.base.sha")
        return base, ""
    if event_name == "push":
        before = _require_sha(event.get("before"), "push before")
        if set(before) == {"0"}:
            return _empty_tree(), "--direct"
        return before, "--direct"
    if event_name == "workflow_dispatch":
        return _empty_tree(), "--direct"
    raise ResolveError(f"unsupported event {event_name!r}; refusing to guess a diff base")


def _ensure_available(base: str) -> None:
    if _git("cat-file", "-e", f"{base}^{{tree}}").returncode == 0:
        return
    _git("fetch", "--no-tags", "--quiet", "origin", base)
    if _git("cat-file", "-e", f"{base}^{{tree}}").returncode != 0:
        raise ResolveError(f"diff base {base} is not available in this checkout")


def main() -> int:
    try:
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if not event_name or not event_path:
            raise ResolveError("GITHUB_EVENT_NAME and GITHUB_EVENT_PATH must be set")
        with open(event_path, encoding="utf-8") as f:
            event = json.load(f)
        base, diff_args = resolve(event_name, event)
        _ensure_available(base)
    except (OSError, ValueError, ResolveError) as e:
        print(f"ci_diff_base: {e}", file=sys.stderr)
        return 1

    head = _git("rev-parse", "HEAD").stdout.strip()
    lines = [f"base={base}", f"diff_args={diff_args}"]
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)
    print(f"event={event_name} head={head}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
