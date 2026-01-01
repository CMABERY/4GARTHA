#!/usr/bin/env python3

"""Example replayable transform (v0).

Deterministically concatenates the bytes of ordered parents and writes the result to --out.
Ignores params except for an optional "suffix" string which is appended UTF-8.

This is intentionally minimal: the point is the interface, not the operation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parents-manifest", required=True)
    ap.add_argument("--parents-dir", required=True)
    ap.add_argument("--params-path", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    parents_manifest = json.loads(Path(args.parents_manifest).read_text(encoding="utf-8"))
    params = json.loads(Path(args.params_path).read_text(encoding="utf-8"))

    out = bytearray()
    parents_dir = Path(args.parents_dir)
    for item in parents_manifest:
        # parents_manifest is ordered; do not sort.
        rel = item["path"]
        out.extend((parents_dir / rel).read_bytes())

    suffix = params.get("suffix")
    if isinstance(suffix, str):
        out.extend(suffix.encode("utf-8"))

    Path(args.out).write_bytes(bytes(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
