from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Set

from .cas import CasPaths, sha256_file
from .manifest import node_manifest_path, read_node_manifest
from .replay import replay_node

@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    errors: List[str]

def verify_node(repo_root: Path, node_id: str, replay: bool = False) -> VerifyResult:
    errors: List[str] = []

    # 1) manifest exists
    mp = node_manifest_path(repo_root, node_id)
    if not mp.exists():
        return VerifyResult(False, [f"missing manifest: {mp}"])

    # 2) object exists and hash matches
    cas = CasPaths.from_repo_root(repo_root)
    obj = cas.object_path(node_id)
    if not obj.exists():
        errors.append(f"missing object: {obj}")
    else:
        digest = sha256_file(obj)
        if digest != node_id:
            errors.append(f"object hash mismatch: expected {node_id}, got {digest}")

    # 3) parents reachable (manifest exists)
    m = read_node_manifest(repo_root, node_id)
    parents = m.get("parents", [])
    if not isinstance(parents, list):
        errors.append("manifest.parents not a list")
        parents = []

    for p in parents:
        if not isinstance(p, str) or len(p) != 64:
            errors.append(f"invalid parent id: {p!r}")
            continue
        pm = node_manifest_path(repo_root, p)
        if not pm.exists():
            errors.append(f"missing parent manifest: {pm}")

    # 4) optional derivation replay (stronger verification)
    if replay and len(errors) == 0:
        rr = replay_node(repo_root, node_id)
        if not rr.ok:
            errors.extend([f"replay: {e}" for e in rr.errors])

    return VerifyResult(ok=(len(errors) == 0), errors=errors)

def verify_reachable(repo_root: Path, root_id: str, replay: bool = False) -> VerifyResult:
    # DFS with memoization; validates all reachable nodes.
    errors: List[str] = []
    seen: Set[str] = set()
    stack: List[str] = [root_id]

    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)

        r = verify_node(repo_root, nid, replay=replay)
        if not r.ok:
            errors.extend([f"{nid}: {e}" for e in r.errors])

        try:
            m = read_node_manifest(repo_root, nid)
            parents = m.get("parents", [])
            if isinstance(parents, list):
                for p in parents:
                    if isinstance(p, str) and len(p) == 64:
                        stack.append(p)
        except Exception as e:
            errors.append(f"{nid}: failed reading manifest: {e}")

    return VerifyResult(ok=(len(errors) == 0), errors=errors)
