from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .cas import CasPaths, sha256_file
from .manifest import is_node_id, load_node_manifest, node_manifest_path
from .replay import replay_node

@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    errors: List[str]


def _check_node(repo_root: Path, node_id: str) -> Tuple[List[str], Optional[Dict[str, Any]]]:
    """Integrity checks for a single node (no replay).

    Returns (errors, manifest); manifest is None if it is missing or invalid.
    """
    m, errors = load_node_manifest(repo_root, node_id)
    if not is_node_id(node_id):
        # Never build CAS paths from an unvalidated id.
        return errors, None

    # object exists and hash matches
    cas = CasPaths.from_repo_root(repo_root)
    obj = cas.object_path(node_id)
    if not obj.is_file():
        errors.append(f"missing object: {obj}")
    else:
        digest = sha256_file(obj)
        if digest != node_id:
            errors.append(f"object hash mismatch: expected {node_id}, got {digest}")

    # parents reachable (manifest exists); deep validity is verify_reachable's job
    if m is not None:
        for p in m["parents"]:
            pm = node_manifest_path(repo_root, p)
            if not pm.exists():
                errors.append(f"missing parent manifest: {pm}")

    return errors, m


def verify_node(repo_root: Path, node_id: str, replay: bool = False) -> VerifyResult:
    errors, _ = _check_node(repo_root, node_id)

    # optional derivation replay (stronger verification)
    if replay and len(errors) == 0:
        rr = replay_node(repo_root, node_id)
        if not rr.ok:
            errors.extend([f"replay: {e}" for e in rr.errors])

    return VerifyResult(ok=(len(errors) == 0), errors=errors)


def verify_reachable_many(repo_root: Path, root_ids: Iterable[str], replay: bool = False) -> VerifyResult:
    """Verify every node reachable from ``root_ids``.

    Phase 1 checks integrity of the whole reachable graph (manifest schema and
    id binding, object hashes, parent manifests) and rejects cycles. Phase 2,
    only when ``replay`` is requested and phase 1 found nothing wrong, replays
    derivations parents-first. No transform runs unless the entire reachable
    closure is structurally sound.
    """
    errors: List[str] = []
    ACTIVE, DONE = 1, 2
    state: Dict[str, int] = {}
    topo: List[str] = []  # post-order: parents before children

    def enter(nid: str) -> Iterator[str]:
        state[nid] = ACTIVE
        errs, m = _check_node(repo_root, nid)
        errors.extend(f"{nid}: {e}" for e in errs)
        return iter(m["parents"] if m is not None else [])

    for root in root_ids:
        if state.get(root) == DONE:
            continue
        stack: List[Tuple[str, Iterator[str]]] = [(root, enter(root))]
        while stack:
            nid, parents = stack[-1]
            parent = next(parents, None)
            if parent is None:
                state[nid] = DONE
                topo.append(nid)
                stack.pop()
                continue
            st = state.get(parent)
            if st == DONE:
                continue  # shared ancestor, already verified
            if st == ACTIVE:
                path = [n for n, _ in stack]
                cycle = path[path.index(parent):] + [parent]
                errors.append(f"{nid}: cycle detected: {' -> '.join(cycle)}")
                continue
            stack.append((parent, enter(parent)))

    if replay and not errors:
        for nid in topo:
            rr = replay_node(repo_root, nid)
            if not rr.ok:
                errors.extend(f"{nid}: replay: {e}" for e in rr.errors)

    return VerifyResult(ok=(len(errors) == 0), errors=errors)


def verify_reachable(repo_root: Path, root_id: str, replay: bool = False) -> VerifyResult:
    return verify_reachable_many(repo_root, [root_id], replay=replay)
