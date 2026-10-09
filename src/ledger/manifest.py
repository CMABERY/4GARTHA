from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# A node id / CAS digest: exactly 64 lowercase hex chars. Always use fullmatch:
# Python's `$` also matches before a trailing newline. The node schema pairs the
# same pattern with minLength/maxLength 64 so it is exact under any regex dialect.
NODE_ID_RE = re.compile(r"[a-f0-9]{64}")

# Packaged copy of ledger/schema/node.schema.json. The verifier's expectations are
# pinned by the installed package, not by the repository under verification.
# tests/test_manifest_validation.py asserts the two copies stay identical.
_NODE_SCHEMA_PATH = Path(__file__).with_name("node.schema.json")


def is_node_id(value: Any) -> bool:
    return isinstance(value, str) and NODE_ID_RE.fullmatch(value) is not None


@dataclass(frozen=True)
class Transform:
    name: str
    digest: str
    params: Dict[str, Any]
    # Replay contract (optional; semantic if present):
    # - runner: command prefix used for replay, e.g. ["python3"]
    # - env_digest: hash of an environment description (lockfile, nix flake, container recipe, etc.)
    runner: List[str] | None = None
    env_digest: str | None = None

@dataclass(frozen=True)
class Node:
    id: str
    parents: List[str]
    transform: Transform
    meta: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "parents": list(self.parents),
            "transform": {
                "name": self.transform.name,
                "digest": self.transform.digest,
                "params": self.transform.params,
            },
        }
        # Optional replay contract fields (semantic if present).
        if self.transform.runner is not None:
            d["transform"]["runner"] = list(self.transform.runner)
        if self.transform.env_digest is not None:
            d["transform"]["env_digest"] = self.transform.env_digest
        if self.meta is not None:
            d["meta"] = self.meta
        return d


@lru_cache(maxsize=1)
def _node_schema_validator() -> Any:
    from jsonschema import Draft202012Validator

    schema = json.loads(_NODE_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _json_path(parts: Any) -> str:
    out = "manifest"
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


def validate_manifest(obj: Any, expected_id: str) -> List[str]:
    """Return a list of problems with a parsed node manifest (empty == valid).

    Checks, in order:
      - the id it is requested/stored under is an exact 64-hex digest
      - structure against the node schema (required fields, types, exact
        digest formats for id, parents, transform.digest, transform.env_digest)
      - manifest.id is bound to the id it was requested/stored under
      - the node does not list itself as a parent (trivial derivation cycle)
    """
    errors: List[str] = []
    if not is_node_id(expected_id):
        errors.append(f"invalid node id: {expected_id!r} (expected 64 lowercase hex chars)")
    validator = _node_schema_validator()
    schema_errors = sorted(
        validator.iter_errors(obj),
        key=lambda e: ([str(p) for p in e.absolute_path], e.message),
    )
    for e in schema_errors:
        errors.append(f"schema: {_json_path(e.absolute_path)}: {e.message}")

    if isinstance(obj, dict):
        mid = obj.get("id")
        if isinstance(mid, str) and mid != expected_id:
            errors.append(f"manifest id mismatch: expected {expected_id}, got {mid}")
        parents = obj.get("parents")
        if isinstance(parents, list) and expected_id in parents:
            errors.append(f"node lists itself as a parent (cycle): {expected_id}")
    return errors


def node_manifest_path(repo_root: Path, node_id: str) -> Path:
    return repo_root / "ledger" / "nodes" / f"{node_id}.json"


def load_node_manifest(repo_root: Path, node_id: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Read and validate the manifest for ``node_id``.

    Returns ``(manifest, [])`` on success or ``(None, errors)`` on any failure.
    Never raises for missing, unreadable, malformed or schema-invalid manifests.
    """
    if not is_node_id(node_id):
        return None, [f"invalid node id: {node_id!r} (expected 64 lowercase hex chars)"]

    mp = node_manifest_path(repo_root, node_id)
    if not mp.exists():
        return None, [f"missing manifest: {mp}"]
    try:
        obj = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return None, [f"unreadable manifest {mp}: {e}"]

    errors = validate_manifest(obj, node_id)
    if errors:
        return None, errors
    return obj, []


def write_node_manifest(repo_root: Path, node: Node) -> Path:
    payload = node.to_dict()
    errors = validate_manifest(payload, node.id)
    if errors:
        raise ValueError("invalid node manifest: " + "; ".join(errors))

    p = node_manifest_path(repo_root, node.id)
    p.parent.mkdir(parents=True, exist_ok=True)

    txt = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    # Append-only invariant: manifests are immutable once created. Exclusive
    # creation makes the existence check and the create a single atomic step.
    try:
        with p.open("x", encoding="utf-8") as f:
            f.write(txt)
    except FileExistsError:
        raise FileExistsError(f"Node manifest already exists: {p}") from None
    return p

def read_node_manifest(repo_root: Path, node_id: str) -> Dict[str, Any]:
    """Raw (unvalidated) manifest read. Prefer load_node_manifest for verification."""
    p = node_manifest_path(repo_root, node_id)
    return json.loads(p.read_text(encoding="utf-8"))
