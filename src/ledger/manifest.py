from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

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

def node_manifest_path(repo_root: Path, node_id: str) -> Path:
    return repo_root / "ledger" / "nodes" / f"{node_id}.json"

def write_node_manifest(repo_root: Path, node: Node) -> Path:
    p = node_manifest_path(repo_root, node.id)
    p.parent.mkdir(parents=True, exist_ok=True)

    if p.exists():
        # Append-only invariant: manifests are immutable once created.
        raise FileExistsError(f"Node manifest already exists: {p}")

    payload = node.to_dict()
    txt = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    p.write_text(txt, encoding="utf-8")
    return p

def read_node_manifest(repo_root: Path, node_id: str) -> Dict[str, Any]:
    p = node_manifest_path(repo_root, node_id)
    return json.loads(p.read_text(encoding="utf-8"))
