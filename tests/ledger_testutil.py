"""Shared helpers for ledger regression tests (not a test module)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ledger.cas import CasPaths, sha256_bytes
from ledger.manifest import Node, Transform, node_manifest_path, write_node_manifest

REPO = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ADMIT_DIGEST = sha256_bytes(b"admit")


def init_repo(root: Path) -> Path:
    for name in ("nodes", "objects", "refs"):
        (root / "ledger" / name).mkdir(parents=True, exist_ok=True)
    return root


def put_blob(root: Path, data: bytes) -> str:
    """Store bytes in the CAS under their real digest."""
    digest = sha256_bytes(data)
    put_blob_at(root, digest, data)
    return digest


def put_blob_at(root: Path, digest: str, data: bytes) -> Path:
    """Store arbitrary bytes under ``digest`` (may deliberately not match)."""
    path = CasPaths.from_repo_root(root).object_path(digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def write_manifest_raw(root: Path, node_id: str, obj: Any) -> Path:
    """Write a manifest without validation, to exercise verifier/replay rejection."""
    path = node_manifest_path(root, node_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
    return path


def manifest_dict(node_id: str, parents: Iterable[str], digest: str = ADMIT_DIGEST, **transform: Any) -> Dict[str, Any]:
    t: Dict[str, Any] = {"name": "t", "digest": digest, "params": {}}
    t.update(transform)
    return {"id": node_id, "parents": list(parents), "transform": t}


def admit(root: Path, data: bytes) -> str:
    """Valid root/admission node (object + manifest)."""
    node_id = put_blob(root, data)
    write_node_manifest(root, Node(node_id, [], Transform("admit", ADMIT_DIGEST, {})))
    return node_id


def derive(
    root: Path,
    data: bytes,
    parents: List[str],
    transform_code: bytes,
    params: Optional[Dict[str, Any]] = None,
) -> str:
    """Valid derived node whose transform is stored in the CAS."""
    node_id = put_blob(root, data)
    t_digest = put_blob(root, transform_code)
    write_node_manifest(
        root,
        Node(node_id, list(parents), Transform("t", t_digest, params or {}, runner=[PYTHON])),
    )
    return node_id


def concat_transform() -> bytes:
    return (REPO / "transforms" / "concat_parents.py").read_bytes()


def marker_transform(marker: Path, output: bytes) -> bytes:
    """Transform that records that it ran, then writes fixed output bytes."""
    return (
        "import sys\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
        f"Path(sys.argv[sys.argv.index('--out') + 1]).write_bytes({output!r})\n"
    ).encode("utf-8")


def identity_marker_transform(marker: Path) -> bytes:
    """Transform that records that it ran, then copies its first parent."""
    return (
        "import json, sys\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
        "a = sys.argv\n"
        "pm = json.loads(Path(a[a.index('--parents-manifest') + 1]).read_text())\n"
        "pd = Path(a[a.index('--parents-dir') + 1])\n"
        "Path(a[a.index('--out') + 1]).write_bytes((pd / pm[0]['path']).read_bytes())\n"
    ).encode("utf-8")


def cli_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(os.environ)
    env.pop("LEDGER_INGEST_SESSION_LOCK", None)
    if extra:
        env.update(extra)
    return env


def run_cli(root: Path, *args: str, env: Optional[Dict[str, str]] = None, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, "-m", "ledger.cli", *args],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env if env is not None else cli_env(),
    )


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout.strip()


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-q", "--allow-empty", "-m", message)
    return git(root, "rev-parse", "HEAD")
