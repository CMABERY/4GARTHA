"""Shared helpers for ledger regression tests (not a test module)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ledger import records
from ledger.assurance import Dimension, Report, Status
from ledger.cas import CasPaths, sha256_bytes
from ledger.verifier import verify

REPO = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def init_repo(root: Path) -> Path:
    for name in ("objects", "records", "refs"):
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


def admit(root: Path, data: bytes, statement: str = "test admission") -> str:
    """Valid admission record (object + record). Returns the record ID."""
    rid, _, _ = records.write(root, records.admission(put_blob(root, data), statement))
    return rid


def derive(
    root: Path,
    data: bytes,
    inputs: List[str],
    transform_code: bytes,
    params: Optional[Dict[str, Any]] = None,
    runtime: str = "python3",
    environment: Optional[bytes] = None,
) -> str:
    """Valid derivation record whose transform (and environment) are in the CAS."""
    env = put_blob(root, environment) if environment is not None else None
    rec = records.derivation(put_blob(root, data), list(inputs), put_blob(root, transform_code),
                             runtime, params or {}, env)
    rid, _, _ = records.write(root, rec)
    return rid


def write_record_raw(root: Path, rid: str, content: Any) -> Path:
    """Store anything under ledger/records/<rid>.json, bypassing validation."""
    path = records.record_path(root, rid)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    elif isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(json.dumps(content, sort_keys=True, separators=(",", ":")).encode())
    return path


def record_of(root: Path, rid: str) -> Dict[str, Any]:
    loaded = records.load(root, rid)
    assert loaded.record is not None, loaded.errors
    return loaded.record


def status(report: Report, dim: Dimension) -> Status:
    return report.outcomes[dim].status


def check(root: Path, rid: str, **kw: Any) -> Report:
    return verify(root, [rid], **kw)


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
    """Transform that records that it ran, then copies its first input."""
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
