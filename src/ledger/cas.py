from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

CHUNK_SIZE = 1024 * 1024

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK_SIZE)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

@dataclass(frozen=True)
class CasPaths:
    root: Path  # repo root
    objects_dir: Path  # root / "ledger" / "objects"

    @staticmethod
    def from_repo_root(repo_root: Path) -> "CasPaths":
        return CasPaths(
            root=repo_root,
            objects_dir=repo_root / "ledger" / "objects",
        )

    def object_path(self, digest: str) -> Path:
        # Spread by prefix to avoid huge dirs.
        prefix = digest[:2]
        return self.objects_dir / prefix / digest

def store_blob(src: Path, cas: CasPaths, digest: str) -> Path:
    dst = cas.object_path(digest)
    dst.parent.mkdir(parents=True, exist_ok=True)

    if dst.exists():
        return dst

    # Copy bytes verbatim; determinism = byte identity.
    # Use replace-atomic temp -> rename to avoid partial writes.
    tmp = dst.with_suffix(".tmp")
    tmp.write_bytes(src.read_bytes())
    tmp.replace(dst)
    return dst
