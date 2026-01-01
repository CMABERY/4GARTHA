"""P3 — File reference helpers.

Sprint-1 intentionally does not define a full content-addressed storage system.
These helpers exist to make fixture generation and verification deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .ids import sha256_prefixed


@dataclass(frozen=True)
class FileRef:
    """A minimal, self-contained file reference.

    This is *not* the ledger's CAS pathing. It is only a canonical tuple
    used by the Sprint-1 verifier.
    """

    path: str
    raw_sha256: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_ref(path: Path) -> FileRef:
    p = Path(path)
    raw = sha256_file(p)
    return FileRef(path=p.as_posix(), raw_sha256=f"sha256:{raw}")


def file_digest_prefixed(path: Path) -> str:
    return sha256_prefixed(Path(path).read_bytes())
