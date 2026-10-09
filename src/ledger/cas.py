from __future__ import annotations

import hashlib
import os
import stat
import tempfile
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

class CasIntegrityError(ValueError):
    """An existing CAS entry is not a regular file holding the bytes its digest names."""


def verify_existing_object(cas: CasPaths, digest: str) -> bool:
    """Check whatever is already stored at ``digest``'s CAS path.

    Returns False if nothing is there, True if a regular file (not a symlink)
    with exactly the expected digest is there. Raises CasIntegrityError for
    anything else; the entry is left untouched, since objects are append-only
    and corruption must be repaired deliberately rather than silently replaced.
    """
    dst = cas.object_path(digest)
    try:
        st = os.lstat(dst)
    except FileNotFoundError:
        return False
    except NotADirectoryError:
        raise CasIntegrityError(f"CAS prefix directory is not a directory: {dst.parent}") from None
    if not stat.S_ISREG(st.st_mode):
        raise CasIntegrityError(f"existing CAS entry is not a regular file: {dst}")
    actual = sha256_file(dst)
    if actual != digest:
        raise CasIntegrityError(
            f"existing CAS object is corrupt: {dst}: expected sha256 {digest}, got {actual} "
            "(refusing to overwrite append-only storage)"
        )
    return True


def publish_no_clobber(tmp: Path, dst: Path) -> bool:
    """Atomically publish fully written ``tmp`` at ``dst`` without ever
    replacing an existing ``dst``. Returns True if published, False if
    ``dst`` already existed (the caller must then verify what is there).
    ``tmp`` is always removed.

    Hard link first: atomic and no-clobber, so a concurrent writer that
    creates ``dst`` at any moment is never overwritten and no partial file is
    ever visible under ``dst``. Where hard links are unavailable: on Windows,
    ``os.rename`` is likewise atomic and fails if ``dst`` exists; elsewhere,
    exclusive create plus copy (no-clobber, but not crash-atomic: a crash can
    leave a partial file, which then fails verification and is never
    silently replaced).
    """
    try:
        try:
            os.link(tmp, dst)
            return True
        except FileExistsError:
            return False
        except OSError:
            pass  # no hard links on this filesystem
        if os.name == "nt":
            try:
                os.rename(tmp, dst)
                return True
            except FileExistsError:
                return False
        data = tmp.read_bytes()
        try:
            with dst.open("xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            return True
        except FileExistsError:
            return False
    finally:
        tmp.unlink(missing_ok=True)


def store_blob(src: Path, cas: CasPaths, digest: str) -> Path:
    dst = cas.object_path(digest)
    dst.parent.mkdir(parents=True, exist_ok=True)

    # Deduplicate only against a verified object; never trust mere existence.
    if verify_existing_object(cas, digest):
        return dst

    # Copy bytes verbatim; determinism = byte identity. Hash the exact bytes
    # being stored so a source that changed after it was hashed cannot land in
    # the CAS under the wrong address.
    data = src.read_bytes()
    actual = sha256_bytes(data)
    if actual != digest:
        raise ValueError(f"refusing to store {src}: expected sha256 {digest}, got {actual}")

    # Unique temp file in the destination directory, fully written and synced,
    # then published without clobbering: another writer may have created the
    # object since the check above (e.g. with --no-session-lock or a writer
    # that does not take the lock).
    fd, tmp_name = tempfile.mkstemp(prefix=f".{digest}.", suffix=".tmp", dir=dst.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if not publish_no_clobber(tmp, dst):
        # Lost the race: reuse the existing entry only if it is intact.
        if not verify_existing_object(cas, digest):
            raise CasIntegrityError(f"CAS entry vanished during publication: {dst}")
    return dst
