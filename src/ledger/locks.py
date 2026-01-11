from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def _truthy(v: str) -> bool:
    s = v.strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _falsey(v: str) -> bool:
    s = v.strip().lower()
    return s in ("0", "false", "no", "n", "off")


def ingest_session_lock_path(repo_root: Path) -> Path:
    """
    Repo-wide ingest-session lock path.

    Stored under ledger/ so the lock is per-repo/worktree (not per cwd).
    Recommended to ignore in git: ledger/.locks/
    """
    return Path(repo_root) / "ledger" / ".locks" / "ingest.lock"@contextmanager
def file_lock(lock_path: Path) -> Iterator[None]:
    """
    Cross-process exclusive advisory lock.

    POSIX: fcntl.flock
    Windows: msvcrt.locking (1-byte range lock)

    Lock lifetime is tied to the open FD; crashes release locks.
    """
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    f = lock_path.open("a+b")
    try:
        # Ensure at least 1 byte exists for Windows range locks.
        try:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                f.write(b"\0")
                f.flush()
        except Exception:
            pass

        if os.name == "posix":
            import fcntl  # type: ignore

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
        else:
            import msvcrt  # type: ignore

            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
    finally:
        try:
            f.close()
        except Exception:
            pass


@contextmanager
def ingest_session_lock(repo_root: Path) -> Iterator[None]:
    """Convenience wrapper for the repo-wide ingest-session lock."""
    with file_lock(ingest_session_lock_path(repo_root)):
        yield


def ingest_session_lock_enabled(*, cli_no_session_lock: bool = False) -> bool:
    """
    Maximal safety default: ON.

    Controls:
      - CLI: --no-session-lock disables
      - Env: LEDGER_INGEST_SESSION_LOCK overrides (true/false)

    Unknown env values => default ON.
    """
    if cli_no_session_lock:
        return False

    v = os.environ.get("LEDGER_INGEST_SESSION_LOCK")
    if v is None:
        return True

    if _truthy(v):
        return True
    if _falsey(v):
        return False

    return True

