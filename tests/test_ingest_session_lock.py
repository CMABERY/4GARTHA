from __future__ import annotations

import multiprocessing as mp
import tempfile
from pathlib import Path

from ledger.locks import ingest_session_lock, ingest_session_lock_path


def _init_repo(root: Path) -> None:
    (root / "ledger").mkdir(parents=True, exist_ok=True)


def _holder(repo: str, ready, ctrl) -> None:
    repo_root = Path(repo)
    with ingest_session_lock(repo_root):
        ready.send("LOCKED")
        msg = ctrl.recv()
        assert msg == "RELEASE"


def _waiter(repo: str, out) -> None:
    repo_root = Path(repo)
    with ingest_session_lock(repo_root):
        out.send("ACQUIRED")


def test_ingest_session_lock_blocks_other_processes() -> None:
    ctx = mp.get_context("spawn")
    with tempfile.TemporaryDirectory() as td:
        repo_root = Path(td)
        _init_repo(repo_root)

        lp = ingest_session_lock_path(repo_root)
        assert lp.parts[-3:] == ("ledger", ".locks", "ingest.lock")

        ready_parent, ready_child = ctx.Pipe()
        ctrl_parent, ctrl_child = ctx.Pipe()
        out_parent, out_child = ctx.Pipe()

        p1 = ctx.Process(target=_holder, args=(str(repo_root), ready_child, ctrl_child))
        p1.start()
        assert ready_parent.recv() == "LOCKED"

        p2 = ctx.Process(target=_waiter, args=(str(repo_root), out_child))
        p2.start()

        # While p1 holds the lock, p2 must not acquire.
        assert out_parent.poll(0.25) is False

        # Release and ensure p2 acquires.
        ctrl_parent.send("RELEASE")
        assert out_parent.poll(2.0) is True
        assert out_parent.recv() == "ACQUIRED"

        p2.join(timeout=5)
        p1.join(timeout=5)
        assert p1.exitcode == 0
        assert p2.exitcode == 0

