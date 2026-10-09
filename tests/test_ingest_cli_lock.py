"""Finding 1: `ledger ingest` must run its whole transaction under the
repo-wide session lock (tested through the CLI, not just the lock helper)."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from ledger.cas import CasPaths, sha256_bytes, sha256_file
from ledger.locks import ingest_session_lock
from ledger.manifest import node_manifest_path
from ledger.verify import verify_reachable

from ledger_testutil import PYTHON, REPO, admit, cli_env, init_repo, run_cli


def _start_ingest(root: Path, *args: str, env=None) -> subprocess.Popen:
    return subprocess.Popen(
        [PYTHON, "-m", "ledger.cli", "ingest", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env if env is not None else cli_env(),
    )


def test_cli_ingest_blocks_while_session_lock_is_held(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "control").write_bytes(b"control")
    (root / "input").write_bytes(b"lock-test")
    expected = sha256_bytes(b"lock-test")

    proc = None
    with ingest_session_lock(root):
        # Positive control: same command shape, lock disabled. Its runtime
        # calibrates how long an unblocked ingest takes on this machine.
        t0 = time.monotonic()
        control = run_cli(root, "ingest", "--no-session-lock", "control")
        control_elapsed = time.monotonic() - t0
        assert control.returncode == 0, control.stderr
        window = max(1.0, 3 * control_elapsed)

        try:
            proc = _start_ingest(root, "input")
            time.sleep(window)
            assert proc.poll() is None, "ingest finished while another session held the lock"
            assert not node_manifest_path(root, expected).exists()
            assert not CasPaths.from_repo_root(root).object_path(expected).exists()
        except BaseException:
            if proc is not None:
                proc.kill()
                proc.communicate()
            raise

    out, err = proc.communicate(timeout=60)
    assert proc.returncode == 0, err
    assert out.strip() == expected
    assert verify_reachable(root, expected).ok


@pytest.mark.parametrize("value", ["0", "false", "off"])
def test_env_var_can_disable_session_lock(tmp_path: Path, value: str) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"env-disabled")
    with ingest_session_lock(root):
        proc = run_cli(root, "ingest", "input", env=cli_env({"LEDGER_INGEST_SESSION_LOCK": value}), timeout=30)
    assert proc.returncode == 0, proc.stderr


def test_concurrent_cli_ingests_all_succeed_and_verify(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    tf = root / "concat.py"
    tf.write_bytes((REPO / "transforms" / "concat_parents.py").read_bytes())
    parent = admit(root, b"base")
    inputs = []
    for i in range(6):
        p = root / f"in{i}"
        p.write_bytes(b"base" + str(i).encode())
        inputs.append(p)

    procs = [
        _start_ingest(
            root, p.name, "--parent", parent, "--transform-file", str(tf),
            "--params-json", '{"suffix": "%d"}' % i, "--runner", PYTHON,
        )
        for i, p in enumerate(inputs)
    ]
    results = [pr.communicate(timeout=60) for pr in procs]
    for pr, (_, err) in zip(procs, results):
        assert pr.returncode == 0, err

    ids = [out.strip() for out, _ in results]
    assert ids == [sha256_file(p) for p in inputs]
    for nid in ids:
        assert verify_reachable(root, nid, replay=True).ok
    leftovers = [p for p in (root / "ledger" / "objects").rglob("*") if p.name.endswith(".tmp")]
    assert leftovers == []


def test_ingest_rejects_self_parent_without_writing(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"self")
    self_id = sha256_bytes(b"self")

    proc = run_cli(root, "ingest", "input", "--parent", self_id)
    assert proc.returncode != 0
    assert "own parent" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert not node_manifest_path(root, self_id).exists()
    assert not CasPaths.from_repo_root(root).object_path(self_id).exists()


@pytest.mark.parametrize(
    "args",
    [["--parent", "ABC"], ["--env-digest", "nope"], ["--params-json", "[1]"], ["--params-json", "{bad"]],
)
def test_ingest_rejects_invalid_input_without_writing(tmp_path: Path, args) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"data")

    proc = run_cli(root, "ingest", "input", *args)
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert list((root / "ledger" / "objects").iterdir()) == []
    assert list((root / "ledger" / "nodes").iterdir()) == []


def test_reingest_fails_cleanly(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"data")
    assert run_cli(root, "ingest", "input").returncode == 0
    again = run_cli(root, "ingest", "input")
    assert again.returncode != 0
    assert "already exists" in again.stderr
    assert "Traceback" not in again.stderr
