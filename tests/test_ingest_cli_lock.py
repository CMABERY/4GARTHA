"""Finding 1: `ledger admit` / `ledger derive` run their whole transaction
under the repo-wide session lock (tested through the CLI, not just the lock
helper). Also: input validation happens before anything is written."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from ledger import records
from ledger.assurance import PROFILES, evaluate
from ledger.cas import CasPaths, sha256_bytes
from ledger.locks import ingest_session_lock

from ledger_testutil import PYTHON, admit, check, cli_env, concat_transform, init_repo, run_cli


def _start(root: Path, *args: str, env=None) -> subprocess.Popen:
    return subprocess.Popen(
        [PYTHON, "-m", "ledger.cli", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env if env is not None else cli_env(),
    )


def _empty(root: Path) -> bool:
    return (list((root / "ledger" / "objects").iterdir()) == []
            and list((root / "ledger" / "records").iterdir()) == [])


def test_cli_admit_blocks_while_session_lock_is_held(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "control").write_bytes(b"control")
    (root / "input").write_bytes(b"lock-test")
    expected = records.record_id(records.admission(sha256_bytes(b"lock-test"), "s"))

    proc = None
    with ingest_session_lock(root):
        # Positive control: same command shape, lock disabled. Its runtime
        # calibrates how long an unblocked admit takes on this machine.
        t0 = time.monotonic()
        control = run_cli(root, "admit", "--no-session-lock", "control", "--statement", "s")
        window = max(1.0, 3 * (time.monotonic() - t0))
        assert control.returncode == 0, control.stderr

        try:
            proc = _start(root, "admit", "input", "--statement", "s")
            time.sleep(window)
            assert proc.poll() is None, "admit finished while another session held the lock"
            assert not records.record_path(root, expected).exists()
            assert not CasPaths.from_repo_root(root).object_path(sha256_bytes(b"lock-test")).exists()
        except BaseException:
            if proc is not None:
                proc.kill()
                proc.communicate()
            raise

    out, err = proc.communicate(timeout=60)
    assert proc.returncode == 0, err
    assert out.strip() == expected
    assert evaluate(check(root, expected), PROFILES["integrity"]).satisfied


@pytest.mark.parametrize("value", ["0", "false", "off"])
def test_env_var_can_disable_session_lock(tmp_path: Path, value: str) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"env-disabled")
    with ingest_session_lock(root):
        proc = run_cli(root, "admit", "input", "--statement", "s",
                       env=cli_env({"LEDGER_INGEST_SESSION_LOCK": value}), timeout=30)
    assert proc.returncode == 0, proc.stderr


def test_concurrent_cli_derives_all_succeed_and_replay(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    tf = root / "concat.py"
    tf.write_bytes(concat_transform())
    a = admit(root, b"base")
    outs = []
    for i in range(6):
        p = root / f"out{i}"
        p.write_bytes(b"base" + str(i).encode())
        outs.append(p)

    procs = [
        _start(root, "derive", p.name, "--input", a, "--transform-file", str(tf), "--params-json", '{"suffix": "%d"}' % i)
        for i, p in enumerate(outs)
    ]
    results = [pr.communicate(timeout=60) for pr in procs]
    for pr, (_, err) in zip(procs, results):
        assert pr.returncode == 0, err
    ids = [out.strip() for out, _ in results]
    assert len(set(ids)) == 6
    for rid in ids:
        assert evaluate(check(root, rid, replay=True), PROFILES["replay"]).satisfied
    leftovers = [p for p in (root / "ledger").rglob("*") if p.name.endswith(".tmp")]
    assert leftovers == []


@pytest.mark.parametrize(
    "args",
    [
        ["--input", "ABC"],
        ["--input", "7" * 64],                 # well-formed but no such record
        ["--params-json", "[1]"],
        ["--params-json", "{bad"],
        ["--params-json", '{"a": 1.5}'],       # floats have no canonical form
        ["--params-json", '{"a": 1, "a": 2}'], # duplicate keys
        ["--runtime", "sh -c id"],
        [],                                     # no --input at all
    ],
    ids=["bad-id", "missing-record", "params-list", "params-bad-json", "float", "dup-key", "argv-runtime", "no-input"],
)
def test_derive_rejects_invalid_input_without_writing(tmp_path: Path, args) -> None:
    root = init_repo(tmp_path)
    (root / "out").write_bytes(b"data")
    (root / "t.py").write_bytes(b"pass\n")
    proc = run_cli(root, "derive", "out", "--transform-file", "t.py", *args)
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert _empty(root)


@pytest.mark.parametrize("statement", ["", "é"], ids=["empty", "non-nfc"])
def test_admit_rejects_invalid_statement_without_writing(tmp_path: Path, statement: str) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"data")
    proc = run_cli(root, "admit", "input", "--statement", statement)
    assert proc.returncode != 0 and "Traceback" not in proc.stderr
    assert _empty(root)


def test_readmitting_the_same_claim_is_idempotent(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "input").write_bytes(b"data")
    first = run_cli(root, "admit", "input", "--statement", "s")
    again = run_cli(root, "admit", "input", "--statement", "s")
    other = run_cli(root, "admit", "input", "--statement", "a different claim")
    assert first.returncode == again.returncode == other.returncode == 0
    assert first.stdout == again.stdout != other.stdout
    assert "already present" in again.stderr
    assert len(list((root / "ledger" / "records").iterdir())) == 2
