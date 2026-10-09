"""Finding 13: the default `pytest` invocation (as run in CI) must collect
every test module in the repository, including root-level ones."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ledger_testutil import PYTHON, REPO


def _tracked_test_files() -> set:
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("needs a git checkout to enumerate test files")
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True
    ).stdout
    names = (os.fsdecode(p) for p in out.split(b"\0") if p)
    files = {n for n in names if Path(n).name.startswith("test_") and n.endswith(".py")}
    files.add("tests/test_collection.py")  # this guard, even before it is committed
    return files


def test_default_collection_includes_every_test_module() -> None:
    expected = _tracked_test_files()
    proc = subprocess.run(
        [PYTHON, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=REPO, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    collected = {line.split("::", 1)[0] for line in proc.stdout.splitlines() if "::" in line}
    assert "test_memory_system.py" in collected
    assert expected <= collected, f"not collected by default: {sorted(expected - collected)}"
