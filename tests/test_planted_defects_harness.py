"""The planted-defect harness (tools/planted_defects.py) fails closed.

These run the harness on a tiny synthetic repository, not the real
catalogue: they check the harness's own guarantees (isolation, determinism,
strict attribution, fail-closed outcomes, cleanup) in seconds. The full
catalogue is a manual maintenance command (ASSURANCE.md section 8).
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from ledger_testutil import REPO, commit_all, git

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")

_spec = importlib.util.spec_from_file_location("planted_defects", REPO / "tools" / "planted_defects.py")
pd = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pd  # dataclasses resolve annotations via sys.modules
_spec.loader.exec_module(pd)  # type: ignore[union-attr]

T = "tests/test_m.py"


def _repo(root: Path, with_package: bool = True) -> Path:
    if with_package:
        (root / "src" / "ledger").mkdir(parents=True)
        (root / "src" / "ledger" / "__init__.py").write_text("")
        (root / "src" / "ledger" / "m.py").write_text("def f():\n    return 1\n\n\ndef g():\n    return 2\n")
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / T).write_text(
        "from ledger.m import f, g\n\n\n"
        "def test_f():\n    assert f() == 1, 'f must return 1'\n\n\n"
        "def test_g():\n    assert g() == 2, 'g must return 2'\n"
    )
    (root / "pyproject.toml").write_text('[tool.pytest.ini_options]\ntestpaths = ["tests"]\n')
    git(root, "init", "-q")
    commit_all(root, "synthetic")
    return root


def _d(id_: str, old: str, new: str, node: str, reason: str) -> "pd.Defect":
    return pd.Defect(id_, id_, "src/ledger/m.py", old, new, ((f"{T}::{node}", reason),), targets=(T,))


DETECTED = _d("ok", "return 1", "return 0", "test_f", r"f must return 1")
UNDETECTED = _d("undetected", "    return 2\n", "    return 2  # harmless\n", "test_g", r"g must return 2")
MISSING = _d("missing", "no such text", "x", "test_f", r".")
WRONG = _d("wrong", "return 2", "return 3", "test_g", r"some other reason")
BROKEN = _d("broken", "def f():", "def f(:", "test_f", r".")


def _run(repo: Path, tmp_path: Path, catalogue, *extra: str):
    out = tmp_path / "result.json"
    before = sorted(p.name for p in Path(tempfile.gettempdir()).glob(pd.WORK_PREFIX + "*"))
    status = git(repo, "status", "--porcelain")
    code = pd.main(["--repo", str(repo), "--json", str(out), *extra], catalogue=catalogue)
    after = sorted(p.name for p in Path(tempfile.gettempdir()).glob(pd.WORK_PREFIX + "*"))
    assert git(repo, "status", "--porcelain") == status, "invoking tree changed"
    return code, json.loads(out.read_text()), set(after) - set(before)


def test_detected_defects_pass_and_leave_nothing_behind(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    code, doc, leftovers = _run(repo, tmp_path, [DETECTED])
    assert code == 0 and doc["summary"]["result"] == "PASS"
    assert doc["results"][0]["status"] == "detected"
    assert doc["revision"] == git(repo, "rev-parse", "HEAD")
    assert leftovers == set()


def test_every_failure_mode_fails_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    code, doc, leftovers = _run(repo, tmp_path, [DETECTED, UNDETECTED, MISSING, WRONG, BROKEN])
    assert code == 1 and doc["summary"]["result"] == "FAIL"
    got = {r["id"]: r["status"] for r in doc["results"]}
    assert got == {"ok": "detected", "undetected": "undetected", "missing": "infrastructure_error",
                   "wrong": "wrong_reason", "broken": "infrastructure_error"}
    assert "occurs 0 times" in next(r for r in doc["results"] if r["id"] == "missing")["detail"]
    assert doc["summary"] == {"planted": 5, "detected": 1, "undetected": 1, "unexpected_failures": 1,
                              "infrastructure_errors": 2, "not_run": 0, "result": "FAIL"}
    assert leftovers == set()


def test_only_committed_bytes_are_tested(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    # An uncommitted edit that would break the baseline must not be seen.
    (repo / "src" / "ledger" / "m.py").write_text("def f():\n    return 99\n\n\ndef g():\n    return 2\n")
    code, doc, _ = _run(repo, tmp_path, [DETECTED])
    assert code == 0 and doc["results"][0]["status"] == "detected"
    assert "return 99" in (repo / "src" / "ledger" / "m.py").read_text()


def test_expected_test_missing_from_baseline_is_fatal(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    ghost = _d("ghost", "return 1", "return 0", "test_renamed_away", r".")
    code, doc, _ = _run(repo, tmp_path, [ghost])
    assert code == 1 and "absent from the baseline" in doc["fatal"]
    assert doc["results"][0]["status"] == "not_run"


def test_import_resolving_outside_the_copy_is_fatal(tmp_path: Path) -> None:
    # No src/ledger in the copy, so `import ledger` finds the installed
    # package: the harness must refuse rather than test the wrong code.
    repo = _repo(tmp_path / "repo", with_package=False)
    code, doc, _ = _run(repo, tmp_path, [DETECTED])
    assert code == 1 and "outside the disposable copy" in doc["fatal"]


def test_interrupted_run_is_incomplete_and_cleaned_up(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path / "repo")
    real_apply = pd._apply
    calls = []

    def apply_then_interrupt(checkout, d):
        calls.append(d.id)
        if len(calls) == 2:
            raise KeyboardInterrupt
        real_apply(checkout, d)

    monkeypatch.setattr(pd, "_apply", apply_then_interrupt)
    second = _d("ok2", "return 1", "return 0", "test_f", r"f must return 1")
    code, doc, leftovers = _run(repo, tmp_path, [DETECTED, second, WRONG])
    assert code == 1 and doc["fatal"] == "interrupted"
    assert [r["status"] for r in doc["results"]] == ["detected", "not_run", "not_run"]
    assert leftovers == set()


def test_keep_retains_only_its_own_directory(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    code, _, leftovers = _run(repo, tmp_path, [DETECTED], "--keep")
    try:
        assert code == 0 and len(leftovers) == 1
        kept = Path(tempfile.gettempdir()) / leftovers.pop()
        assert (kept / "baseline" / T).is_file()
    finally:
        for name in leftovers:
            shutil.rmtree(Path(tempfile.gettempdir()) / name, ignore_errors=True)
        if "kept" in locals():
            shutil.rmtree(kept, ignore_errors=True)


def test_real_catalogue_is_well_formed() -> None:
    ids = [d.id for d in pd.CATALOGUE]
    assert len(ids) == len(set(ids))
    for d in pd.CATALOGUE:
        assert d.expect and d.old != d.new, d.id
        for node, reason in d.expect:
            assert node.split("::")[0] in d.targets, (d.id, node)
            re.compile(reason)
