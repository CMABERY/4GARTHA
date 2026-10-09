"""ci/verify_record_ids.sh: the independent (jq + sha256sum) record-ID check
reproduces the committed fixtures and fails closed on every tampering it is
meant to catch. It serializes each fixture's record object itself, so a
wrong expected canonical form is caught even when the expected IDs were
computed consistently from that wrong form."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ledger_testutil import REPO

SCRIPT = REPO / "ci" / "verify_record_ids.sh"
VECTORS = REPO / "conformance" / "record-v1-vectors.json"
TAG = b"4gartha.record/1\x00"

pytestmark = pytest.mark.skipif(
    any(shutil.which(t) is None for t in ("bash", "jq", "sha256sum", "cmp", "od")),
    reason="needs bash, jq and coreutils",
)


def _run(vectors: Path, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), str(vectors)], capture_output=True, text=True,
                          timeout=120, env=env)


def _write(tmp_path: Path, doc: dict) -> Path:
    p = tmp_path / "vectors.json"
    p.write_text(json.dumps(doc, ensure_ascii=True, indent=2), encoding="utf-8")
    return p


def _doc() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_committed_fixtures_reproduce(tmp_path: Path) -> None:
    proc = _run(VECTORS)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert sum(1 for line in proc.stdout.splitlines() if line.startswith("ok   ")) == 4
    for name in ("admission-ascii", "admission-non-ascii", "derivation-with-environment",
                 "derivation-duplicate-inputs-no-environment"):
        assert f"ok   {name}  record_id=" in proc.stdout
    assert "4/4 fixtures reproduced" in proc.stdout


def test_wrong_canonical_form_with_consistent_ids_is_caught(tmp_path: Path) -> None:
    # The crucial case: the expected canonical bytes are wrong (whitespace),
    # and the expected IDs were computed from those wrong bytes. Hashing the
    # prewritten canonical_utf8 would pass; independent serialization fails.
    doc = _doc()
    fx = doc["record_ids"][0]
    wrong = json.dumps(fx["record"], sort_keys=True, ensure_ascii=False)  # ", " and ": "
    assert wrong != fx["canonical_utf8"]
    fx["canonical_utf8"] = wrong
    fx["record_id"] = hashlib.sha256(TAG + wrong.encode()).hexdigest()
    fx["plain_sha256_of_canonical"] = hashlib.sha256(wrong.encode()).hexdigest()
    proc = _run(_write(tmp_path, doc))
    assert proc.returncode != 0
    assert "FAIL admission-ascii  serialization=MISMATCH record_id=MISMATCH" in proc.stdout


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda d: d["record_ids"][1].update(record_id="0" * 64), "FAIL admission-non-ascii  serialization=ok record_id=MISMATCH"),
        (lambda d: d["record_ids"][2].update(plain_sha256_of_canonical="0" * 64), "plain_sha256=MISMATCH"),
        (lambda d: d["record_ids"][0]["record"]["basis"].update(statement="edited"), "FAIL admission-ascii  serialization=MISMATCH"),
        (lambda d: d["record_ids"][3].update(canonical_utf8=d["record_ids"][3]["canonical_utf8"] + "\n"), "serialization=MISMATCH"),
    ],
    ids=["record-id", "plain-sha256", "record-object", "canonical-trailing-newline"],
)
def test_any_mismatch_fails(tmp_path: Path, mutate, message: str) -> None:
    doc = _doc()
    mutate(doc)
    proc = _run(_write(tmp_path, doc))
    assert proc.returncode != 0
    assert message in proc.stdout, proc.stdout
    assert "did not reproduce" in proc.stderr


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda d: d["record_ids"].pop(), "expected 4 record-ID fixtures, found 3"),
        (lambda d: d["record_ids"].append(copy.deepcopy(d["record_ids"][0])), "expected 4 record-ID fixtures, found 5"),
        (lambda d: d["record_ids"].__setitem__(3, copy.deepcopy(d["record_ids"][0])),
         "fixture 'admission-ascii' appears 2 time(s)"),
        (lambda d: d["record_ids"][1].update(name="renamed"), "fixture 'admission-non-ascii' appears 0 time(s)"),
        (lambda d: d["record_ids"][2].pop("plain_sha256_of_canonical"), "missing field 'plain_sha256_of_canonical'"),
        (lambda d: d["record_ids"][2].update(record=None), "missing field 'record'"),
        (lambda d: d.update(domain_tag_hex=d["domain_tag_hex"][:-2] + "01"), "domain tag mismatch"),
        (lambda d: d.pop("record_ids"), "no record_ids array"),
    ],
    ids=["fixture-removed", "fixture-added", "fixture-duplicated", "fixture-renamed", "field-missing",
         "record-null", "domain-tag", "section-missing"],
)
def test_fixture_set_and_shape_fail_closed(tmp_path: Path, mutate, message: str) -> None:
    doc = _doc()
    mutate(doc)
    proc = _run(_write(tmp_path, doc))
    assert proc.returncode != 0
    assert message in proc.stderr, proc.stdout + proc.stderr


def test_missing_vectors_file_fails(tmp_path: Path) -> None:
    proc = _run(tmp_path / "absent.json")
    assert proc.returncode != 0 and "vectors file not found" in proc.stderr


def test_missing_tool_fails_closed(tmp_path: Path) -> None:
    # A PATH holding every tool the script uses except jq.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("bash", "sha256sum", "cmp", "od", "mktemp", "rm", "cat", "cut", "seq", "tr", "head", "dirname"):
        found = shutil.which(tool)
        if found:
            os.symlink(found, bindir / tool)
    env = {"PATH": str(bindir), "HOME": str(tmp_path)}
    proc = subprocess.run([str(bindir / "bash"), str(SCRIPT), str(VECTORS)], capture_output=True,
                          text=True, timeout=60, env=env)
    assert proc.returncode != 0
    assert "required tool not found: jq" in proc.stderr


# --- review finding 3: success only after every fixture was compared --------

_EXTERNAL_TOOLS = ("jq", "sha256sum", "cmp", "od", "mktemp", "cat", "cut", "tr", "head", "dirname", "rm")


def _path_without(tmp_path: Path, missing: str, fakes: dict | None = None) -> dict:
    bindir = tmp_path / f"bin-without-{missing}"
    bindir.mkdir()
    for tool in ("bash", "seq", *_EXTERNAL_TOOLS):
        found = shutil.which(tool)
        if tool != missing and found:
            os.symlink(found, bindir / tool)
    for name, body in (fakes or {}).items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    return {"PATH": str(bindir), "HOME": str(tmp_path)}


def _run_with(env: dict) -> subprocess.CompletedProcess:
    bash = shutil.which("bash")
    return subprocess.run([bash, str(SCRIPT), str(VECTORS)], capture_output=True, text=True, timeout=60, env=env)


def _compared(stdout: str) -> int:
    return sum(1 for line in stdout.splitlines() if line.startswith(("ok   ", "FAIL ")))


def test_failing_seq_cannot_skip_the_comparisons(tmp_path: Path) -> None:
    # Review reproduction: `for i in $(seq ...)` with a failing seq ran zero
    # iterations under set -e and still printed success.
    env = _path_without(tmp_path, "seq", fakes={"seq": "#!/bin/sh\nexit 127\n"})
    proc = _run_with(env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _compared(proc.stdout) == 4
    assert "4/4 fixtures reproduced" in proc.stdout


@pytest.mark.parametrize("missing", _EXTERNAL_TOOLS + ("seq",))
def test_no_missing_tool_yields_success_without_four_comparisons(tmp_path: Path, missing: str) -> None:
    proc = _run_with(_path_without(tmp_path, missing))
    if missing in _EXTERNAL_TOOLS:
        assert proc.returncode != 0, f"succeeded without {missing}"
        assert f"required tool not found: {missing}" in proc.stderr
    else:  # not used by the script: must still compare everything
        assert proc.returncode == 0 and _compared(proc.stdout) == 4


def test_script_never_loops_over_a_command_substitution() -> None:
    import re

    text = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"^\s*for\s+\w+\s+in\s+[^;]*\$\(", text, re.M), "use an arithmetic for-loop"
    assert '[ "$checked" -eq "${#EXPECTED_FIXTURES[@]}" ]' in text  # success requires every comparison
