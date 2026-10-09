"""Conformance tests for ASSURANCE.md (assurance contract 4gartha.assurance/1).

Each test is tagged with the conformance ID it establishes (C1..C8). Per
LAW-0001 these tests, not the prose, are normative: a claim in ASSURANCE.md
without a passing test here is not a claim the implementation makes.

What tests cannot establish (stated in ASSURANCE.md): that a sandbox exists or
that repository-level controls (branch protection, rulesets, token defaults)
are configured. C2/C7 pin the verifier's and the workflow's own behaviour; the
corresponding assurances remain NOT_CHECKED or FAIL until those controls exist.
"""
from __future__ import annotations

import copy
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterator, List, Tuple

import pytest

from ledger import canonical, records
from ledger.assurance import PROFILES, Dimension, Report, Status, evaluate
from ledger.execution import RESTRICTED, restricted_policy

from ledger_testutil import (
    PYTHON,
    REPO,
    admit,
    check,
    commit_all,
    concat_transform,
    derive,
    git,
    init_repo,
    marker_transform,
    put_blob,
    record_of,
    run_cli,
    status,
    write_record_raw,
)

D = Dimension
S = Status
NEVER_PASS_IN_V1 = (D.EXECUTION_SAFETY, D.REPRODUCIBILITY, D.AUTHENTICITY, D.GOVERNANCE)


def _cli_status(stdout: str, dim: Dimension) -> str:
    for line in stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == dim.value:
            return parts[1]
    raise AssertionError(f"{dim.value} missing from CLI output:\n{stdout}")


# --- C1: an unperformed derivation is never reported as succeeded -----------


def test_C1_root_replay_is_not_applicable_not_success(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    rid = admit(root, b"root evidence")

    report = check(root, rid, replay=True)
    assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_APPLICABLE
    assert report.transforms_executed == 0
    assert status(report, D.EXECUTION_SAFETY) is S.NOT_APPLICABLE
    # Acceptability is profile-dependent, never implied by the status itself.
    assert not evaluate(report, PROFILES["replay"]).satisfied
    assert evaluate(report, PROFILES["replay-if-derived"]).satisfied


def test_C1_cli_replay_of_root_names_the_status_and_fails_the_profile(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    rid = admit(root, b"root evidence")

    proc = run_cli(root, "replay", rid)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert _cli_status(proc.stdout, D.DERIVATION_VERIFICATION) == "NOT_APPLICABLE"
    assert "profile replay: NOT SATISFIED" in proc.stdout
    assert "OK" not in proc.stdout.split()

    as_json = run_cli(root, "replay", rid, "--json")
    doc = json.loads(as_json.stdout)
    assert doc["report"]["outcomes"]["derivation_verification"]["status"] == "NOT_APPLICABLE"
    assert doc["profile"]["satisfied"] is False

    lenient = run_cli(root, "verify", rid, "--replay", "--profile", "replay-if-derived")
    assert lenient.returncode == 0, lenient.stdout
    assert _cli_status(lenient.stdout, D.DERIVATION_VERIFICATION) == "NOT_APPLICABLE"


def test_C1_unrequested_replay_is_not_checked(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    a = admit(root, b"in")
    d = derive(root, b"out", [a], marker_transform(marker, b"out"))

    report = check(root, d)  # replay not requested
    assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_CHECKED
    assert not marker.exists()
    proc = run_cli(root, "verify", d, "--profile", "replay")
    assert proc.returncode == 2
    assert _cli_status(proc.stdout, D.DERIVATION_VERIFICATION) == "NOT_CHECKED"


# --- C2: a record cannot choose what runs the verifier's code --------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.update(runner=["sh", "-c", "id"]),          # v0-style argv field
        lambda t: t.update(runtime="sh -c id"),                 # argv smuggled in the name
        lambda t: t.update(runtime=["python3", "-c", "1"]),     # list instead of a name
        lambda t: t.update(runtime="python3\n"),                # trailing newline
        lambda t: t.update(runtime="/bin/sh"),                  # path
    ],
    ids=["runner-argv", "runtime-with-spaces", "runtime-list", "runtime-newline", "runtime-path"],
)
def test_C2_records_cannot_carry_argv(mutate) -> None:
    rec = records.derivation("a" * 64, ["b" * 64], "c" * 64, "python3", {})
    mutate(rec["transform"])
    assert records.validate(rec), "record selecting argv must be invalid"
    with pytest.raises(ValueError):
        records.record_id(rec)


def test_C2_unlisted_runtime_is_refused_before_execution(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    a = admit(root, b"in")
    d = derive(root, b"out", [a], marker_transform(marker, b"out"), runtime="sh")

    report = check(root, d, replay=True)
    assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_CHECKED
    assert "not permitted by replay policy 'restricted'" in report.outcomes[D.DERIVATION_VERIFICATION].detail
    assert report.transforms_executed == 0 and not marker.exists()
    assert status(report, D.EXECUTION_SAFETY) is S.NOT_APPLICABLE


def test_C2_restricted_policy_pins_the_interpreter() -> None:
    assert dict(RESTRICTED.runtimes) == {"python3": (sys.executable, "-I")}
    with pytest.raises(TypeError):
        RESTRICTED.runtimes["sh"] = ("/bin/sh",)  # type: ignore[index]


def test_C2_transform_does_not_inherit_verifier_environment(tmp_path: Path, monkeypatch) -> None:
    root = init_repo(tmp_path)
    leak = tmp_path / "env.json"
    code = (
        "import json, os, sys\n"
        "from pathlib import Path\n"
        f"Path({str(leak)!r}).write_text(json.dumps(dict(os.environ)))\n"
        "Path(sys.argv[sys.argv.index('--out') + 1]).write_bytes(b'out')\n"
    ).encode()
    a = admit(root, b"in")
    d = derive(root, b"out", [a], code)
    monkeypatch.setenv("VERIFIER_SECRET", "must-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")

    report = check(root, d, replay=True)
    assert status(report, D.DERIVATION_VERIFICATION) is S.PASS
    seen = json.loads(leak.read_text())
    assert "must-not-leak" not in seen.values()
    assert set(seen) <= {"PATH", "LC_ALL", "HOME", "TMPDIR", "SYSTEMROOT", "TEMP", "TMP", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}


def test_C2_timeout_is_inconclusive_not_failed(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"in")
    d = derive(root, b"out", [a], b"import time\ntime.sleep(30)\n")
    report = check(root, d, replay=True, policy=restricted_policy(timeout_s=1.0))
    assert status(report, D.DERIVATION_VERIFICATION) is S.ERROR
    result = evaluate(report, PROFILES["replay"])
    assert not result.satisfied and result.error


def test_C2_execution_is_never_reported_as_safe(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    report = check(root, d, replay=True)
    assert status(report, D.DERIVATION_VERIFICATION) is S.PASS
    assert report.transforms_executed == 1
    assert status(report, D.EXECUTION_SAFETY) is S.FAIL
    assert "no enforced isolation boundary" in report.outcomes[D.EXECUTION_SAFETY].detail
    assert not evaluate(report, PROFILES["isolated-replay"]).satisfied


# --- C3: identical bytes, distinct derivations, distinct record IDs --------


def test_C3_identical_outputs_get_distinct_record_ids(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    via_concat = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    via_constant = derive(root, b"hello!", [a], marker_transform(tmp_path / "m", b"hello!"))
    b = admit(root, b"hello", statement="the same bytes, admitted for a different reason")
    via_other_input = derive(root, b"hello!", [b], concat_transform(), params={"suffix": "!"})
    direct = admit(root, b"hello!", statement="admitted directly")

    ids = {via_concat, via_constant, via_other_input, direct}
    assert len(ids) == 4
    outputs = {record_of(root, r)["output"]["artifact"] for r in ids}
    assert len(outputs) == 1  # one artifact, four claims about it
    assert len(list((root / "ledger" / "records").glob("*.json"))) == 6
    for rid in (via_concat, via_constant, via_other_input):
        report = check(root, rid, replay=True)
        assert evaluate(report, PROFILES["replay"]).satisfied, report.to_dict()


def test_C3_same_claim_is_the_same_record(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    first = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    again = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    assert first == again
    rec = record_of(root, first)
    reordered = dict(reversed(list(rec.items())))
    assert records.record_id(reordered) == first  # key order is not identity


# --- C4: every identity-bearing field is committed by the record ID --------


def _schema_leaf_paths(schema: dict, node: dict, prefix: Tuple[str, ...]) -> Iterator[Tuple[str, ...]]:
    if "$ref" in node:
        node = schema["$defs"][node["$ref"].split("/")[-1]]
    if "oneOf" in node:
        for alt in node["oneOf"]:
            yield from _schema_leaf_paths(schema, alt, prefix)
        return
    if node.get("type") == "array":
        yield from _schema_leaf_paths(schema, node["items"], prefix + ("[]",))
        return
    props = node.get("properties")
    if not props or node.get("type") != "object" or prefix and prefix[-1] == "params":
        yield prefix
        return
    for name, sub in props.items():
        yield from _schema_leaf_paths(schema, sub, prefix + (name,))


def _record_leaf_paths(obj: Any, prefix: Tuple[Any, ...] = ()) -> Iterator[Tuple[Any, ...]]:
    if isinstance(obj, dict) and obj and not (prefix and prefix[-1] == "params"):
        for k, v in obj.items():
            yield from _record_leaf_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _record_leaf_paths(v, prefix + (i,))
    else:
        yield prefix


def _get(obj: Any, path: Tuple[Any, ...]) -> Any:
    for p in path:
        obj = obj[p]
    return obj


def _set(obj: Any, path: Tuple[Any, ...], value: Any) -> None:
    _get(obj, path[:-1])[path[-1]] = value


def _changed(value: Any) -> Any:
    if isinstance(value, str):
        if records.is_digest(value):
            return value[:-1] + ("0" if value[-1] != "0" else "1")
        return value + "x"
    if value is None:
        return {"artifact": "e" * 64}
    if isinstance(value, dict):  # params
        return {**value, "added": 1}
    raise AssertionError(f"no mutation for {value!r}")


def _full_records() -> List[dict]:
    return [
        records.admission("a" * 64, "admitted from fixture X"),
        records.derivation("b" * 64, ["c" * 64, "d" * 64], "e" * 64, "python3", {"suffix": "!", "n": 2}, "f" * 64),
        records.derivation("b" * 64, ["c" * 64], "e" * 64, "python3", {}, None),
    ]


def _id_of(obj: dict) -> str:
    # Hash exactly what is stored, bypassing validation, so that changes to
    # constant fields (protocol, kind) are covered too.
    return records.record_id_of_bytes(canonical.encode(obj))


@pytest.mark.parametrize("base", _full_records(), ids=["admission", "derivation-env", "derivation-noenv"])
def test_C4_changing_any_field_changes_the_record_id(base: dict) -> None:
    original = _id_of(base)
    assert original == records.record_id(base)
    mutated_paths = set()
    for path in _record_leaf_paths(base):
        m = copy.deepcopy(base)
        _set(m, path, _changed(_get(base, path)))
        assert _id_of(m) != original, f"changing {path} did not change the record ID"
        mutated_paths.add(tuple("[]" if isinstance(p, int) else p for p in path))

    if base["kind"] == "derivation":
        for name, change in [
            ("reorder inputs", lambda r: r["inputs"].reverse()),
            ("add input", lambda r: r["inputs"].append({"record": "9" * 64})),
            ("drop input", lambda r: r["inputs"].pop()),
            ("params value", lambda r: r["transform"]["params"].update(suffix="?")),
        ]:
            m = copy.deepcopy(base)
            change(m)
            if m["inputs"] != base["inputs"] or m["transform"] != base["transform"]:
                assert _id_of(m) != original, name

    # Coverage guard: every field the schema allows for this kind was mutated,
    # so a field added to the schema later cannot escape this test. A null
    # environment is itself the leaf; a present one is mutated via .artifact.
    schema = json.loads((REPO / "src" / "ledger" / "record.schema.json").read_text())
    expected = set(_schema_leaf_paths(schema, schema["$defs"][base["kind"]], ()))
    if base["kind"] == "derivation":
        expected.discard(("environment",) if base["environment"] is not None else ("environment", "artifact"))
    assert expected == mutated_paths, f"schema/test field mismatch: {sorted(expected ^ mutated_paths)}"


def test_C4_record_ids_are_domain_separated() -> None:
    import hashlib

    rec = _full_records()[1]
    data = canonical.encode(rec)
    assert records.record_id(rec) != hashlib.sha256(data).hexdigest()
    assert records.record_id(rec) == hashlib.sha256(b"4gartha.record/1\x00" + data).hexdigest()
    assert records.record_id(rec) != hashlib.sha256(b"4gartha.record/2\x00" + data).hexdigest()


# --- C5: unattested admissions cannot satisfy authenticated profiles -------


def test_C5_unsigned_admission_fails_authenticated_profile(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"evidence", statement="received by email from the lab")
    d = derive(root, b"evidence!", [a], concat_transform(), params={"suffix": "!"})
    for rid in (a, d):
        report = check(root, rid)
        assert status(report, D.AUTHENTICITY) is S.NOT_CHECKED
        assert not evaluate(report, PROFILES["authenticated-admission"]).satisfied
    proc = run_cli(root, "verify", a, "--profile", "authenticated-admission")
    assert proc.returncode == 2
    assert _cli_status(proc.stdout, D.AUTHENTICITY) == "NOT_CHECKED"


@pytest.mark.parametrize(
    "basis",
    [
        {"kind": "signature", "statement": "signed", "key": "ab" * 32, "sig": "00"},
        {"kind": "unattested", "statement": "x", "signature": "00" * 64},
        {"kind": "tpm-quote", "statement": "x"},
    ],
    ids=["signature-kind", "signature-field", "tpm-kind"],
)
def test_C5_unverifiable_authenticity_claims_are_rejected(tmp_path: Path, basis: dict) -> None:
    rec = records.admission("a" * 64, "x")
    rec["basis"] = basis
    assert records.validate(rec)
    root = init_repo(tmp_path)
    put_blob(root, b"evidence")
    data = canonical.encode(rec)
    rid = records.record_id_of_bytes(data)
    write_record_raw(root, rid, data)
    report = check(root, rid)
    assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
    assert status(report, D.AUTHENTICITY) is not S.PASS
    assert not evaluate(report, PROFILES["authenticated-admission"]).satisfied


# --- C6: no governance claim without external evidence ---------------------


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_C6_repository_controls_do_not_produce_governance_assurance(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "tools").mkdir()
    for name in ("verify_new_records.py", "check_append_only.py", "_gitdiff.py"):
        shutil.copyfile(REPO / "tools" / name, root / "tools" / name)
    git(root, "init", "-q")
    commit_all(root, "baseline")
    a = admit(root, b"evidence")
    commit_all(root, "admit")

    import subprocess
    for script in ("check_append_only.py", "verify_new_records.py"):
        proc = subprocess.run([PYTHON, str(root / "tools" / script), "HEAD~1"], cwd=root,
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    report = check(root, a)
    assert status(report, D.GOVERNANCE) is S.NOT_CHECKED
    assert "external anchoring" in report.outcomes[D.GOVERNANCE].detail
    assert not evaluate(report, PROFILES["governed"]).satisfied
    proc = run_cli(root, "verify", a, "--profile", "governed")
    assert proc.returncode == 2 and "profile governed: NOT SATISFIED" in proc.stdout


# --- C7: CI never executes transforms and holds a read-only token ----------


def _code_lines(path: Path) -> List[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append(line)
    return out


def _permission_entries(lines: List[str]) -> List[str]:
    """Every value under any `permissions:` key (inline or indented block)."""
    out: List[str] = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)permissions:\s*(.*)$", line)
        if not m:
            continue
        indent, inline = len(m.group(1)), m.group(2).strip()
        if inline:
            out.append(inline)
            continue
        for nxt in lines[i + 1:]:
            if len(nxt) - len(nxt.lstrip()) <= indent:
                break
            out.append(nxt.strip())
    return out


def test_C7_permission_scanner_reads_only_permission_blocks() -> None:
    lines = [
        "permissions:", "  contents: read", "jobs:", "  a:", "    permissions: write-all",
        "    steps:", "      - name: write results", "        run: echo 'status: write'",
        "  b:", "    permissions:", "      pull-requests: write", "    runs-on: x",
    ]
    assert _permission_entries(lines) == ["contents: read", "write-all", "pull-requests: write"]


def test_C7_workflows_do_not_replay_and_ci_token_is_read_only() -> None:
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    assert workflows
    for wf in workflows:
        code = "\n".join(_code_lines(wf))
        for forbidden in ("--replay", "ledger replay", "replay_new_nodes", "replay=True"):
            assert forbidden not in code, f"{wf.name} executes transforms via {forbidden!r}"

    ci = _code_lines(REPO / ".github" / "workflows" / "ci.yml")
    top = [i for i, l in enumerate(ci) if l.startswith("permissions:")]
    assert len(top) == 1, "ci.yml must declare top-level permissions"
    block = []
    for line in ci[top[0] + 1:]:
        if not line.startswith(" "):
            break
        block.append(line.strip())
    assert block == ["contents: read"], block
    granted = _permission_entries(ci)
    assert not [g for g in granted if "write" in g], f"no job may request write permissions: {granted}"
    assert any("python tools/verify_new_records.py" in l for l in ci)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_C7_ci_record_gate_executes_nothing(tmp_path: Path) -> None:
    import subprocess

    root = init_repo(tmp_path)
    (root / "tools").mkdir()
    for name in ("verify_new_records.py", "_gitdiff.py"):
        shutil.copyfile(REPO / "tools" / name, root / "tools" / name)
    git(root, "init", "-q")
    commit_all(root, "baseline")
    marker = tmp_path / "ran"
    a = admit(root, b"in")
    derive(root, b"out", [a], marker_transform(marker, b"out"))
    commit_all(root, "records")

    proc = subprocess.run([PYTHON, str(root / "tools" / "verify_new_records.py"), "HEAD~1"],
                          cwd=root, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "profile integrity: SATISFIED" in proc.stdout
    assert re.search(r"derivation_verification\s+NOT_CHECKED", proc.stdout)
    assert not marker.exists()


# --- C8: reports are complete, and unimplemented assurances never PASS -----


def _scenarios(root: Path, tmp_path: Path) -> List[Tuple[str, Report]]:
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"}, environment=b"lockfile")
    refused = derive(root, b"x", [a], b"", runtime="node")
    broken = "0" * 64
    write_record_raw(root, broken, "{not json")
    return [
        ("admission", check(root, a)),
        ("admission-replay", check(root, a, replay=True)),
        ("derivation", check(root, d)),
        ("derivation-replay", check(root, d, replay=True)),
        ("refused-runtime", check(root, refused, replay=True)),
        ("broken-record", check(root, broken, replay=True)),
        ("missing-record", check(root, "1" * 64, replay=True)),
    ]


def test_C8_reports_cover_every_dimension_and_v1_cannot_pass_unimplemented_ones(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    for name, report in _scenarios(root, tmp_path):
        assert set(report.outcomes) == set(Dimension), name
        for dim in NEVER_PASS_IN_V1:
            assert status(report, dim) is not S.PASS, f"{name}: {dim.value} must not PASS in contract v1"
        if report.transforms_executed:
            assert status(report, D.EXECUTION_SAFETY) is S.FAIL, name
        for profile in ("isolated-replay", "reproducible", "authenticated-admission", "governed"):
            assert not evaluate(report, PROFILES[profile]).satisfied, (name, profile)


def test_C8_report_cannot_omit_a_dimension() -> None:
    from ledger.assurance import Outcome

    with pytest.raises(ValueError, match="omits"):
        Report(targets=("x",), outcomes={D.ARTIFACT_INTEGRITY: Outcome(S.PASS, "")})


def test_C8_broken_or_missing_records_fail_rather_than_pass(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    write_record_raw(root, "0" * 64, "{not json")
    for rid in ("0" * 64, "1" * 64):
        report = check(root, rid, replay=True)
        assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
        assert status(report, D.ARTIFACT_INTEGRITY) is S.NOT_CHECKED
        assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_CHECKED
        assert not evaluate(report, PROFILES["integrity"]).satisfied
