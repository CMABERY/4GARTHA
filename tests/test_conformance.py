"""Conformance tests for ASSURANCE.md (assurance contract 4gartha.assurance/2).

Each test is tagged with the conformance ID it establishes (C1..C10). Per
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
from ledger.execution import RESTRICTED, ReplayPolicy, restricted_policy

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
# Contract v2: these never PASS. Governance PASSes only through external
# anchoring under a policy the verifier supplies (C10), never without one (C8).
NEVER_PASS = (D.EXECUTION_SAFETY, D.REPRODUCIBILITY, D.AUTHENTICITY)


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
    # Execution safety is a property of the run, not a record claim: nothing
    # ran and no boundary was checked, so NOT_CHECKED (never NOT_APPLICABLE,
    # which a profile could accept without any sandbox existing).
    assert status(report, D.EXECUTION_SAFETY) is S.NOT_CHECKED
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


def test_C1_unattested_root_under_ci_integrity_profile(tmp_path: Path) -> None:
    """The review's reference case: an unattested root verified integrity-only.
    The verifier reports what it established; the profile decides acceptance."""
    root = init_repo(tmp_path)
    rid = admit(root, b"root evidence", statement="exported from instrument X")
    report = check(root, rid)  # what CI does: no replay
    assert {d: status(report, d) for d in Dimension} == {
        D.ARTIFACT_INTEGRITY: S.PASS,
        D.PROVENANCE_INTEGRITY: S.PASS,
        D.DERIVATION_VERIFICATION: S.NOT_APPLICABLE,
        D.EXECUTION_SAFETY: S.NOT_CHECKED,
        D.REPRODUCIBILITY: S.NOT_APPLICABLE,  # an admission makes no derivation claim
        D.AUTHENTICITY: S.NOT_CHECKED,
        D.GOVERNANCE: S.NOT_CHECKED,
    }
    assert evaluate(report, PROFILES["integrity"]).satisfied
    for strict in ("replay", "authenticated-admission", "governed", "isolated-replay", "reproducible"):
        assert not evaluate(report, PROFILES[strict]).satisfied, strict


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
    assert status(report, D.EXECUTION_SAFETY) is S.NOT_CHECKED


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


def test_C2_unstartable_runtime_is_not_reported_as_executed(tmp_path: Path) -> None:
    # Review finding: a replay whose process never started was counted as
    # executed code and reported execution_safety FAIL.
    root = init_repo(tmp_path)
    a = admit(root, b"in")
    d = derive(root, b"out", [a], marker_transform(tmp_path / "ran", b"out"))
    broken = ReplayPolicy("broken", {"python3": (str(tmp_path / "no-such-interpreter"),)})
    report = check(root, d, replay=True, policy=broken)
    assert status(report, D.DERIVATION_VERIFICATION) is S.ERROR
    assert "could not start runtime" in report.outcomes[D.DERIVATION_VERIFICATION].problems[0]
    assert (report.replay_attempts, report.transforms_executed) == (1, 0)
    assert status(report, D.EXECUTION_SAFETY) is S.NOT_CHECKED
    result = evaluate(report, PROFILES["replay"])
    assert not result.satisfied and result.error


def test_C2_execution_safety_fails_once_any_transform_process_started(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    d1 = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    d2 = derive(root, b"hello!!", [d1], concat_transform(), params={"suffix": "!"}, runtime="brokenrt")
    mixed = ReplayPolicy("mixed", {"python3": RESTRICTED.runtimes["python3"],
                                   "brokenrt": (str(tmp_path / "no-such-interpreter"),)})
    report = check(root, d2, replay=True, policy=mixed)
    assert (report.replay_attempts, report.transforms_executed) == (2, 1)
    assert status(report, D.DERIVATION_VERIFICATION) is S.ERROR
    assert status(report, D.EXECUTION_SAFETY) is S.FAIL  # d1's code did run


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
    # A satisfied replay profile must not conceal the failed safety assurance.
    replay_result = evaluate(report, PROFILES["replay"])
    assert replay_result.satisfied and replay_result.unrequired_failures == (D.EXECUTION_SAFETY,)
    proc = run_cli(root, "replay", d)
    assert proc.returncode == 0, proc.stdout
    assert "note: execution_safety is FAIL (not required by profile replay)" in proc.stdout
    doc = json.loads(run_cli(root, "replay", d, "--json").stdout)
    assert doc["profile"]["satisfied"] is True
    assert doc["profile"]["unrequired_failures"] == ["execution_safety"]


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
    original_api = records.record_id(base)
    mutated_paths = set()
    for path in _record_leaf_paths(base):
        m = copy.deepcopy(base)
        _set(m, path, _changed(_get(base, path)))
        # Hash of the stored bytes (covers constant fields such as protocol)...
        assert _id_of(m) != original, f"changing {path} did not change the record ID (stored bytes)"
        # ...and the public ID function, for every mutation that is still a
        # valid record, so record_id() itself cannot ignore a field.
        if not records.validate(m):
            assert records.record_id(m) != original_api, f"changing {path} did not change the record ID (record_id)"
        mutated_paths.add(tuple("[]" if isinstance(p, int) else p for p in path))
    assert original_api == original, "record_id() disagrees with the hash of the stored canonical bytes"

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
                if not records.validate(m):
                    assert records.record_id(m) != original_api, name

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


# --- C7: the CI admission gate does not replay; CI's token is read-only ---
#
# The claim tested here is deliberately narrow (ASSURANCE.md section 7): CI does
# not replay newly submitted ledger records as part of its admission gate. CI
# *does* execute transforms elsewhere: the test suite (run by pytest in CI)
# replays fixture transforms on purpose, and PR builds, tests and tools are
# contributor-controlled code. Nothing here claims CI is a sandbox.


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


def _gate_invocations(lines: List[str]) -> List[str]:
    return [l.strip() for l in lines if "tools/verify_new_records.py" in l]


def test_C7_admission_gate_step_does_not_replay() -> None:
    ci = _code_lines(REPO / ".github" / "workflows" / "ci.yml")
    calls = _gate_invocations(ci)
    assert len(calls) == 1, f"expected exactly one admission-gate invocation in ci.yml, found {calls}"
    assert "--replay" not in calls[0], f"the record admission gate must not replay: {calls[0]}"
    for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        for call in _gate_invocations(_code_lines(wf)):
            assert "--replay" not in call, f"{wf.name}: the record admission gate must not replay: {call}"


def test_C7_workflow_text_has_no_direct_replay_invocation() -> None:
    # A regression check for *direct* replay invocation in workflow files. It
    # is not proof that nothing in CI replays: pytest, which CI runs, replays
    # fixture transforms deliberately (e.g. test_C2_execution_is_never_reported_as_safe).
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    assert workflows
    for wf in workflows:
        code = "\n".join(_code_lines(wf))
        for forbidden in ("--replay", "ledger replay", "replay_new_nodes", "replay=True"):
            assert forbidden not in code, f"{wf.name} invokes derivation replay via {forbidden!r}"


def test_C7_ci_token_is_read_only() -> None:
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


def test_C8_reports_cover_every_dimension_and_unimplemented_ones_never_pass(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    for name, report in _scenarios(root, tmp_path):  # no anchor policy in any of these
        assert set(report.outcomes) == set(Dimension), name
        for dim in NEVER_PASS:
            assert status(report, dim) is not S.PASS, f"{name}: {dim.value} must not PASS in contract v2"
        assert status(report, D.GOVERNANCE) is not S.PASS, f"{name}: governance must not PASS without an anchor policy"
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


# --- C9: canonical encoding and record identity match the frozen vectors ---
#
# conformance/record-v1-vectors.json is language-neutral (bytes as hex) so an
# independent implementation can run the same cases. Expected outcomes were
# written by hand; record IDs were cross-checked outside Python (jq -cS +
# sha256sum). The vectors are frozen for 4gartha.record/1.

VECTORS = json.loads((REPO / "conformance" / "record-v1-vectors.json").read_text(encoding="utf-8"))
_by_name = lambda section: {v["name"]: v for v in VECTORS[section]}  # noqa: E731


def test_C9_vector_constants_match_the_implementation() -> None:
    assert VECTORS["protocol"] == records.PROTOCOL
    assert bytes.fromhex(VECTORS["domain_tag_hex"]) == records.DOMAIN_TAG == b"4gartha.record/1\x00"
    assert VECTORS["max_depth"] == canonical.MAX_DEPTH
    assert VECTORS["max_safe_integer"] == canonical.MAX_SAFE_INTEGER == 2**53 - 1


def test_C9_vectors_cover_every_canonicalization_boundary() -> None:
    reasons = {v["reason"] for v in VECTORS["decode"] if v["expect"] == "reject"}
    required = {"duplicate-key", "whitespace", "key-order", "bom", "float", "negative-zero", "nan",
                "big-int", "escape-form", "non-nfc", "non-ascii-key", "surrogate", "non-utf8", "depth", "not-json"}
    assert required <= reasons, f"missing boundary vectors: {sorted(required - reasons)}"
    accepted = {v["name"] for v in VECTORS["decode"] if v["expect"] == "accept"}
    assert {"literal-non-ascii", "short-escapes", "control-escapes-lowercase-hex", "depth-at-limit",
            "max-safe-integers", "key-order-uppercase-first"} <= accepted
    assert {r["reason"] for r in VECTORS["record_reject"]} >= {"argv", "authenticity", "non-semantic", "digest"}


# Each reject vector must fail for its stated reason, not merely fail: the
# round-trip check alone would reject (for example) duplicate keys, which would
# hide a missing duplicate-key check that other parse paths rely on.
_REASON_MESSAGE = {
    "duplicate-key": "duplicate object key",
    "whitespace": "not the canonical encoding",
    "key-order": "not the canonical encoding",
    "escape-form": "not the canonical encoding",
    "negative-zero": "not the canonical encoding",
    "bom": "byte-order mark",
    "float": "floats are not permitted",
    "nan": "is not permitted in canonical records",
    "big-int": "integer outside",
    "non-nfc": "not NFC-normalized",
    "non-ascii-key": "is not ASCII",
    "surrogate": "lone surrogate",
    "non-utf8": "not UTF-8",
    "depth": "nesting deeper than",
    "not-json": "not JSON",
}


@pytest.mark.parametrize("name", sorted(_by_name("decode")))
def test_C9_decode_vectors(name: str) -> None:
    vec = _by_name("decode")[name]
    data = bytes.fromhex(vec["hex"])
    if vec["expect"] == "accept":
        assert canonical.encode(canonical.decode(data)) == data
    else:
        with pytest.raises(canonical.CanonicalError) as exc:
            canonical.decode(data)
        assert _REASON_MESSAGE[vec["reason"]] in str(exc.value), (vec["reason"], str(exc.value))


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a": 1, "a": 1}', '{"x":{"k":1,"k":1}}'])
def test_C9_strict_parsing_rejects_duplicate_keys_without_round_trip(text: str) -> None:
    # The path used for --params-json: input text need not be canonical, so
    # only the duplicate-key check stands between it and last-value-wins.
    with pytest.raises(canonical.CanonicalError, match="duplicate object key"):
        canonical.parse_strict(text)


@pytest.mark.parametrize("name", sorted(_by_name("encode_reject")))
def test_C9_encode_rejects_rather_than_normalizes(name: str) -> None:
    value = _by_name("encode_reject")[name]["value"]
    assert canonical.problems(value)
    with pytest.raises(canonical.CanonicalError):
        canonical.encode(value)


@pytest.mark.parametrize("name", sorted(_by_name("record_ids")))
def test_C9_record_id_vectors(tmp_path: Path, name: str) -> None:
    import hashlib

    vec = _by_name("record_ids")[name]
    data = vec["canonical_utf8"].encode("utf-8")
    assert canonical.encode(vec["record"]) == data
    assert records.record_id(vec["record"]) == vec["record_id"]
    assert hashlib.sha256(data).hexdigest() == vec["plain_sha256_of_canonical"] != vec["record_id"]
    rid, path, _ = records.write(init_repo(tmp_path), vec["record"])
    assert rid == vec["record_id"] and path.read_bytes() == data
    assert records.load(tmp_path, rid).record == vec["record"]


@pytest.mark.parametrize("name", sorted(_by_name("record_reject")))
def test_C9_record_reject_vectors(tmp_path: Path, name: str) -> None:
    record = _by_name("record_reject")[name]["record"]
    assert records.validate(record)
    with pytest.raises(ValueError):
        records.write(init_repo(tmp_path), record)
    assert list((tmp_path / "ledger" / "records").iterdir()) == []


# --- C10: governance PASSes only through external anchoring, under the -----
# --- verifier's own trust policy (4gartha.anchor/1, ASSURANCE.md 5.7) ------
#
# Fixtures are built in temporary repositories with public test keys and a
# test-only Sigsum log (tools/anchor_fixtures.py). Policies are written by the
# verifier, outside the repository under test, unless a test plants one inside
# it on purpose. Tests needing Ed25519 require the [anchor] extra (installed by
# requirements.lock); test_C10_ci_has_the_anchor_extra fails in CI without it.

import hashlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402

from ledger import anchor as A  # noqa: E402
from ledger.verifier import verify  # noqa: E402

needs_ed25519 = pytest.mark.skipif(not A.ed25519_available(), reason="needs the [anchor] extra (cryptography)")

if A.ed25519_available():
    from anchor_testutil import (  # noqa: E402
        F, K, ORIGIN, STD_COSIGNERS, STD_TIME, T0, anchor_batch, anchored_repo, batch_dir, log_batch,
        note_text, policy, write_policy, write_proof,
    )

ANCHOR_VECTORS = json.loads((REPO / "conformance" / "anchor-v1-vectors.json").read_text(encoding="utf-8"))
_anchor_by_name = lambda section: {v["name"]: v for v in ANCHOR_VECTORS[section]}  # noqa: E731


def _gov(report: Report):
    return report.outcomes[D.GOVERNANCE]


def test_C10_ci_has_the_anchor_extra() -> None:
    # CI must exercise the signature checks, not skip them.
    if os.environ.get("CI", "").lower() != "true":
        pytest.skip("only enforced in CI")
    assert A.ed25519_available(), "CI must install the [anchor] extra (cryptography, via requirements.lock)"


@needs_ed25519
def test_C10_valid_anchoring_passes_and_reports_the_quorum_time_bound(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    report = check(root, d, anchor_policy=policy())
    oc = _gov(report)
    assert oc.status is S.PASS, oc
    assert evaluate(report, PROFILES["governed"]).satisfied
    ev = dict(oc.evidence)
    # Quorum 2 of 3 with cosignatures at T0+300, T0+100, T0+200: the bound is
    # the second-smallest timestamp, never the earliest (one dishonest witness
    # could backdate that).
    assert ev["anchored_no_later_than"] == STD_TIME == T0 + 200
    assert ev["anchored_no_later_than_utc"] == "2026-01-01T00:03:20Z"
    assert ev["quorum_witnesses"] == ["w2", "w3"]
    assert (ev["checkpoint_size"], ev["origin"]) == (size, ORIGIN)
    assert ev["policy_sha256"] == policy().sha256
    assert "not freshness, completeness, absence of forks" in oc.detail
    for dim in (D.EXECUTION_SAFETY, D.REPRODUCIBILITY, D.AUTHENTICITY):
        assert status(report, dim) is not S.PASS


@needs_ed25519
def test_C10_cli_governed_profile_with_the_verifiers_policy(tmp_path: Path) -> None:
    root, a, d, _ = anchored_repo(tmp_path / "repo")
    pol = write_policy(tmp_path / "verifier" / "anchor-policy")
    proc = run_cli(root, "verify", d, "--profile", "governed", "--anchor-policy", str(pol))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _cli_status(proc.stdout, D.GOVERNANCE) == "PASS"
    assert "profile governed: SATISFIED" in proc.stdout
    doc = json.loads(run_cli(root, "verify", d, "--json", "--anchor-policy", str(pol)).stdout)
    assert doc["report"]["contract"] == "4gartha.assurance/2"
    assert doc["report"]["outcomes"]["governance"]["evidence"]["anchored_no_later_than"] == STD_TIME
    no_policy = run_cli(root, "verify", d, "--profile", "governed")
    assert no_policy.returncode == 2 and _cli_status(no_policy.stdout, D.GOVERNANCE) == "NOT_CHECKED"


@needs_ed25519
def test_C10_no_policy_is_not_checked_even_with_valid_anchors(tmp_path: Path) -> None:
    root, a, d, _ = anchored_repo(tmp_path / "repo")
    for rid in (a, d):
        oc = _gov(check(root, rid))
        assert oc.status is S.NOT_CHECKED
        assert "no anchor trust policy supplied" in oc.detail


@needs_ed25519
def test_C10_policy_in_the_repository_is_never_read(tmp_path: Path) -> None:
    # A4 (or a careless commit) anchors with its own key and plants a policy
    # trusting that key wherever a verifier might look for one.
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"evidence")
    size = anchor_batch(root, signer=K["attacker"].signer)
    log_batch(root, size, submitter=K["attacker"])
    planted = F.policy_text(anchor=K["attacker"])
    for where in ("anchor-policy", "ledger/anchor-policy", ".4gartha/anchor-policy"):
        write_policy(root / where, planted)
    assert _gov(check(root, a)).status is S.NOT_CHECKED                          # no policy: nothing loaded
    honest = _gov(check(root, a, anchor_policy=policy()))
    assert honest.status is S.NOT_CHECKED                                        # the verifier's policy decides
    assert any("no signature by the policy's anchor key" in p for p in honest.problems)
    proc = run_cli(root, "verify", a, "--profile", "governed")
    assert proc.returncode == 2 and _cli_status(proc.stdout, D.GOVERNANCE) == "NOT_CHECKED"
    # Pointing at the planted file explicitly is the verifier's own choice, and
    # the CLI warns that the repository's writers control it.
    explicit = run_cli(root, "verify", a, "--anchor-policy", str(root / "anchor-policy"))
    assert "is inside the repository being verified" in explicit.stderr


@needs_ed25519
def test_C10_unanchored_records_are_not_checked(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"first")
    oc = _gov(check(root, a, anchor_policy=policy()))  # no ledger/anchors/ at all
    assert oc.status is S.NOT_CHECKED and "1 of 1 lineage record(s) not yet anchored" in oc.detail
    size = anchor_batch(root)
    log_batch(root, size)
    later = derive(root, b"first!", [a], concat_transform(), params={"suffix": "!"})
    assert _gov(check(root, a, anchor_policy=policy())).status is S.PASS
    oc = _gov(check(root, later, anchor_policy=policy()))
    assert oc.status is S.NOT_CHECKED and "1 of 2 lineage record(s) not yet anchored" in oc.detail
    assert oc.problems == (f"not anchored: {later}",)


@needs_ed25519
def test_C10_the_smallest_trusted_covering_checkpoint_is_used(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"first")
    s1 = anchor_batch(root)                      # checkpoint 1: never logged
    b = admit(root, b"second")
    s2 = anchor_batch(root)
    log_batch(root, s2)                           # checkpoint 2 covers leaf 0 as well
    oc = _gov(check(root, a, anchor_policy=policy()))
    assert oc.status is S.PASS and oc.evidence["checkpoint_size"] == s2 == 2
    log_batch(root, s1, cosigners=(("w1", T0 + 10), ("w3", T0 + 20)))
    oc = _gov(check(root, a, anchor_policy=policy()))
    assert oc.status is S.PASS and (oc.evidence["checkpoint_size"], oc.evidence["anchored_no_later_than"]) == (1, T0 + 20)
    assert _gov(check(root, b, anchor_policy=policy())).evidence["checkpoint_size"] == 2


@needs_ed25519
def test_C10_omitting_a_cosignature_never_lowers_the_time_bound(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"evidence")
    size = anchor_batch(root)
    p = log_batch(root, size)
    full = _gov(check(root, a, anchor_policy=policy())).evidence["anchored_no_later_than"]
    import dataclasses
    for keep in ((0, 1), (0, 2), (1, 2)):
        write_proof(root, size, dataclasses.replace(p, cosignatures=tuple(p.cosignatures[i] for i in keep)))
        oc = _gov(check(root, a, anchor_policy=policy()))
        assert oc.status is S.PASS and oc.evidence["anchored_no_later_than"] >= full, keep
    write_proof(root, size, dataclasses.replace(p, cosignatures=p.cosignatures[1:2]))
    assert _gov(check(root, a, anchor_policy=policy())).status is S.NOT_CHECKED


@needs_ed25519
def test_C10_below_quorum_is_not_checked(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"evidence")
    size = anchor_batch(root)
    log_batch(root, size, cosigners=(("w1", T0),))
    oc = _gov(check(root, a, anchor_policy=policy()))
    assert oc.status is S.NOT_CHECKED
    assert any("witness quorum not met: 1 valid cosignature(s)" in p for p in oc.problems)
    assert not evaluate(check(root, a, anchor_policy=policy()), PROFILES["governed"]).satisfied


@needs_ed25519
def test_C10_untrusted_signer_or_log_is_not_checked(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"evidence")
    size = anchor_batch(root, signer=K["attacker"].signer)
    log_batch(root, size, submitter=K["attacker"])
    oc = _gov(check(root, a, anchor_policy=policy()))
    assert oc.status is S.NOT_CHECKED
    assert any("no signature by the policy's anchor key" in p for p in oc.problems)
    assert any("not the policy's anchor key" in p for p in oc.problems)
    root2 = init_repo(tmp_path / "repo2")
    a2 = admit(root2, b"evidence")
    s2 = anchor_batch(root2)
    log_batch(root2, s2, log=F.TestSigsumLog(K["other-log"]))
    oc = _gov(check(root2, a2, anchor_policy=policy()))
    assert oc.status is S.NOT_CHECKED and any("is not in the policy" in p for p in oc.problems)
    other_origin = _gov(check(root2, a2, anchor_policy=policy(origin="4gartha.test/other")))
    assert other_origin.status is S.NOT_CHECKED
    assert any("is not the policy's anchor origin" in p for p in other_origin.problems)


@needs_ed25519
def test_C10_root_mismatch_fails_even_when_signed_by_the_trusted_key(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    bad = A.signed_checkpoint(ORIGIN, size, hashlib.sha256(b"not the root").digest(), K["anchor"].signer)
    (batch_dir(root, size) / A.CHECKPOINT_FILE).write_bytes(bad)
    log_batch(root, size)
    oc = _gov(check(root, d, anchor_policy=policy()))
    assert oc.status is S.FAIL
    assert any("does not match the root" in p for p in oc.problems)


@needs_ed25519
def test_C10_missing_anchored_record_fails(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    other = admit(root, b"unrelated")
    s2 = anchor_batch(root)
    log_batch(root, s2)
    assert _gov(check(root, d, anchor_policy=policy())).status is S.PASS
    records.record_path(root, other).unlink()   # outside d's lineage, but anchored
    oc = _gov(check(root, d, anchor_policy=policy()))
    assert oc.status is S.FAIL
    assert any(f"anchored record {other}" in p and "is missing" in p for p in oc.problems)


@needs_ed25519
def test_C10_non_contiguous_batches_fail(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    admit(root, b"third")
    s2 = anchor_batch(root)
    log_batch(root, s2)
    # A fork: a second batch claiming to follow the same predecessor.
    fork = batch_dir(root, s2 + 5)
    fork.mkdir()
    (fork / A.LEAVES_FILE).write_bytes((batch_dir(root, s2) / A.LEAVES_FILE).read_bytes()
                                       .replace(b'"previous_size":2', b'"previous_size":%d' % (s2 + 4)))
    (fork / A.CHECKPOINT_FILE).write_bytes((batch_dir(root, s2) / A.CHECKPOINT_FILE).read_bytes())
    oc = _gov(check(root, d, anchor_policy=policy()))
    assert oc.status is S.FAIL
    assert any("batches must be contiguous" in p for p in oc.problems)


@needs_ed25519
def test_C10_a_gap_between_batches_fails_even_when_roots_match(tmp_path: Path) -> None:
    # A batch claiming to start after a phantom leaf. Its checkpoint is signed
    # and logged over the leaves that exist, so every root matches: only the
    # contiguity check sees that previous_size skips a leaf.
    root = init_repo(tmp_path / "repo")
    first = admit(root, b"one")
    s1 = anchor_batch(root)
    log_batch(root, s1)
    late = sorted([admit(root, b"three"), admit(root, b"four")])
    bdir = batch_dir(root, s1 + 1 + len(late))
    bdir.mkdir()
    (bdir / A.LEAVES_FILE).write_bytes(A.leaves_document(s1 + 1, late))
    tree = A.Tree()
    for rid in [first] + late:
        tree.append(A.leaf_hash(A.record_leaf(rid)))
    (bdir / A.CHECKPOINT_FILE).write_bytes(A.signed_checkpoint(ORIGIN, s1 + 1 + len(late), tree.root(), K["anchor"].signer))
    log_batch(root, s1 + 1 + len(late))
    oc = _gov(check(root, late[0], anchor_policy=policy()))
    assert oc.status is S.FAIL, oc
    assert any("batches must be contiguous" in p for p in oc.problems)


@needs_ed25519
def test_C10_duplicate_leaf_fails(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    a_again = A.leaves_document(size, [a])
    bdir = batch_dir(root, size + 1)
    bdir.mkdir()
    (bdir / A.LEAVES_FILE).write_bytes(a_again)
    tree = A.Tree()
    for rid in sorted([a, d]) + [a]:
        tree.append(A.leaf_hash(A.record_leaf(rid)))
    (bdir / A.CHECKPOINT_FILE).write_bytes(A.signed_checkpoint(ORIGIN, size + 1, tree.root(), K["anchor"].signer))
    log_batch(root, size + 1)
    oc = _gov(check(root, d, anchor_policy=policy()))
    assert oc.status is S.FAIL
    assert any(f"record {a} was already anchored" in p for p in oc.problems)


def _tamper_body(root: Path, size: int, p) -> None:
    path = batch_dir(root, size) / A.CHECKPOINT_FILE
    path.write_bytes(path.read_bytes().replace(b"\n%d\n" % size, b"\n%d\n" % (size + 1), 1))


def _wrong_key_signature(root: Path, size: int, p) -> None:
    text = note_text(root, size)
    kid = A.note_key_id(ORIGIN, A.SIG_TYPE_ED25519, K["anchor"].public)
    (batch_dir(root, size) / A.CHECKPOINT_FILE).write_bytes(
        text + b"\n" + A.signature_line(ORIGIN, kid, K["attacker"].sign(text)))


def _tampered_path(root: Path, size: int, p) -> None:
    import dataclasses
    write_proof(root, size, dataclasses.replace(p, path=(bytes(32),) + p.path[1:]))


def _tampered_cosignature(root: Path, size: int, p) -> None:
    import dataclasses
    c = list(p.cosignatures)
    c[0] = dataclasses.replace(c[0], signature=bytes(64))   # w1; w2 and w3 still meet the quorum
    write_proof(root, size, dataclasses.replace(p, cosignatures=tuple(c)))


def _backdated_cosignature(root: Path, size: int, p) -> None:
    import dataclasses
    c = list(p.cosignatures)
    c[2] = dataclasses.replace(c[2], timestamp=T0 - 365 * 86400)   # w3 "cosigned a year earlier"
    write_proof(root, size, dataclasses.replace(p, cosignatures=tuple(c)))


def _tampered_tree_head(root: Path, size: int, p) -> None:
    import dataclasses
    write_proof(root, size, dataclasses.replace(p, tree_head_signature=bytes(64)))


def _tampered_leaf_signature(root: Path, size: int, p) -> None:
    import dataclasses
    write_proof(root, size, dataclasses.replace(p, leaf_signature=K["anchor"].sign(b"something else")))


@needs_ed25519
@pytest.mark.parametrize("tamper, reason", [
    (_tamper_body, "checkpoint is for tree size"),
    (_wrong_key_signature, "checkpoint signature by the policy's anchor key does not verify"),
    (_tampered_path, "does not lead to the root hash"),
    (_tampered_cosignature, "cosignature by policy witness 'w1' does not verify"),
    (_backdated_cosignature, "cosignature by policy witness 'w3' does not verify"),
    (_tampered_tree_head, "tree head signature by policy log"),
    (_tampered_leaf_signature, "sigsum.proof does not log this checkpoint"),
], ids=["checkpoint-body", "wrong-key-signature", "inclusion-path", "cosignature-quorum-otherwise-met",
        "backdated-cosignature", "tree-head-signature", "leaf-signature"])
def test_C10_tampered_evidence_fails(tmp_path: Path, tamper, reason: str) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    p = A.parse_sigsum_proof((batch_dir(root, size) / A.PROOF_FILE).read_bytes())
    tamper(root, size, p)
    oc = _gov(check(root, d, anchor_policy=policy()))
    assert oc.status is S.FAIL, oc
    assert any(reason in prob for prob in oc.problems), oc.problems


@needs_ed25519
def test_C10_a_failure_anywhere_in_the_anchor_log_fails_every_record(tmp_path: Path) -> None:
    # Add-only storage makes this permanent once committed, which is why
    # `ledger anchor verify --anchor-policy` must pass before a batch is committed.
    root, a, d, size = anchored_repo(tmp_path / "repo")
    admit(root, b"later")
    s2 = anchor_batch(root)
    p = log_batch(root, s2)
    assert _gov(check(root, a, anchor_policy=policy())).status is S.PASS
    _tampered_cosignature(root, s2, p)
    oc = _gov(check(root, a, anchor_policy=policy()))
    assert oc.status is S.FAIL and any(f"checkpoint {A.batch_name(s2)}" in prob for prob in oc.problems)


def _unexpected_file(root: Path, size: int) -> None:
    (batch_dir(root, size) / "notes.txt").write_text("x")


def _missing_checkpoint(root: Path, size: int) -> None:
    (batch_dir(root, size) / A.CHECKPOINT_FILE).unlink()


def _noncanonical_leaves(root: Path, size: int) -> None:
    path = batch_dir(root, size) / A.LEAVES_FILE
    path.write_bytes(path.read_bytes() + b"\n")


def _crlf_checkpoint(root: Path, size: int) -> None:
    path = batch_dir(root, size) / A.CHECKPOINT_FILE
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))


def _proof_version_1(root: Path, size: int) -> None:
    path = batch_dir(root, size) / A.PROOF_FILE
    path.write_bytes(path.read_bytes().replace(b"version=2", b"version=1"))


def _unexpected_entry(root: Path, size: int) -> None:
    (A.anchors_dir(root) / "latest").write_text(A.batch_name(size))


def _symlinked_leaves(root: Path, size: int) -> None:
    path = batch_dir(root, size) / A.LEAVES_FILE
    real = root / "leaves-copy.json"
    real.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(real)


@needs_ed25519
@pytest.mark.parametrize("damage, reason", [
    (_unexpected_file, "unexpected file 'notes.txt'"),
    (_missing_checkpoint, "missing checkpoint"),
    (_noncanonical_leaves, "leaves.json is not canonical JSON"),
    (_crlf_checkpoint, "control character U+000D"),
    (_proof_version_1, "pins version 2"),
    (_unexpected_entry, "unexpected entry"),
    (_symlinked_leaves, "not a regular file"),
], ids=["unexpected-file", "missing-checkpoint", "noncanonical-leaves", "crlf-checkpoint", "proof-version-1",
        "unexpected-entry", "symlink"])
def test_C10_malformed_anchor_files_fail(tmp_path: Path, damage, reason: str) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    damage(root, size)
    oc = _gov(check(root, d, anchor_policy=policy()))
    assert oc.status is S.FAIL, oc
    assert any(reason in p for p in oc.problems), oc.problems


@needs_ed25519
def test_C10_integrity_failure_prevents_governance(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    rec = record_of(root, a)
    from ledger.cas import CasPaths
    CasPaths.from_repo_root(root).object_path(rec["output"]["artifact"]).unlink()
    report = check(root, d, anchor_policy=policy())
    assert status(report, D.ARTIFACT_INTEGRITY) is S.FAIL
    assert _gov(report).status is S.NOT_CHECKED and "integrity checks did not pass" in _gov(report).detail


_BLOCK_CRYPTOGRAPHY = (
    "import sys\n"
    "class _Block:\n"
    "    def find_spec(self, name, path=None, target=None):\n"
    "        if name == 'cryptography' or name.startswith('cryptography.'):\n"
    "            raise ImportError('blocked for this test')\n"
    "sys.meta_path.insert(0, _Block())\n"
)


@needs_ed25519
def test_C10_without_the_ed25519_extra_governance_is_not_checked(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    pol = write_policy(tmp_path / "verifier" / "anchor-policy")
    code = _BLOCK_CRYPTOGRAPHY + (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from ledger import anchor\n"
        "from ledger.verifier import verify\n"
        "assert not anchor.ed25519_available()\n"
        "pol = anchor.load_policy(Path(sys.argv[2]))\n"
        "oc = verify(Path(sys.argv[1]), [sys.argv[3]], anchor_policy=pol).outcomes\n"
        "g = [v for k, v in oc.items() if k.value == 'governance'][0]\n"
        "print(json.dumps(g.to_dict()))\n"
    )
    run = lambda: subprocess.run([PYTHON, "-c", code, str(root), str(pol), d],  # noqa: E731
                                 capture_output=True, text=True, timeout=120)
    proc = run()
    assert proc.returncode == 0, proc.stderr
    g = json.loads(proc.stdout)
    assert g["status"] == "NOT_CHECKED"
    assert "pip install 'epistemic-ledger[anchor]'" in g["detail"]
    # Hash-only contradictions are still found without Ed25519.
    _tampered_path(root, size, A.parse_sigsum_proof((batch_dir(root, size) / A.PROOF_FILE).read_bytes()))
    g = json.loads(run().stdout)
    assert g["status"] == "FAIL" and any("does not lead to the root hash" in p for p in g["problems"])


def test_C10_policy_must_require_witnesses_and_reject_weak_keys(tmp_path: Path) -> None:
    good = _anchor_by_name("policies")["valid"]["text"]
    with pytest.raises(A.PolicyError, match="quorum none"):
        A.parse_policy(good.replace("quorum quorum-rule", "quorum none").encode())
    with pytest.raises(A.PolicyError, match="small-order"):
        A.parse_policy(good.replace(good.split("witness w3 ")[1].split("\n")[0], "00" * 32).encode())
    root = init_repo(tmp_path / "repo")
    rid = admit(root, b"x")
    bad = tmp_path / "bad-policy"
    bad.write_text(good.replace("quorum quorum-rule", "quorum none"))
    proc = run_cli(root, "verify", rid, "--anchor-policy", str(bad))
    assert proc.returncode == 1 and "invalid anchor policy" in proc.stderr


# Language-neutral vectors (conformance/anchor-v1-vectors.json): every expected
# outcome below is also checked against sigsum-go and x/mod's signed-note code
# by ci/anchor-go, which records the reference outcome next to ours.


def test_C10_vector_constants_and_pins() -> None:
    v = ANCHOR_VECTORS
    assert (v["protocol"], v["policy_format"]) == (A.PROTOCOL, A.POLICY_FORMAT) == ("4gartha.anchor/1", "4gartha.anchor-policy/1")
    assert "sigsum-go v0.14.1" in v["pinned_specifications"]["sigsum_go"]
    assert "signed-note@v1.1.0" in v["pinned_specifications"]["c2sp"]
    names = {s: set(_anchor_by_name(s)) for s in ("checkpoints", "policies", "sigsum_proofs", "leaves_json")}
    assert {"valid", "key-id-collision", "wrong-content-size", "unknown-key-under-origin-name", "crlf",
            "double-space-in-signature-line", "signature-noncanonical-base64"} <= names["checkpoints"]
    assert {"valid", "below-quorum", "tampered-cosignature-quorum-otherwise-met", "backdated-cosignature-timestamp",
            "omitted-cosignature-raises-time-bound", "tampered-inclusion-path", "crlf", "double-space-in-cosignature",
            "format-version-1", "unknown-log", "leaf-by-other-submitter"} <= names["sigsum_proofs"]
    assert {"quorum-none", "small-order-witness-key", "crlf", "none-as-member"} <= names["policies"]


@needs_ed25519
def test_C10_vectors_reproduce_from_the_generator() -> None:
    assert F.render() == (REPO / "conformance" / "anchor-v1-vectors.json").read_bytes(), \
        "regenerate with: python tools/anchor_fixtures.py --write"


def test_C10_rfc6962_known_answers() -> None:
    v = ANCHOR_VECTORS["rfc6962"]
    leaves = [A.leaf_hash(bytes.fromhex(h)) for h in v["leaves"]]
    tree = A.Tree()
    assert tree.root().hex() == v["roots"][0] == hashlib.sha256(b"").hexdigest()
    for n in range(1, len(leaves) + 1):
        tree.append(leaves[n - 1])
        assert A.root_of(leaves[:n]).hex() == tree.root().hex() == v["roots"][n], n


def test_C10_anchor_tree_vectors() -> None:
    v = ANCHOR_VECTORS["anchor_tree"]
    leaves = [A.leaf_hash(A.record_leaf(r)) for r in v["records"]]
    assert [h.hex() for h in leaves] == v["leaf_hashes"]
    assert v["leaf_hashes"][0] == hashlib.sha256(b"\x00" + bytes.fromhex(v["records"][0])).hexdigest()
    for n in range(len(leaves) + 1):
        assert A.root_of(leaves[:n]).hex() == v["roots"][n]
    for inc in v["inclusion"]:
        i, n, path = inc["index"], inc["size"], [bytes.fromhex(h) for h in inc["path"]]
        assert A.inclusion_path(i, leaves[:n]) == path
        root = bytes.fromhex(v["roots"][n])
        assert A.verify_inclusion(leaves[i], i, n, root, path) is None
        if path:
            assert A.verify_inclusion(leaves[i], i, n, root, [bytes(32)] + path[1:]) is not None


@needs_ed25519
def test_C10_signed_note_spec_example() -> None:
    ex = ANCHOR_VECTORS["signed_note_example"]
    name, kid, key = ex["vkey"].split("+")
    raw = A.b64decode_canonical(key)
    note = A.parse_note(ex["note"].encode())
    assert A.note_key_id(name, raw[0], raw[1:]).hex() == kid == note.signatures[0].key_id.hex()
    assert A.ed25519_verify(raw[1:], note.text, note.signatures[0].signature)


@pytest.mark.parametrize("name", sorted(_anchor_by_name("leaves_json")))
def test_C10_leaves_json_vectors(name: str) -> None:
    v = _anchor_by_name("leaves_json")[name]
    if v["expect"] == "accept":
        prev, rids = A.parse_leaves(v["text"].encode())
        assert A.leaves_document(prev, rids) == v["text"].encode()
    else:
        with pytest.raises(A.FormatError) as exc:
            A.parse_leaves(v["text"].encode())
        assert v["reason"] in str(exc.value)


@needs_ed25519
@pytest.mark.parametrize("name", sorted(_anchor_by_name("checkpoints")))
def test_C10_checkpoint_vectors(name: str) -> None:
    v = _anchor_by_name("checkpoints")[name]
    try:
        note = A.parse_note(v["note"].encode())
        body = A.parse_checkpoint_body(note.text)
    except A.FormatError as e:
        got, why = "malformed", str(e)
    else:
        fail, nc = A.note_signature_problems(note, v["origin"], bytes.fromhex(v["public_key"]), True)
        got, why = ("invalid", fail[0]) if fail else ("untrusted", nc[0]) if nc else ("trusted", "")
        if got == "trusted":
            assert body.origin == v["origin"]
    assert got == v["expect"], why
    assert v["reason"] is None or v["reason"] in why


@pytest.mark.parametrize("name", sorted(_anchor_by_name("policies")))
def test_C10_policy_vectors(name: str) -> None:
    v = _anchor_by_name("policies")[name]
    if v["expect"] == "accept":
        A.parse_policy(v["text"].encode())
    else:
        with pytest.raises(A.PolicyError) as exc:
            A.parse_policy(v["text"].encode())
        assert v["reason"] in str(exc.value)


@needs_ed25519
@pytest.mark.parametrize("name", sorted(_anchor_by_name("sigsum_proofs")))
def test_C10_sigsum_proof_vectors(name: str) -> None:
    v = _anchor_by_name("sigsum_proofs")[name]
    pol = A.parse_policy(v["policy"].encode())
    assert pol.anchor_key.hex() == v["anchor_public_key"]
    time = None
    try:
        p = A.parse_sigsum_proof(v["proof"].encode())
    except A.FormatError as e:
        got, why = "FAIL", str(e)
    else:
        r = A.sigsum_proof_trust(p, v["checkpoint_text"].encode(), pol, True)
        got, why = ("FAIL", "; ".join(r.fail)) if r.fail else ("NOT_CHECKED", "; ".join(r.not_checked)) \
            if r.not_checked else ("PASS", "")
        time = r.time if got == "PASS" else None
    assert got == v["expect"], why
    assert time == v["anchored_no_later_than"]
    assert v["reason"] is None or v["reason"] in why, why


# C10, repository side: anchors are add-only and CI checks their integrity.
# These are repository controls (ASSURANCE.md 5.7): they guard honest changes
# and A1 against a reviewing maintainer, not A4, which controls them.


@needs_ed25519
@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_C10_anchor_files_are_add_only(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    (root / "tools").mkdir()
    for name in ("check_append_only.py", "_gitdiff.py"):
        shutil.copyfile(REPO / "tools" / name, root / "tools" / name)
    git(root, "init", "-q")
    commit_all(root, "anchored")
    proof = batch_dir(root, size) / A.PROOF_FILE

    def append_only() -> subprocess.CompletedProcess:
        return subprocess.run([PYTHON, str(root / "tools" / "check_append_only.py"), "HEAD~1"], cwd=root,
                              capture_output=True, text=True, timeout=120)

    admit(root, b"more")
    s2 = anchor_batch(root)
    log_batch(root, s2)
    commit_all(root, "second batch")
    assert append_only().returncode == 0                      # additions are allowed
    _tampered_cosignature(root, size, A.parse_sigsum_proof(proof.read_bytes()))
    commit_all(root, "rewrite a stored proof")
    proc = append_only()
    assert proc.returncode == 2 and "ledger/anchors/" in proc.stderr
    git(root, "rm", "-q", "-r", f"ledger/anchors/{A.batch_name(s2)}")
    commit_all(root, "delete a batch")
    proc = append_only()
    assert proc.returncode == 2 and f"ledger/anchors/{A.batch_name(s2)}" in proc.stderr


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
@pytest.mark.parametrize("path, ok", [
    ("ledger/anchors/000000000003/leaves.json", True),
    ("ledger/anchors/000000000003/checkpoint", True),
    ("ledger/anchors/000000000003/sigsum.proof", True),
    ("ledger/anchors/3/leaves.json", False),
    ("ledger/anchors/000000000003/policy", False),
    ("ledger/anchors/anchor-policy", False),
    ("ledger/anchors/000000000003/sub/leaves.json", False),
])
def test_C10_record_gate_admits_only_anchor_batch_paths(tmp_path: Path, path: str, ok: bool) -> None:
    root = init_repo(tmp_path)
    (root / "tools").mkdir()
    for name in ("verify_new_records.py", "_gitdiff.py"):
        shutil.copyfile(REPO / "tools" / name, root / "tools" / name)
    git(root, "init", "-q")
    commit_all(root, "baseline")
    (root / path).parent.mkdir(parents=True, exist_ok=True)
    (root / path).write_text("x")
    commit_all(root, "add")
    proc = subprocess.run([PYTHON, str(root / "tools" / "verify_new_records.py"), "HEAD~1"], cwd=root,
                          capture_output=True, text=True, timeout=120)
    if ok:
        assert proc.returncode == 0, proc.stderr
    else:
        assert proc.returncode == 2 and "expected ledger/anchors/<12-digit tree size>/" in proc.stderr


def test_C10_ci_checks_anchor_integrity_and_runs_the_reference_implementation() -> None:
    ci = _code_lines(REPO / ".github" / "workflows" / "ci.yml")
    text = "\n".join(ci)
    job = text.split("  wheel:")[0]   # the required Ledger Integrity job
    assert re.search(r"^\s+run: ledger anchor verify\s*$", job, re.M), "CI must audit the anchor log"
    assert "--anchor-policy" not in job, "CI cannot judge trust; it must not pretend to with a repository policy"
    assert "run: bash ci/verify_anchor_vectors.sh" in job
    assert job.index("actions/setup-go") < job.index("ci/verify_anchor_vectors.sh")
    assert "go-version-file: ci/anchor-go/go.mod" in job
    script = (REPO / "ci" / "verify_anchor_vectors.sh").read_text()
    assert "set -euo pipefail" in script and "GOFLAGS=-mod=readonly" in script and "GOTOOLCHAIN=local" in script
    assert "-sigsum-verify" in script and "-anchors" in script
    gomod = (REPO / "ci" / "anchor-go" / "go.mod").read_text()
    assert "sigsum.org/sigsum-go v0.14.1" in gomod and "tool sigsum.org/sigsum-go/cmd/sigsum-verify" in gomod
    gomain = (REPO / "ci" / "anchor-go" / "main.go").read_text()
    assert "negativeControls(&v, work)" in gomain and '"negative_controls": 4' in gomain
    assert "no -policy to verify it against" in gomain
    gosum = (REPO / "ci" / "anchor-go" / "go.sum").read_text()
    assert "sigsum.org/sigsum-go v0.14.1 h1:" in gosum
    assert "ledger/anchors/" in (REPO / "tools" / "check_append_only.py").read_text()
