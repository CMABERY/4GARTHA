#!/usr/bin/env python3
"""Planted-defect harness for the 4GARTHA test suite (ASSURANCE.md section 8).

Measures test *sensitivity*: for each catalogued defect it plants that one
defect in a fresh, disposable copy of a committed revision, runs the tests
designed to catch it, and requires each of them to fail *for the expected
reason*. A pass shows the suite detects these particular defects; it is not
evidence of exhaustive security coverage.

Manual maintenance command (not run in CI):

    python tools/planted_defects.py                # every defect, at HEAD
    python tools/planted_defects.py --rev <commit> --json result.json
    python tools/planted_defects.py --list         # show the catalogue
    python tools/planted_defects.py --only M1 M9 --explain --keep

Requires git and a Python environment with requirements.lock installed.

Trust boundary: the disposable checkout isolates *files*, not *execution*. The
tests it runs execute as the invoking user, with that user's filesystem
access, network and most environment variables (PYTHONPATH, PYTEST_ADDOPTS and
plugin autoloading are overridden). Run it only on revisions you trust as much
as your own code; it is not a way to inspect untrusted changes.

Guarantees:
  - Isolation: works only in a harness-owned temporary directory; the
    invoking working tree is never written to (checked before and after).
  - Determinism: the committed revision is exported once (`git archive`);
    the baseline and every defect start from a fresh extraction of those
    same bytes. Uncommitted changes are never tested.
  - Attribution: each result names the defect, its expected detecting tests
    and reasons, and the observed failures.
  - Strictness: a defect counts as detected only if every expected test
    fails (an assertion failure, not an error) and its failure text matches
    the expected reason. The baseline must pass and must contain every
    expected test.
  - Fail-closed: a mutation that does not apply exactly once, an
    undetected defect, a wrong-reason failure, an import resolving outside
    the disposable copy, a pytest error/timeout/interrupt, or an incomplete
    run makes the result FAIL.
  - Cleanup: removes only the temporary directory it created (--keep
    retains it for debugging).

Exit status: 0 PASS; 1 FAIL; 2 usage error.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

CONFORMANCE = "tests/test_conformance.py"
WORK_PREFIX = "4gartha-planted-defects-"


@dataclass(frozen=True)
class Defect:
    id: str
    description: str
    file: str
    old: str
    new: str
    # (pytest node ID, regex the failure text must match). Every entry must
    # fail for its reason for the defect to count as detected.
    expect: Tuple[Tuple[str, str], ...]
    targets: Tuple[str, ...] = (CONFORMANCE,)


def _c(name: str) -> str:
    return f"{CONFORMANCE}::{name}"


_FAIL_IS = r"assert <Status\.{got}: '{got}'> is <Status\.{want}: '{want}'>"


def _is(got: str, want: str) -> str:
    return _FAIL_IS.format(got=got, want=want)


_M49 = r"assert b\.note is not None and b\.body is not None"


CATALOGUE: Tuple[Defect, ...] = (
    Defect("M1", "root replay reported as PASS", "src/ledger/verifier.py",
           'dv = Outcome(Status.NOT_APPLICABLE, "lineage contains only admission records',
           'dv = Outcome(Status.PASS, "lineage contains only admission records',
           ((_c("test_C1_root_replay_is_not_applicable_not_success"), _is("PASS", "NOT_APPLICABLE")),)),
    Defect("M2", "replay policy permits any runtime name", "src/ledger/execution.py",
           "        return self.runtimes.get(runtime)",
           '        return self.runtimes.get(runtime) or (sys.executable, "-I")',
           ((_c("test_C2_unlisted_runtime_is_refused_before_execution"), _is("PASS", "NOT_CHECKED")),)),
    Defect("M3", "transform inherits the verifier's environment", "src/ledger/execution.py",
           '    env = {\n        "PATH": os.defpath,',
           '    env = {**os.environ,\n        "PATH": os.defpath,',
           ((_c("test_C2_transform_does_not_inherit_verifier_environment"), r"must-not-leak"),)),
    Defect("M4", "record ID computed without the domain tag", "src/ledger/records.py",
           "return hashlib.sha256(DOMAIN_TAG + canonical_bytes).hexdigest()",
           "return hashlib.sha256(canonical_bytes).hexdigest()",
           ((_c("test_C4_record_ids_are_domain_separated"), r"assert '[0-9a-f]{64}' != '[0-9a-f]{64}'"),
            (_c("test_C9_record_id_vectors[admission-ascii]"), r"record_id")),),
    Defect("M5", "record ID ignores derivation inputs", "src/ledger/records.py",
           "def record_id(record: Dict[str, Any]) -> str:\n    return record_id_of_bytes(encode(record))",
           "def record_id(record: Dict[str, Any]) -> str:\n"
           '    return record_id_of_bytes(canonical.encode({k: v for k, v in record.items() if k != "inputs"}))',
           ((_c("test_C4_changing_any_field_changes_the_record_id[derivation-env]"),
             r"changing \('inputs', 0, 'record'\) did not change the record ID \(record_id\)"),
            (_c("test_C9_record_id_vectors[derivation-with-environment]"), r"record_id"))),
    Defect("M6", "governance reported as PASS without an anchor policy", "src/ledger/verifier.py",
           "o[Dimension.GOVERNANCE] = Outcome(Status.NOT_CHECKED, GOVERNANCE_NO_POLICY)",
           "o[Dimension.GOVERNANCE] = Outcome(Status.PASS if lin.complete else Status.NOT_CHECKED, GOVERNANCE_NO_POLICY)",
           ((_c("test_C6_repository_controls_do_not_produce_governance_assurance"), _is("PASS", "NOT_CHECKED")),
            (_c("test_C8_reports_cover_every_dimension_and_unimplemented_ones_never_pass"), r"governance must not PASS"),
            (_c("test_C10_no_policy_is_not_checked_even_with_valid_anchors"), _is("PASS", "NOT_CHECKED")))),
    Defect("M7", "unattested admission reported as authentic", "src/ledger/verifier.py",
           "        o[Dimension.AUTHENTICITY] = Outcome(\n            Status.NOT_CHECKED,\n            f\"{len(admissions)}",
           "        o[Dimension.AUTHENTICITY] = Outcome(\n            Status.PASS,\n            f\"{len(admissions)}",
           ((_c("test_C5_unsigned_admission_fails_authenticated_profile"), _is("PASS", "NOT_CHECKED")),
            (_c("test_C8_reports_cover_every_dimension_and_unimplemented_ones_never_pass"), r"authenticity must not PASS"))),
    Defect("M8", "unsandboxed execution reported as safe", "src/ledger/verifier.py",
           "o[Dimension.EXECUTION_SAFETY] = Outcome(Status.FAIL,",
           "o[Dimension.EXECUTION_SAFETY] = Outcome(Status.PASS,",
           ((_c("test_C2_execution_is_never_reported_as_safe"), _is("PASS", "FAIL")),
            (_c("test_C8_reports_cover_every_dimension_and_unimplemented_ones_never_pass"), r"execution_safety must not PASS"))),
    Defect("M9", "record schema admits a runner argv", "src/ledger/record.schema.json",
           '"required": ["artifact", "runtime", "params"],\n          "properties": {',
           '"required": ["artifact", "runtime", "params"],\n          "properties": {"runner": {"type": "array"},',
           ((_c("test_C2_records_cannot_carry_argv[runner-argv]"), r"record selecting argv must be invalid"),
            (_c("test_C9_record_reject_vectors[transform-runner-argv]"), r"assert \[\]"))),
    Defect("M10", "CI workflow invokes replay", ".github/workflows/ci.yml",
           "python tools/verify_new_records.py $LEDGER_DIFF_ARGS",
           "python tools/verify_new_records.py --replay $LEDGER_DIFF_ARGS",
           ((_c("test_C7_admission_gate_step_does_not_replay"), r"the record admission gate must not replay"),
            (_c("test_C7_workflow_text_has_no_direct_replay_invocation"), r"ci\.yml invokes derivation replay via '--replay'"))),
    Defect("M11", "CI workflow token can write", ".github/workflows/ci.yml",
           "permissions:\n  contents: read", "permissions:\n  contents: write",
           ((_c("test_C7_ci_token_is_read_only"), r"\['contents: write'\]"),)),
    Defect("M12", "CI record gate replays by default", "tools/verify_new_records.py",
           "    report = verify(repo_root, sorted(new_ids), replay=args.replay)",
           "    report = verify(repo_root, sorted(new_ids), replay=True)",
           ((_c("test_C7_ci_record_gate_executes_nothing"), r"derivation_verification\\s\+NOT_CHECKED"),)),
    Defect("M13", "unrequested replay reported as PASS", "src/ledger/verifier.py",
           'dv = Outcome(Status.NOT_CHECKED, f"replay not requested',
           'dv = Outcome(Status.PASS, f"replay not requested',
           ((_c("test_C1_unrequested_replay_is_not_checked"), _is("PASS", "NOT_CHECKED")),)),
    Defect("M14", "record schema admits a signature basis", "src/ledger/record.schema.json",
           '"kind": {"const": "unattested"},',
           '"kind": {"enum": ["unattested", "signature"]}, "key": {"type": "string"}, "sig": {"type": "string"},',
           ((_c("test_C5_unverifiable_authenticity_claims_are_rejected[signature-kind]"), r"assert \[\]"),
            (_c("test_C9_record_reject_vectors[signature-basis-kind]"), r"assert \[\]"))),
    Defect("M15", "record ID ignores transform params", "src/ledger/records.py",
           "def record_id(record: Dict[str, Any]) -> str:\n    return record_id_of_bytes(encode(record))",
           "def record_id(record: Dict[str, Any]) -> str:\n    import copy as _c; r = _c.deepcopy(record)\n"
           '    if r.get("kind") == "derivation": r["transform"]["params"] = {}\n'
           "    return record_id_of_bytes(encode(r))",
           ((_c("test_C4_changing_any_field_changes_the_record_id[derivation-env]"),
             r"changing \('transform', 'params'\) did not change the record ID \(record_id\)"),
            (_c("test_C9_record_id_vectors[derivation-with-environment]"), r"record_id"))),
    Defect("M16", "CI job grants itself write permission", ".github/workflows/ci.yml",
           "    name: Ledger Integrity\n    runs-on: ubuntu-latest",
           "    name: Ledger Integrity\n    permissions:\n      contents: read\n      pull-requests: write\n    runs-on: ubuntu-latest",
           ((_c("test_C7_ci_token_is_read_only"), r"no job may request write permissions"),)),
    Defect("M17", "canonical encoding accepts floats", "src/ledger/canonical.py",
           '        return [f"{path}: floats are not permitted in canonical records"]', "        return []",
           ((_c("test_C9_encode_rejects_rather_than_normalizes[float]"), r"assert \[\]"),)),
    Defect("M18", "canonical encoding skips the NFC check", "src/ledger/canonical.py",
           '    if not unicodedata.is_normalized("NFC", s):', "    if False:",
           ((_c("test_C9_decode_vectors[non-nfc-string]"), r"DID NOT RAISE"),
            (_c("test_C9_encode_rejects_rather_than_normalizes[non-nfc-string]"), r"assert \[\]"))),
    Defect("M19", "duplicate object keys accepted", "src/ledger/canonical.py",
           '        if key in out:\n            raise CanonicalError(f"duplicate object key {key!r}")', "        pass",
           ((_c("test_C9_decode_vectors[duplicate-key]"), r"duplicate-key"),
            (_c("test_C9_strict_parsing_rejects_duplicate_keys_without_round_trip[{\"a\":1,\"a\":2}]"), r"DID NOT RAISE"))),
    Defect("M20", "canonical encoding escapes non-ASCII", "src/ledger/canonical.py",
           'obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False',
           'obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False',
           ((_c("test_C9_decode_vectors[literal-non-ascii]"), r"not the canonical encoding"),
            (_c("test_C9_record_id_vectors[admission-non-ascii]"), r"canonical\.encode")),),
    Defect("M21", "decoder drops the byte-for-byte round-trip check", "src/ledger/canonical.py",
           "    if encode(obj) != data:", "    if False:",
           ((_c("test_C9_decode_vectors[whitespace-after-colon]"), r"DID NOT RAISE"),
            (_c("test_C9_decode_vectors[escaped-non-ascii]"), r"DID NOT RAISE"))),
    Defect("M22", "execution safety NOT_APPLICABLE when nothing ran", "src/ledger/verifier.py",
           '            Status.NOT_CHECKED,\n            "no transform was executed in this run, and no isolation boundary was checked "',
           '            Status.NOT_APPLICABLE,\n            "no transform was executed in this run, and no isolation boundary was checked "',
           ((_c("test_C1_root_replay_is_not_applicable_not_success"), _is("NOT_APPLICABLE", "NOT_CHECKED")),
            (_c("test_C1_unattested_root_under_ci_integrity_profile"), r"EXECUTION_SAFETY"))),
    Defect("M23", "satisfied profile conceals a failed dimension", "src/ledger/assurance.py",
           "            d for d in Dimension if d not in profile.requires and report.status(d) is Status.FAIL",
           "            d for d in () if d",
           ((_c("test_C2_execution_is_never_reported_as_safe"), r"unrequired_failures"),)),
    Defect("M24", "verifier skips cycles instead of failing", "src/ledger/verifier.py",
           "                lin.cycles.append(path[path.index(nxt):] + [nxt])", "                pass",
           (("tests/test_verifier.py::test_cycle_among_id_valid_records_is_reported_not_skipped", _is("PASS", "FAIL")),),
           targets=("tests/test_verifier.py",)),
    Defect("M25", "refs set does not check its target record", "src/ledger/cli.py",
           '    _require_integrity(repo_root, [rid], "ref target record")', "    pass",
           (("tests/test_refs.py::test_ref_target_must_exist_and_pass_integrity[missing-record]", r"assert 0 != 0"),
            ("tests/test_refs.py::test_ref_target_must_exist_and_pass_integrity[missing-artifact]", r"assert 0 != 0")),
           targets=("tests/test_refs.py",)),
    Defect("M26", "derive does not check its input records", "src/ledger/cli.py",
           '        _require_integrity(repo_root, inputs, "input record")', "        pass",
           (("tests/test_ingest_cli_lock.py::test_derive_requires_inputs_to_pass_integrity[missing-artifact]", r"assert 0 != 0"),
            ("tests/test_ingest_cli_lock.py::test_derive_rejects_invalid_input_without_writing[missing-record]", r"assert 0 != 0")),
           targets=("tests/test_ingest_cli_lock.py",)),
    Defect("M27", "domain tag changed without a protocol change", "src/ledger/records.py",
           'DOMAIN_TAG = PROTOCOL.encode("ascii") + b"\\x00"', 'DOMAIN_TAG = PROTOCOL.encode("ascii") + b"\\x01"',
           ((_c("test_C9_vector_constants_match_the_implementation"), r"DOMAIN_TAG"),
            (_c("test_C4_record_ids_are_domain_separated"), r'hashlib\.sha256\(b"4gartha\.record/1\\x00" \+ data\)'))),
    # Defects found in implementation review of PR #34, re-planted in their
    # original form: each must be caught by the regression test added for it.
    Defect("M28", "record writer ignores the size limit the reader enforces", "src/ledger/records.py",
           "        if size > MAX_RECORD_BYTES:", "        if False:",
           (("tests/test_records.py::test_oversized_record_is_refused_before_publication", r"assert False"),),
           targets=("tests/test_records.py",)),
    Defect("M29", "CAS publication clobbers a concurrently created entry", "src/ledger/cas.py",
           "    if not publish_no_clobber(tmp, dst):",
           "    os.replace(tmp, dst)\n    if False:",
           (("tests/test_cas_existing_objects.py::test_store_blob_race_with_corrupt_competitor_is_refused_not_clobbered[link]",
             r"DID NOT RAISE"),),
           targets=("tests/test_cas_existing_objects.py",)),
    Defect("M30", "independent ID checker loops over a command substitution", "ci/verify_record_ids.sh",
           "for ((i = 0; i < count; i++)); do", "for i in $(seq 0 $((count - 1))); do",
           # The comparison counter catches it independently of the loop fix.
           (("tests/test_verify_record_ids_script.py::test_failing_seq_cannot_skip_the_comparisons",
             r"compared 0 fixture\(s\), expected 4; refusing to report success"),
            ("tests/test_verify_record_ids_script.py::test_script_never_loops_over_a_command_substitution",
             r"use an arithmetic for-loop")),
           targets=("tests/test_verify_record_ids_script.py",)),
    Defect("M31", "replay attempt counted as executed code", "src/ledger/verifier.py",
           "                if ex.started:\n                    executed += 1",
           "                if True:\n                    executed += 1",
           ((_c("test_C2_unstartable_runtime_is_not_reported_as_executed"), r"assert \(1, 1\) == \(1, 0\)"),)),
    Defect("M32", "run-directory failure escapes as an exception", "src/ledger/execution.py",
           '    except OSError as e:\n        return Execution("error", errors=(f"could not create a run directory: {e}",))',
           '    except ZeroDivisionError as e:\n        return Execution("error", errors=(f"could not create a run directory: {e}",))',
           (("tests/test_verifier.py::test_unusable_workdir_is_a_typed_error", r"FileExistsError"),),
           targets=("tests/test_verifier.py",)),
    # External anchoring (4gartha.anchor/1, C10). Each targets the only check
    # that stands between the defect and a wrong governance result.
    Defect("M33", "anchor policy read from the repository when none is supplied", "src/ledger/verifier.py",
           "    if anchor_policy is None:\n        o[Dimension.GOVERNANCE]",
           '    if anchor_policy is None and (repo_root / "anchor-policy").is_file():\n'
           '        anchor_policy = anchor.load_policy(repo_root / "anchor-policy")\n'
           "    if anchor_policy is None:\n        o[Dimension.GOVERNANCE]",
           ((_c("test_C10_policy_in_the_repository_is_never_read"), _is("PASS", "NOT_CHECKED")),)),
    Defect("M34", "checkpoint root not compared with the root recomputed from leaves.json", "src/ledger/anchor.py",
           "                if b.body.root != root:", "                if False:",
           ((_c("test_C10_root_mismatch_fails_even_when_signed_by_the_trusted_key"), _is("PASS", "FAIL")),)),
    Defect("M35", "witness quorum ignored", "src/ledger/anchor.py",
           "    r.time = quorum_time(policy.quorum, r.verified)",
           "    r.time = min(r.verified.values(), default=None)",
           ((_c("test_C10_below_quorum_is_not_checked"), _is("PASS", "NOT_CHECKED")),
            (_c("test_C10_sigsum_proof_vectors[below-quorum]"), r"assert 'PASS' == 'NOT_CHECKED'"))),
    Defect("M36", "time bound taken from the earliest cosignature", "src/ledger/anchor.py",
           "    return times[node.threshold - 1] if len(times) >= node.threshold else None",
           "    return times[0] if len(times) >= node.threshold else None",
           ((_c("test_C10_valid_anchoring_passes_and_reports_the_quorum_time_bound"), r"assert 1767225700 == 1767225800"),
            (_c("test_C10_sigsum_proof_vectors[valid]"), r"assert 1767225700 == 1767225800"))),
    Defect("M37", "missing anchored record not detected", "src/ledger/anchor.py",
           '            if loaded.problem in ("missing", "invalid"):', '            if loaded.problem in ("invalid",):',
           ((_c("test_C10_missing_anchored_record_fails"), _is("PASS", "FAIL")),)),
    Defect("M38", "checkpoint signature not verified once its key name and ID match", "src/ledger/anchor.py",
           "    if crypto and not ed25519_verify(public_key, note.text, mine[0].signature):", "    if False:",
           ((_c("test_C10_tampered_evidence_fails[wrong-key-signature]"), _is("PASS", "FAIL")),
            (_c("test_C10_checkpoint_vectors[key-id-collision]"), r"assert 'trusted' == 'invalid'"))),
    Defect("M39", "invalid cosignature by a policy witness skipped when the quorum is met anyway", "src/ledger/anchor.py",
           '            r.fail.append(f"cosignature by policy witness {w.name!r} does not verify")', "            pass",
           ((_c("test_C10_tampered_evidence_fails[cosignature-quorum-otherwise-met]"), _is("PASS", "FAIL")),
            (_c("test_C10_tampered_evidence_fails[backdated-cosignature]"), _is("PASS", "FAIL")),
            (_c("test_C10_sigsum_proof_vectors[tampered-cosignature-quorum-otherwise-met]"), r"assert 'PASS' == 'FAIL'"))),
    Defect("M40", "Sigsum checksum computed as the message itself (single hash)", "src/ledger/anchor.py",
           '    """What the log stores: checksum = SHA-256(message)."""\n    return hashlib.sha256(message).digest()',
           '    """What the log stores: checksum = SHA-256(message)."""\n    return message',
           ((_c("test_C10_sigsum_proof_vectors[valid]"), r"assert 'FAIL' == 'PASS'"),)),
    Defect("M41", "Sigsum inclusion path not checked", "src/ledger/anchor.py",
           "    return verify_inclusion(lh, p.leaf_index, p.size, p.root, p.path)", "    return None",
           ((_c("test_C10_tampered_evidence_fails[inclusion-path]"), _is("PASS", "FAIL")),
            (_c("test_C10_sigsum_proof_vectors[tampered-inclusion-path]"), r"assert 'PASS' == 'FAIL'"))),
    Defect("M42", "append-only check omits ledger/anchors", "tools/check_append_only.py",
           '"ledger/nodes/", "ledger/anchors/")', '"ledger/nodes/")',
           ((_c("test_C10_anchor_files_are_add_only"), r"assert \(0 == 2\)"),)),
    Defect("M43", "RFC 6962 leaf hash without its 0x00 prefix", "src/ledger/anchor.py",
           '    return hashlib.sha256(b"\\x00" + data).digest()', "    return hashlib.sha256(data).digest()",
           ((_c("test_C10_rfc6962_known_answers"), r"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
            (_c("test_C10_anchor_tree_vectors"), r"assert \["))),
    Defect("M44", "governance evaluated although integrity did not pass", "src/ledger/verifier.py",
           "          or o[Dimension.PROVENANCE_INTEGRITY].status is not Status.PASS):\n        o[Dimension.GOVERNANCE] = Outcome(",
           "          or o[Dimension.PROVENANCE_INTEGRITY].status is not Status.PASS) and False:\n        o[Dimension.GOVERNANCE] = Outcome(",
           ((_c("test_C10_integrity_failure_prevents_governance"), r"assert \(" + _is("PASS", "NOT_CHECKED")[len("assert "):]),)),
    Defect("M45", "record gate admits any path under ledger/anchors", "tools/verify_new_records.py",
           "                if ANCHOR_PATH_RE.fullmatch(p) is None:", "                if False:",
           ((_c("test_C10_record_gate_admits_only_anchor_batch_paths[ledger/anchors/anchor-policy-False]"), r"assert \(0 == 2\)"),)),
    Defect("M46", "batches accepted without checking contiguity", "src/ledger/anchor.py",
           "            if b.previous_size != expected:", "            if False:",
           ((_c("test_C10_a_gap_between_batches_fails_even_when_roots_match"), _is("PASS", "FAIL")),)),
    # Defects found in implementation review of PR #41 (anchoring phase 1),
    # re-planted in their original form. M47 and M48 need a Python that limits
    # int() digits (3.10.7+), as the defects themselves do.
    Defect("M47", "anchor decimals converted with int() before their length is bounded", "src/ledger/anchor.py",
           "    if len(text) > _MAX_DECIMAL_DIGITS or _DECIMAL_RE.fullmatch(text) is None:",
           "    if _DECIMAL_RE.fullmatch(text) is None:",
           ((_c("test_C10_oversized_decimals_fail_rather_than_crash[checkpoint-tree-size]"),
             r"Exceeds the limit \(\d+ digits\) for integer string conversion"),
            (_c("test_C10_oversized_decimals_fail_rather_than_crash[proof-version]"),
             r"Exceeds the limit \(\d+ digits\) for integer string conversion"))),
    Defect("M48", "policy threshold converted with int() before its length is bounded", "src/ledger/anchor.py",
           "                k = _decimal(k_text)   # bounded before conversion",
           "                k = int(k_text)",
           (("tests/test_anchor.py::test_policy_threshold_is_bounded_before_conversion",
             r"Exceeds the limit \(\d+ digits\) for integer string conversion"),),
           targets=("tests/test_anchor.py",)),
    Defect("M49", "checkpoint trust assumes the checkpoint was read", "src/ledger/anchor.py",
           "    fail, nc = list(b.fail), []\n",
           "    assert b.note is not None and b.body is not None\n    fail, nc = list(b.fail), []\n",
           # The re-planted line, as printed in the CLI's traceback and in pytest's.
           ((_c("test_C10_unreadable_anchor_files_are_errors[checkpoint]"), _M49),
            (_c("test_C10_unreadable_anchor_files_are_errors[batch-directory]"), _M49),
            (_c("test_C10_a_contradiction_outranks_an_unreadable_file[other-checkpoint]"), _M49))),
    Defect("M50", "UTC formatting limited to the platform's time range", "src/ledger/anchor.py",
           "    if not 0 <= timestamp <= MAX_UTC_TIMESTAMP:\n        return None\n"
           '    return (_EPOCH + _dt.timedelta(seconds=timestamp)).strftime("%Y-%m-%dT%H:%M:%SZ")',
           '    return _dt.datetime.fromtimestamp(timestamp, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")',
           ((_c("test_C10_a_time_bound_past_the_utc_calendar_is_reported_as_the_integer"), r", in utc\b"),)),
    Defect("M51", "whole-log trust reports a read error before a known contradiction", "src/ledger/anchor.py",
           "    failed = _log_fail_or_error(a)\n    if failed is not None:\n        return failed\n"
           "    if a.policy is None:",
           "    integ = integrity_outcome(a)\n    if integ.status in (Status.FAIL, Status.ERROR):\n"
           '        return Outcome(integ.status, "anchor log integrity did not pass", integ.problems)\n'
           "    failed = _log_fail_or_error(a)\n    if failed is not None:\n        return failed\n"
           "    if a.policy is None:",
           ((_c("test_C10_a_contradiction_outranks_an_unreadable_file[own-proof]"), _is("ERROR", "FAIL")),
            (_c("test_C10_a_contradiction_outranks_an_unreadable_file[other-checkpoint]"), _is("ERROR", "FAIL")))),
    # Found in the follow-up review: partial audits.
    Defect("M52", "structural checks abandoned when any batch is not sound", "src/ledger/anchor.py",
           "    tree = Tree()\n    prefix: Optional[Cause] = None",
           # The original early return, for a non-empty log (on an empty one it skipped nothing).
           "    if a.batches and not all(b.sound for b in a.batches):\n"
           "        if not a.fail and not a.error:\n"
           '            a.fail.append("anchor log is malformed")\n'
           "        return\n"
           "    tree = Tree()\n    prefix: Optional[Cause] = None",
           tuple((_c(f"test_C10_a_partial_audit_fails_on_a_contradiction_in_what_it_read[{case}]"),
                  r"assert \('ERROR', 'ERROR'\) == \('FAIL', 'FAIL'\)")
                 for case in ("root-proof", "root-leaves", "gap-leaves"))),
    Defect("M53", "checkpoint PASS inferred from the absence of errors", "src/ledger/anchor.py",
           "    structure = _worst(b.checks.get(c, Status.NOT_CHECKED) for c in BATCH_CHECKS)",
           "    structure = Status.FAIL if b.fail else Status.ERROR if b.errors else Status.PASS",
           tuple((_c(f"test_C10_a_partial_audit_does_not_conclude_past_what_it_could_not_read[{case}]"),
                  r"At index 1 diff: <Status\.PASS: 'PASS'> != <Status\.ERROR: 'ERROR'>")
                 for case in ("correct-leaves", "wrong-leaves"))),
)


# --- results -------------------------------------------------------------

DETECTED, UNDETECTED, WRONG_REASON, INFRA, NOT_RUN = (
    "detected", "undetected", "wrong_reason", "infrastructure_error", "not_run")


@dataclass
class Result:
    id: str
    description: str
    status: str = NOT_RUN
    detail: str = ""
    expected: List[Dict[str, str]] = field(default_factory=list)
    other_failures: List[str] = field(default_factory=list)
    seconds: float = 0.0


@dataclass
class Case:
    node: str
    outcome: str  # passed | failed | error | skipped
    text: str


class HarnessError(Exception):
    pass


def _run(cmd: Sequence[str], cwd: Path, env: Optional[Dict[str, str]] = None,
         timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)


def _git(repo: Path, *args: str) -> str:
    proc = _run(["git", *args], repo)
    if proc.returncode != 0:
        raise HarnessError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _tree_state(repo: Path) -> Tuple[str, str]:
    """HEAD plus porcelain status: changes if the invoking tree is written to."""
    return (_git(repo, "rev-parse", "HEAD").strip(),
            _git(repo, "--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=all"))


def _extract(archive: bytes, dest: Path) -> None:
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tf:
        for member in tf.getmembers():  # refuse anything that could land outside dest
            p = Path(member.name)
            link = Path(member.linkname) if (member.issym() or member.islnk()) else None
            if p.is_absolute() or ".." in p.parts or (link is not None and (link.is_absolute() or ".." in link.parts)):
                raise HarnessError(f"refusing unsafe archive member {member.name!r}")
        if hasattr(tarfile, "data_filter"):  # 3.12+, and 3.10.12+/3.11.4+ backports
            tf.extractall(dest, filter="data")
        else:
            tf.extractall(dest)


def _env(checkout: Path) -> Dict[str, str]:
    env = dict(os.environ)
    for k in ("PYTEST_ADDOPTS", "LEDGER_INGEST_SESSION_LOCK", "PYTHONHOME"):
        env.pop(k, None)
    env["PYTHONPATH"] = str(checkout / "src")  # replace, never extend: no path to the invoking tree
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return env


def _check_import_location(checkout: Path, env: Dict[str, str]) -> None:
    proc = _run([sys.executable, "-c", "import ledger; print(ledger.__file__)"], checkout, env, timeout=60)
    if proc.returncode != 0:
        raise HarnessError(f"cannot import ledger in the disposable copy: {proc.stderr.strip()}")
    where = Path(proc.stdout.strip()).resolve()
    if not where.is_relative_to((checkout / "src").resolve()):
        raise HarnessError(f"ledger imports from {where}, outside the disposable copy {checkout}")


def _pytest(checkout: Path, targets: Sequence[str], junit: Path, timeout: float) -> Tuple[int, Dict[str, Case]]:
    env = _env(checkout)
    _check_import_location(checkout, env)
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "junit_family=xunit2",
           f"--junitxml={junit}", *targets]
    try:
        proc = _run(cmd, checkout, env, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise HarnessError(f"pytest timed out after {timeout:g}s") from None
    if proc.returncode not in (0, 1):  # 2 interrupted/collection error, 3 internal, 4 usage, 5 none collected
        tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-8:])
        raise HarnessError(f"pytest exited {proc.returncode} (not a test outcome):\n{tail}")
    if not junit.is_file():
        raise HarnessError("pytest produced no JUnit report")
    cases: Dict[str, Case] = {}
    for tc in ET.parse(junit).getroot().iter("testcase"):
        module = tc.get("classname", "").replace(".", "/") + ".py"
        node = f"{module}::{tc.get('name', '')}"
        outcome, text = "passed", ""
        for tag in ("failure", "error", "skipped"):
            el = tc.find(tag)
            if el is not None:
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag]
                text = (el.get("message") or "") + "\n" + (el.text or "")
                break
        cases[node] = Case(node, outcome, text)
    if proc.returncode == 1 and not any(c.outcome in ("failed", "error") for c in cases.values()):
        raise HarnessError("pytest reported failure but the JUnit report contains none")
    return proc.returncode, cases


def _apply(checkout: Path, d: Defect) -> None:
    path = checkout / d.file
    if not path.is_file():
        raise HarnessError(f"mutation target {d.file} does not exist at this revision")
    text = path.read_text(encoding="utf-8")
    n = text.count(d.old)
    if n != 1:
        raise HarnessError(f"mutation does not apply: pattern occurs {n} times in {d.file} (expected exactly 1)")
    mutated = text.replace(d.old, d.new, 1)
    if mutated == text:
        raise HarnessError("mutation is a no-op")
    path.write_text(mutated, encoding="utf-8")


def _classify(d: Defect, cases: Dict[str, Case], result: Result) -> None:
    all_ok, failed_any = True, False
    for node, reason in d.expect:
        c = cases.get(node)
        entry = {"test": node, "reason": reason}
        if c is None:
            entry["observed"] = "not collected"
            all_ok = False
        elif c.outcome == "failed" and re.search(reason, c.text):
            entry["observed"] = "failed for the expected reason"
            failed_any = True
        elif c.outcome in ("failed", "error"):
            entry["observed"] = f"{c.outcome}, but not for the expected reason: " + _first_line(c.text)
            failed_any, all_ok = True, False
        else:
            entry["observed"] = c.outcome
            all_ok = False
        result.expected.append(entry)
    expected_nodes = {n for n, _ in d.expect}
    result.other_failures = sorted(n for n, c in cases.items()
                                   if c.outcome in ("failed", "error") and n not in expected_nodes)
    if all_ok:
        result.status = DETECTED
    elif not failed_any and all(e["observed"] in ("passed", "skipped") for e in result.expected):
        result.status = UNDETECTED
        result.detail = "every expected test passed with the defect planted"
    elif any(e["observed"] == "not collected" for e in result.expected):
        result.status = INFRA
        result.detail = "an expected test was not collected"
    else:
        result.status = WRONG_REASON
        result.detail = "expected tests did not all fail for their expected reasons"


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def main(argv: Optional[Sequence[str]] = None, catalogue: Sequence[Defect] = CATALOGUE) -> int:
    ap = argparse.ArgumentParser(description="Planted-defect sensitivity check (ASSURANCE.md section 8).")
    ap.add_argument("--rev", default="HEAD", help="Committed revision to test (default: HEAD).")
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1], help="Repository (default: this checkout).")
    ap.add_argument("--json", type=Path, help="Write the machine-readable result here (default: in the system temp dir).")
    ap.add_argument("--only", nargs="+", metavar="ID", help="Run only these defects.")
    ap.add_argument("--timeout", type=float, default=900, help="Per pytest run, seconds (default: 900).")
    ap.add_argument("--keep", action="store_true", help="Keep the temporary directory for debugging.")
    ap.add_argument("--explain", action="store_true", help="Print observed failures for every defect.")
    ap.add_argument("--list", action="store_true", help="List the catalogue and exit.")
    args = ap.parse_args(argv)

    ids = [d.id for d in catalogue]
    if len(set(ids)) != len(ids):
        print("catalogue has duplicate IDs", file=sys.stderr)
        return 2
    defects = list(catalogue)
    if args.only:
        unknown = sorted(set(args.only) - set(ids))
        if unknown:
            print(f"unknown defect ID(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        defects = [d for d in catalogue if d.id in set(args.only)]
    if args.list:
        for d in defects:
            print(f"{d.id:<4} {d.description}  [{d.file}]")
            for node, reason in d.expect:
                print(f"       expects {node}  /{reason}/")
        return 0

    repo = args.repo.resolve()
    results = [Result(d.id, d.description) for d in defects]
    summary_lines: List[str] = []
    fatal: Optional[str] = None
    work: Optional[Path] = None
    started = _dt.datetime.now(_dt.timezone.utc)
    rev = ""
    try:
        rev = _git(repo, "rev-parse", "--verify", f"{args.rev}^{{commit}}").strip()
        before = _tree_state(repo)
        if before[1]:
            print(f"note: working tree has uncommitted changes; testing committed revision {rev[:12]} only")
        archive = subprocess.run(["git", "archive", "--format=tar", rev], cwd=repo,
                                 capture_output=True, check=True).stdout
        work = Path(tempfile.mkdtemp(prefix=WORK_PREFIX))
        print(f"revision {rev[:12]}; {len(defects)} defect(s); work dir {work}")

        targets = sorted({t for d in defects for t in d.targets})
        base = work / "baseline"
        _extract(archive, base)
        code, cases = _pytest(base, targets, work / "baseline.xml", args.timeout)
        bad = [n for n, c in cases.items() if c.outcome in ("failed", "error")]
        if code != 0 or bad:
            raise HarnessError("baseline (no defect planted) does not pass: " + ", ".join(bad[:5]))
        missing = sorted({n for d in defects for n, _ in d.expect} - set(cases))
        if missing:
            raise HarnessError("expected test(s) absent from the baseline run: " + ", ".join(missing))
        print(f"baseline: {len(cases)} test(s) passed")

        for d, r in zip(defects, results):
            t0 = time.monotonic()
            checkout = work / d.id
            try:
                _extract(archive, checkout)
                _apply(checkout, d)
                _, cases = _pytest(checkout, d.targets, work / f"{d.id}.xml", args.timeout)
                _classify(d, cases, r)
            except HarnessError as e:
                r.status, r.detail = INFRA, str(e)
            r.seconds = round(time.monotonic() - t0, 2)
            mark = "ok  " if r.status == DETECTED else "FAIL"
            print(f"{mark} {d.id:<4} {r.status:<22} {d.description}" + (f": {r.detail}" if r.detail else ""))
            if args.explain or r.status != DETECTED:
                for e in r.expected:
                    print(f"       {e['test']}: {e['observed']}")
                if args.explain and r.other_failures:
                    print(f"       also failed: {', '.join(r.other_failures)}")
            if not args.keep:
                shutil.rmtree(checkout, ignore_errors=True)

        if _tree_state(repo) != before:
            fatal = "the invoking working tree changed during the run"
    except KeyboardInterrupt:
        fatal = "interrupted"
    except (HarnessError, subprocess.CalledProcessError, OSError) as e:
        fatal = str(e)
    finally:
        # Remove only the directory this run created (mkdtemp, harness prefix).
        if work is not None and not args.keep and work.name.startswith(WORK_PREFIX):
            shutil.rmtree(work, ignore_errors=True)

    counts = {s: sum(1 for r in results if r.status == s) for s in (DETECTED, UNDETECTED, WRONG_REASON, INFRA, NOT_RUN)}
    passed = fatal is None and counts[DETECTED] == len(results)
    summary_lines = [
        f"Planted defects: {len(results)}",
        f"Detected as expected: {counts[DETECTED]}",
        f"Undetected: {counts[UNDETECTED]}",
        f"Unexpected failures: {counts[WRONG_REASON]}",
        f"Infrastructure errors: {counts[INFRA] + (1 if fatal else 0)}",
        f"Not run: {counts[NOT_RUN]}",
        f"Result: {'PASS' if passed else 'FAIL'}",
    ]
    print()
    if fatal:
        print(f"error: {fatal}")
    print("\n".join(summary_lines))
    if args.keep and work is not None:
        print(f"kept: {work}")

    doc = {
        "harness": "tools/planted_defects.py",
        "revision": rev,
        "python": platform.python_version(),
        "started": started.isoformat(timespec="seconds"),
        "finished": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "subset": sorted(args.only) if args.only else None,
        "fatal": fatal,
        "summary": {"planted": len(results), "detected": counts[DETECTED], "undetected": counts[UNDETECTED],
                    "unexpected_failures": counts[WRONG_REASON], "infrastructure_errors": counts[INFRA] + (1 if fatal else 0),
                    "not_run": counts[NOT_RUN], "result": "PASS" if passed else "FAIL"},
        "results": [r.__dict__ for r in results],
    }
    out = args.json or Path(tempfile.gettempdir()) / f"4gartha-planted-defects-{(rev or 'unknown')[:12]}.json"
    try:
        out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"result file: {out}")
    except OSError as e:
        print(f"could not write result file {out}: {e}", file=sys.stderr)
        passed = False
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
