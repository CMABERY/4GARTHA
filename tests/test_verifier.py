"""Verifier and replay behaviour on records. Ports the v0 replay-integrity,
replay and reachable-verification regressions (findings 2, 6, 8, 14)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ledger import records
from ledger.assurance import PROFILES, Dimension as D, Status as S, evaluate
from ledger.cas import sha256_bytes

from ledger_testutil import (
    admit,
    check,
    concat_transform,
    derive,
    identity_marker_transform,
    init_repo,
    marker_transform,
    put_blob,
    put_blob_at,
    record_of,
    run_cli,
    status,
)


def _ok(report, profile="replay") -> bool:
    return evaluate(report, PROFILES[profile]).satisfied


def test_replay_passes_for_honest_derivation_chain(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    b = admit(root, b" world")
    d1 = derive(root, b"hello world", [a, b], concat_transform())
    d2 = derive(root, b"hello world!", [d1], concat_transform(), params={"suffix": "!"})
    report = check(root, d2, replay=True)
    assert _ok(report), report.to_dict()
    assert report.records_checked == 4 and report.transforms_executed == 2


def test_input_order_is_part_of_the_derivation(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    b = admit(root, b" world")
    swapped = derive(root, b"hello world", [b, a], concat_transform())  # claims the wrong order
    report = check(root, swapped, replay=True)
    assert status(report, D.DERIVATION_VERIFICATION) is S.FAIL
    assert "derivation mismatch" in report.outcomes[D.DERIVATION_VERIFICATION].problems[0]


def test_substituted_transform_is_rejected_and_never_executed(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    a = admit(root, b"in")
    claimed = sha256_bytes(b"# reviewed transform\n")
    put_blob_at(root, claimed, marker_transform(marker, b"out"))
    rid, _, _ = records.write(root, records.derivation(put_blob(root, b"out"), [a], claimed, "python3", {}))

    report = check(root, rid, replay=True)
    assert status(report, D.ARTIFACT_INTEGRITY) is S.FAIL
    assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_CHECKED
    assert report.transforms_executed == 0 and not marker.exists()


def test_tampered_input_artifact_is_rejected_before_execution(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    a = admit(root, b"hello")
    d = derive(root, b"hello", [a], identity_marker_transform(marker))
    put_blob_at(root, record_of(root, a)["output"]["artifact"], b"HELLO")
    report = check(root, d, replay=True)
    assert status(report, D.ARTIFACT_INTEGRITY) is S.FAIL
    assert not marker.exists()


@pytest.mark.parametrize("problem", ["missing", "mismatch"])
def test_environment_artifact_integrity_is_checked(tmp_path: Path, problem: str) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"}, environment=b"lock")
    env_path = put_blob_at(root, sha256_bytes(b"lock"), b"other")
    if problem == "missing":
        env_path.unlink()
    report = check(root, d, replay=True)
    assert status(report, D.ARTIFACT_INTEGRITY) is S.FAIL
    assert "environment artifact" in " ".join(report.outcomes[D.ARTIFACT_INTEGRITY].problems)
    assert report.transforms_executed == 0


def test_missing_input_record_fails_provenance_and_executes_nothing(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    ghost = "7" * 64
    rid, _, _ = records.write(root, records.derivation(
        put_blob(root, b"out"), [ghost], put_blob(root, marker_transform(marker, b"out")), "python3", {}))
    report = check(root, rid, replay=True)
    assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
    assert "missing record" in " ".join(report.outcomes[D.PROVENANCE_INTEGRITY].problems)
    assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_CHECKED
    assert status(report, D.ARTIFACT_INTEGRITY) is S.NOT_CHECKED  # lineage incomplete
    assert not marker.exists()


def test_invalid_ancestor_deep_in_lineage_blocks_all_replay(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    a = admit(root, b"a")
    d1 = derive(root, b"a", [a], identity_marker_transform(marker))
    d2 = derive(root, b"a", [d1], identity_marker_transform(marker))
    records.record_path(root, a).write_bytes(b"{}")
    report = check(root, d2, replay=True)
    assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
    assert report.transforms_executed == 0 and not marker.exists()


def test_shared_ancestors_are_checked_once(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"x")
    left = derive(root, b"xL", [a], concat_transform(), params={"suffix": "L"})
    right = derive(root, b"xR", [a], concat_transform(), params={"suffix": "R"})
    top = derive(root, b"xLxR", [left, right], concat_transform())
    report = check(root, top, replay=True)
    assert _ok(report), report.to_dict()
    assert report.records_checked == 4 and report.transforms_executed == 3


def test_failing_transform_is_reported_with_its_output(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"x")
    d = derive(root, b"y", [a], b"import sys\nprint('boom', file=sys.stderr)\nsys.exit(4)\n")
    report = check(root, d, replay=True)
    oc = report.outcomes[D.DERIVATION_VERIFICATION]
    assert oc.status is S.FAIL
    assert "exited with status 4" in oc.problems[0] and "boom" in oc.problems[1]


def test_stale_out_bin_in_reused_workdir_is_not_accepted(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"x")
    d = derive(root, b"child", [a], b"# exits 0 without writing output\n")
    wd = tmp_path / "wd"
    wd.mkdir()
    (wd / "out.bin").write_bytes(b"child")
    for kw in ({"workdir": wd}, {}):
        report = check(root, d, replay=True, **kw)
        assert status(report, D.DERIVATION_VERIFICATION) is S.FAIL
        assert "no output" in report.outcomes[D.DERIVATION_VERIFICATION].problems[0]


def test_workdir_is_reusable_and_kept(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    wd = tmp_path / "wd"
    for _ in range(2):
        assert _ok(check(root, d, replay=True, workdir=wd))
    runs = sorted(wd.iterdir())
    assert len(runs) == 2 and all((r / "out.bin").read_bytes() == b"hello!" for r in runs)


def test_cli_replay_keep_reports_existing_run_directory(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"x")
    d = derive(root, b"y", [a], b"import sys\nsys.exit(1)\n")
    proc = run_cli(root, "replay", d, "--keep")
    assert proc.returncode == 2
    line = next(l for l in proc.stdout.splitlines() if "run directory:" in l)
    kept = Path(line.split("run directory:", 1)[1].strip().rstrip(")"))
    assert kept.is_dir() and (kept / "transform.py").is_file()


def test_cli_exit_status_reflects_the_profile(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    assert run_cli(root, "verify", d).returncode == 0
    assert run_cli(root, "replay", d).returncode == 0
    bad = derive(root, b"nope", [a], concat_transform())
    assert run_cli(root, "verify", bad).returncode == 0      # integrity holds
    assert run_cli(root, "replay", bad).returncode == 2      # derivation refuted
    slow = derive(root, b"z", [a], b"import time\ntime.sleep(30)\n")
    assert run_cli(root, "verify", "--profile", "integrity", slow).returncode == 0


def test_cycle_among_id_valid_records_is_reported_not_skipped(tmp_path: Path, monkeypatch) -> None:
    # Unreachable without a SHA-256 preimage (a record's ID hashes its input
    # IDs), so simulate it: make two stored records each name the other. The
    # verifier must report the cycle rather than assume it cannot happen.
    root = init_repo(tmp_path)
    marker = tmp_path / "ran"
    t = put_blob(root, marker_transform(marker, b"x"))
    out = put_blob(root, b"x")
    x, y = "1" * 64, "2" * 64
    fake = {
        x: records.derivation(out, [y], t, "python3", {}),
        y: records.derivation(out, [x], t, "python3", {}),
    }
    real_load = records.load
    monkeypatch.setattr(records, "load", lambda repo, rid: records.Loaded(rid, fake[rid], None, [])
                        if rid in fake else real_load(repo, rid))

    report = check(root, x, replay=True)
    oc = report.outcomes[D.PROVENANCE_INTEGRITY]
    assert oc.status is S.FAIL
    assert any("cycle among ID-valid records" in p and f"{x} -> {y} -> {x}" in p for p in oc.problems), oc.problems
    assert status(report, D.DERIVATION_VERIFICATION) is S.NOT_CHECKED
    assert report.transforms_executed == 0 and not marker.exists()


def test_package_exports_import_cleanly() -> None:
    import importlib

    import ledger

    assert ledger.__version__ == "0.3.0"
    for name in ledger.__all__:
        importlib.import_module(f"ledger.{name}")
    for gone in ("manifest", "verify", "replay"):
        assert gone not in ledger.__all__
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(f"ledger.{gone}")


# --- review finding 5: preparation failures are typed, nothing "executed" ----


def _replayable(root: Path, tmp_path: Path) -> tuple:
    marker = tmp_path / "ran"
    a = admit(root, b"in")
    return derive(root, b"out", [a], marker_transform(marker, b"out")), marker


def _leftover_run_dirs() -> set:
    import tempfile

    return {p.name for p in Path(tempfile.gettempdir()).glob("ledger-replay-*")}


def test_unusable_workdir_is_a_typed_error(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    d, marker = _replayable(root, tmp_path)
    not_a_dir = tmp_path / "workdir-is-a-file"
    not_a_dir.write_text("x")
    report = check(root, d, replay=True, workdir=not_a_dir)  # previously an uncaught FileExistsError
    oc = report.outcomes[D.DERIVATION_VERIFICATION]
    assert oc.status is S.ERROR and "could not create a run directory" in oc.problems[0]
    assert (report.replay_attempts, report.transforms_executed) == (1, 0)
    assert status(report, D.EXECUTION_SAFETY) is S.NOT_CHECKED
    assert not marker.exists()


def test_input_materialization_failure_is_a_typed_error(tmp_path: Path, monkeypatch) -> None:
    root = init_repo(tmp_path)
    d, marker = _replayable(root, tmp_path)
    before = _leftover_run_dirs()

    def disk_full(self, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_bytes", disk_full)
    report = check(root, d, replay=True)
    monkeypatch.undo()
    oc = report.outcomes[D.DERIVATION_VERIFICATION]
    assert oc.status is S.ERROR and "could not materialize replay inputs" in oc.problems[0]
    assert report.transforms_executed == 0 and status(report, D.EXECUTION_SAFETY) is S.NOT_CHECKED
    assert not marker.exists()
    assert _leftover_run_dirs() <= before  # the run directory was removed
