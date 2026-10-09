"""Record format (4gartha.record/1): schema, canonical bytes, ID binding,
append-only storage. Ports the v0 manifest-validation regressions (findings 3,
follow-up 4) to records, plus the canonicalization rules."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ledger import canonical, records
from ledger.assurance import Dimension as D, Status as S

from ledger_testutil import REPO, admit, check, concat_transform, derive, init_repo, put_blob, status, write_record_raw


def _nested(depth: int):
    v = 1
    for _ in range(depth):
        v = [v]
    return v


def _deriv(**over):
    rec = records.derivation("a" * 64, ["b" * 64], "c" * 64, "python3", {"k": "v"}, None)
    rec.update(over)
    return rec


def test_packaged_schema_matches_repository_schema() -> None:
    packaged = (REPO / "src" / "ledger" / "record.schema.json").read_bytes()
    assert (REPO / "ledger" / "schema" / "record.schema.json").read_bytes() == packaged


def test_valid_records_round_trip(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"}, environment=b"lock")
    for rid in (a, d):
        loaded = records.load(root, rid)
        assert loaded.problem is None, loaded.errors
        assert records.record_id(loaded.record) == rid
        assert records.record_path(root, rid).read_bytes() == canonical.encode(loaded.record)


@pytest.mark.parametrize(
    "path",
    [("protocol",), ("kind",), ("output",), ("output", "artifact"), ("inputs",), ("transform",),
     ("transform", "artifact"), ("transform", "runtime"), ("transform", "params"), ("environment",)],
)
def test_derivation_fields_are_required(path) -> None:
    rec = _deriv()
    target = rec
    for p in path[:-1]:
        target = target[p]
    del target[path[-1]]
    assert records.validate(rec), path


@pytest.mark.parametrize("path", [("output",), ("basis",), ("basis", "kind"), ("basis", "statement")])
def test_admission_fields_are_required(path) -> None:
    rec = records.admission("a" * 64, "s")
    target = rec
    for p in path[:-1]:
        target = target[p]
    del target[path[-1]]
    assert records.validate(rec), path


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(meta={"note": "x"}),
        lambda r: r["transform"].update(name="label"),
        lambda r: r.update(inputs=[]),
        lambda r: r.update(inputs=["b" * 64]),  # bare ID, not {"record": ...}
        lambda r: r.update(protocol="4gartha.record/2"),
        lambda r: r.update(kind="annotation"),
        lambda r: r["output"].update(artifact="A" * 64),
        lambda r: r.update(environment={}),
        lambda r: r["transform"].update(params=[]),
    ],
    ids=["meta", "transform-name", "no-inputs", "bare-input", "protocol", "kind", "uppercase", "empty-env", "params-list"],
)
def test_shape_violations_are_rejected(mutate) -> None:
    rec = _deriv()
    mutate(rec)
    assert records.validate(rec)


@pytest.mark.parametrize(
    "where",
    ["output", "input", "transform", "environment"],
)
def test_trailing_newline_digests_are_rejected(tmp_path: Path, where: str) -> None:
    bad = "b" * 64 + "\n"
    rec = _deriv(environment={"artifact": "d" * 64})
    {"output": lambda: rec["output"].update(artifact=bad),
     "input": lambda: rec["inputs"][0].update(record=bad),
     "transform": lambda: rec["transform"].update(artifact=bad),
     "environment": lambda: rec["environment"].update(artifact=bad)}[where]()
    assert records.validate(rec)
    with pytest.raises(ValueError):
        records.write(init_repo(tmp_path), rec)
    assert list((tmp_path / "ledger" / "records").iterdir()) == []


@pytest.mark.parametrize(
    "value,reason",
    [
        (1.5, "float"),
        (2**53, "integer outside"),
        ("é", "NFC"),
        ("\ud800", "surrogate"),
        ({"ключ": 1}, "not ASCII"),
        (_nested(40), "nesting"),
    ],
    ids=["float", "big-int", "non-nfc", "surrogate", "non-ascii-key", "deep"],
)
def test_values_without_a_canonical_form_are_rejected_not_normalized(value, reason) -> None:
    errs = canonical.problems({"v": value})
    assert errs and any(reason in e for e in errs), errs
    assert records.validate(_deriv(transform={"artifact": "c" * 64, "runtime": "python3", "params": {"v": value}}))


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":1}',
        b'{"a": 1}',
        b'{"b":1,"a":2}',
        b'{"a":1}\n',
        b"\xef\xbb\xbf{\"a\":1}",
        b'{"a":1.0}',
        b'{"a":NaN}',
        b'{"a":"\\u00e9"}',
        b"\xff",
    ],
    ids=["dup-key", "whitespace", "key-order", "trailing-newline", "bom", "float", "nan", "escaped-unicode", "not-utf8"],
)
def test_decoder_accepts_only_canonical_bytes(data: bytes) -> None:
    with pytest.raises(canonical.CanonicalError):
        canonical.decode(data)


def test_noncanonical_but_equivalent_file_fails_verification(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    rid = admit(root, b"x")
    path = records.record_path(root, rid)
    path.write_bytes(path.read_bytes() + b"\n")
    report = check(root, rid)
    assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
    assert "not the canonical encoding" in " ".join(report.outcomes[D.PROVENANCE_INTEGRITY].problems)


def test_record_must_be_stored_under_its_own_id(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    put_blob(root, b"x")
    data = canonical.encode(records.admission(put_blob(root, b"x"), "s"))
    wrong = "0" * 64
    write_record_raw(root, wrong, data)
    report = check(root, wrong)
    assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
    assert "record ID mismatch" in " ".join(report.outcomes[D.PROVENANCE_INTEGRITY].problems)


def test_self_referencing_record_cannot_be_stored_under_its_id(tmp_path: Path) -> None:
    # v0 needed explicit self-parent/cycle checks; with inputs named by record
    # ID a record listing itself would need a SHA-256 preimage.
    root = init_repo(tmp_path)
    rid = "5" * 64
    rec = records.derivation(put_blob(root, b"x"), [rid], put_blob(root, concat_transform()), "python3", {})
    write_record_raw(root, rid, canonical.encode(rec))
    report = check(root, rid, replay=True)
    assert status(report, D.PROVENANCE_INTEGRITY) is S.FAIL
    assert report.transforms_executed == 0


def test_malformed_json_is_a_failure_not_a_crash(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    for content in ("{not json", "", "[]", "null"):
        write_record_raw(root, "0" * 64, content)
        loaded = records.load(root, "0" * 64)
        assert loaded.problem == "invalid", content
        assert status(check(root, "0" * 64), D.PROVENANCE_INTEGRITY) is S.FAIL


@pytest.mark.parametrize("rid", ["A" * 64, "a" * 63, "a" * 64 + "\n", "../" + "a" * 61, ""])
def test_invalid_record_ids_are_rejected_without_path_lookup(tmp_path: Path, rid: str) -> None:
    loaded = records.load(init_repo(tmp_path), rid)
    assert loaded.problem == "invalid" and "invalid record ID" in loaded.errors[0]


def test_symlinked_record_is_not_trusted(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    data = canonical.encode(records.admission(put_blob(root, b"x"), "s"))
    rid = records.record_id_of_bytes(data)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(data)
    try:
        os.symlink(elsewhere, records.record_path(root, rid))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert records.load(root, rid).problem == "invalid"


def test_write_is_idempotent_and_never_overwrites(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    rec = records.admission(put_blob(root, b"x"), "s")
    rid, path, created = records.write(root, rec)
    assert created
    assert records.write(root, rec) == (rid, path, False)
    path.write_bytes(b"corrupt")
    with pytest.raises(records.RecordConflict, match="refusing to overwrite"):
        records.write(root, rec)
    assert path.read_bytes() == b"corrupt"
    assert [p.name for p in path.parent.iterdir()] == [path.name]  # no temp files left
