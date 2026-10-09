"""Ledger records, protocol ``4gartha.record/1``.

Two identities, never conflated:

  artifact ID  sha256(artifact bytes)              -> ledger/objects/<aa>/<id>
  record ID    sha256(DOMAIN_TAG || canonical(rec)) -> ledger/records/<id>.json

A record is a claim *about* artifacts. Kinds:

  admission   an artifact enters the ledger as a root of evidence, with a
              declared trust basis (v1: only "unattested", a statement with
              no cryptographic evidence)
  derivation  an output artifact is claimed to result from running a
              transform artifact under a named runtime, with params, an
              optional environment artifact, and ordered *input records*

Inputs reference record IDs, not artifact IDs, so a derivation's ID commits
to the entire lineage beneath it, and any number of derivations (or
admissions) of identical bytes coexist under distinct record IDs. Because an
ID hashes the content that names its inputs, a cycle of valid records would
require a SHA-256 preimage.

Every field is identity-bearing; there is no non-semantic metadata. Record
files hold exactly the canonical bytes, so the stored file is the hashed
preimage (minus the domain tag).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import canonical

PROTOCOL = "4gartha.record/1"
# Preimage prefix: protocol identifier and a NUL. A record ID therefore never
# equals the plain SHA-256 of its own stored file, and IDs from a future
# protocol (different tag) cannot collide with v1 IDs by construction.
DOMAIN_TAG = PROTOCOL.encode("ascii") + b"\x00"
MAX_RECORD_BYTES = 1024 * 1024

DIGEST_RE = re.compile(r"[0-9a-f]{64}")
RUNTIME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")

# Packaged with the verifier: the expectations are pinned by the installed
# package, not by the repository being verified. ledger/schema/ holds an
# identical copy (tests/test_records.py asserts this).
_SCHEMA_PATH = Path(__file__).with_name("record.schema.json")


def is_digest(value: Any) -> bool:
    """Exactly 64 lowercase hex characters (fullmatch: no trailing newline)."""
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def admission(artifact: str, statement: str) -> Dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "kind": "admission",
        "output": {"artifact": artifact},
        "basis": {"kind": "unattested", "statement": statement},
    }


def derivation(
    output: str,
    inputs: List[str],
    transform: str,
    runtime: str,
    params: Dict[str, Any],
    environment: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "kind": "derivation",
        "output": {"artifact": output},
        "inputs": [{"record": r} for r in inputs],
        "transform": {"artifact": transform, "runtime": runtime, "params": params},
        "environment": None if environment is None else {"artifact": environment},
    }


@lru_cache(maxsize=1)
def _validator() -> Any:
    from jsonschema import Draft202012Validator

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _json_path(parts: Any) -> str:
    out = "record"
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


def validate(obj: Any) -> List[str]:
    """Every reason ``obj`` is not a valid v1 record (empty == valid)."""
    errors = [f"canonical: {e}" for e in canonical.problems(obj, "record")]
    for e in sorted(_validator().iter_errors(obj), key=lambda e: ([str(p) for p in e.absolute_path], e.message)):
        errors.append(f"schema: {_json_path(e.absolute_path)}: {e.message}")
    # JSON-schema `$` also matches before a trailing newline; the digest
    # patterns are pinned by min/maxLength, the runtime name is checked here.
    if isinstance(obj, dict) and obj.get("kind") == "derivation":
        t = obj.get("transform")
        rt = t.get("runtime") if isinstance(t, dict) else None
        if isinstance(rt, str) and RUNTIME_RE.fullmatch(rt) is None:
            errors.append(f"schema: record.transform.runtime: {rt!r} is not a runtime name")
    return errors


def encode(record: Dict[str, Any]) -> bytes:
    errors = validate(record)
    if errors:
        raise ValueError("invalid record: " + "; ".join(errors))
    return canonical.encode(record)


def record_id_of_bytes(canonical_bytes: bytes) -> str:
    return hashlib.sha256(DOMAIN_TAG + canonical_bytes).hexdigest()


def record_id(record: Dict[str, Any]) -> str:
    return record_id_of_bytes(encode(record))


def records_dir(repo_root: Path) -> Path:
    return repo_root / "ledger" / "records"


def record_path(repo_root: Path, rid: str) -> Path:
    return records_dir(repo_root) / f"{rid}.json"


def input_ids(record: Dict[str, Any]) -> List[str]:
    if record.get("kind") != "derivation":
        return []
    return [i["record"] for i in record["inputs"]]


def referenced_artifacts(record: Dict[str, Any]) -> Iterator[Tuple[str, str]]:
    """(role, artifact ID) for every artifact a valid record names directly."""
    yield "output", record["output"]["artifact"]
    if record["kind"] == "derivation":
        yield "transform", record["transform"]["artifact"]
        if record["environment"] is not None:
            yield "environment", record["environment"]["artifact"]


@dataclass(frozen=True)
class Loaded:
    """Outcome of reading one record.

    ``problem`` is None (valid), "missing", "invalid" (bytes contradict the
    record ID or the protocol) or "io" (could not be read; inconclusive).
    """

    rid: str
    record: Optional[Dict[str, Any]]
    problem: Optional[str]
    errors: List[str]


def load(repo_root: Path, rid: str) -> Loaded:
    """Read, decode, validate and ID-check one stored record. Never raises."""
    if not is_digest(rid):
        return Loaded(rid, None, "invalid", [f"invalid record ID {rid!r} (expected 64 lowercase hex)"])
    path = record_path(repo_root, rid)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return Loaded(rid, None, "missing", [f"missing record: {path}"])
    except OSError as e:
        return Loaded(rid, None, "io", [f"cannot stat record {path}: {e}"])
    if not stat.S_ISREG(st.st_mode):
        return Loaded(rid, None, "invalid", [f"record is not a regular file: {path}"])
    if st.st_size > MAX_RECORD_BYTES:
        return Loaded(rid, None, "invalid", [f"record exceeds {MAX_RECORD_BYTES} bytes: {path}"])
    try:
        data = path.read_bytes()
    except OSError as e:
        return Loaded(rid, None, "io", [f"cannot read record {path}: {e}"])
    try:
        obj = canonical.decode(data)
    except canonical.CanonicalError as e:
        return Loaded(rid, None, "invalid", [f"record {rid}: {e}"])
    errors = validate(obj)
    if errors:
        return Loaded(rid, None, "invalid", [f"record {rid}: {e}" for e in errors])
    actual = record_id_of_bytes(data)
    if actual != rid:
        return Loaded(rid, None, "invalid", [f"record ID mismatch: stored as {rid}, content hashes to {actual}"])
    return Loaded(rid, obj, None, [])


def _publish(path: Path, data: bytes) -> bool:
    """Atomically create ``path`` with ``data``; False if it already exists.

    The bytes are written to a unique temp file and hard-linked into place, so
    a crash can never leave a partially written record under a valid ID and an
    existing record is never replaced. Falls back to exclusive create where the
    filesystem has no hard links.
    """
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
            return True
        except FileExistsError:
            return False
        except OSError:
            pass  # filesystem without hard links: fall back to exclusive create
        try:
            with path.open("xb") as f:
                f.write(data)
            return True
        except FileExistsError:
            return False
    finally:
        tmp.unlink(missing_ok=True)


class RecordConflict(ValueError):
    """Something other than this record's exact bytes occupies its path."""


def write(repo_root: Path, record: Dict[str, Any]) -> Tuple[str, Path, bool]:
    """Store ``record`` append-only. Returns (record ID, path, created).

    Writing an identical record again is a no-op (same claim, same ID). An
    existing file with any other content is reported, never replaced.
    """
    data = encode(record)
    rid = record_id_of_bytes(data)
    path = record_path(repo_root, rid)
    path.parent.mkdir(parents=True, exist_ok=True)
    if _publish(path, data):
        return rid, path, True
    existing = load(repo_root, rid)
    if existing.problem is not None:
        raise RecordConflict(
            f"existing entry at {path} is not a valid copy of record {rid}: "
            + "; ".join(existing.errors)
            + " (refusing to overwrite append-only storage)"
        )
    return rid, path, False
