"""Sprint-1 — Pre-Δ verifier (Frozen fencepost).

This module is deliberately narrow: it defines an executable invariant for
schema-first validation and two circuit-breaker failure modes.

Frozen behaviors (Sprint-1):
  - Schema-first validation using a pinned Draft 2020-12 validator.
  - Deterministic hashing bytes: canon_json_bytes + sha256_prefixed.
  - Circuit breaker exit codes:
      10 WSS_HASH_INTEGRITY_FAILED
      11 DSS_REQUIRES_NON_NULL_HASH
  - Deterministic fixture runner:
      - sorted case order
      - deterministic schema error ordering
      - deterministic trace envelope (raw-bytes input hashes)

Non-goals: no Notion I/O, no operator execution, no planning/Δ, no cryptography,
no schema changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jsonschema import Draft202012Validator

from canon.ids import canon_json_bytes, sha256_prefixed


# ---- Exit codes (Frozen) ----
EXIT_OK = 0
EXIT_WSS_HASH_INTEGRITY_FAILED = 10
EXIT_DSS_REQUIRES_NON_NULL_HASH = 11

# Additional (non-frozen) exit codes for Sprint-1 harness failure modes.
EXIT_SCHEMA_VALIDATION_FAILED = 12
EXIT_FIXTURE_MISMATCH = 20
EXIT_INTERNAL_ERROR = 99


@dataclass(frozen=True)
class VerifyEnvelope:
    ok: bool
    exit_code: int
    schema_sha256: str
    schema_errors: List[Dict[str, Any]]
    errors: List[str]
    computed: Dict[str, Any]

    def to_json(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "schema_sha256": self.schema_sha256,
            "schema_errors": list(self.schema_errors),
            "errors": list(self.errors),
            "computed": dict(self.computed),
        }


def _sha256_hex(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _json_pointer(path_parts: Any) -> str:
    # jsonschema error.path / error.schema_path are deques of keys/indices.
    try:
        parts = list(path_parts)
    except Exception:
        parts = []

    def esc(p: Any) -> str:
        s = str(p)
        return s.replace("~", "~0").replace("/", "~1")

    return "" if not parts else "/" + "/".join(esc(p) for p in parts)


def _sorted_schema_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def k(e: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
        return (
            str(e.get("doc", "")),
            str(e.get("path", "")),
            str(e.get("validator", "")),
            str(e.get("message", "")),
            str(e.get("schema_path", "")),
        )

    return sorted(errors, key=k)


def _load_schema(repo_root: Path) -> Tuple[Dict[str, Any], str]:
    schema_path = repo_root / "schemas" / "nre-artifacts-v1.0.2.schema.json"
    sha_path = repo_root / "schemas" / "SCHEMA_SHA256"

    schema_bytes = schema_path.read_bytes()
    schema_sha = _sha256_hex(schema_bytes)

    pinned = sha_path.read_text(encoding="utf-8").strip()
    if pinned != schema_sha:
        raise RuntimeError(
            "schema hash pin mismatch\n"
            f"  pinned:  {pinned}\n"
            f"  actual:  {schema_sha}\n"
            f"  schema:  {schema_path}"
        )

    schema = json.loads(schema_bytes.decode("utf-8"))
    return schema, schema_sha


def _subschema(base: Dict[str, Any], def_name: str) -> Dict[str, Any]:
    defs = base.get("$defs", {})
    if def_name not in defs:
        raise KeyError(f"schema missing $defs/{def_name}")
    # Wrap the definition so $ref targets (#/$defs/...) remain resolvable.
    d = defs[def_name]
    return {
        "$schema": base.get("$schema"),
        "$defs": defs,
        **d,
    }


def _validate_doc(doc: str, instance: Any, validator: Draft202012Validator) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for err in validator.iter_errors(instance):
        out.append(
            {
                "doc": doc,
                "path": _json_pointer(err.path),
                "schema_path": _json_pointer(err.schema_path),
                "validator": str(err.validator),
                "message": str(err.message),
            }
        )
    return out


def verify_triplet(repo_root: Path, cap: Any, wss: Any, dss: Any) -> VerifyEnvelope:
    base_schema, schema_sha = _load_schema(repo_root)

    schema_errors: List[Dict[str, Any]] = []
    cap_v = Draft202012Validator(_subschema(base_schema, "CAP"))
    wss_v = Draft202012Validator(_subschema(base_schema, "WSS"))
    dss_v = Draft202012Validator(_subschema(base_schema, "DSS"))

    schema_errors.extend(_validate_doc("cap", cap, cap_v))
    schema_errors.extend(_validate_doc("wss", wss, wss_v))
    schema_errors.extend(_validate_doc("dss", dss, dss_v))
    schema_errors = _sorted_schema_errors(schema_errors)

    computed: Dict[str, Any] = {}
    errors: List[str] = []

    # Schema-first: do not continue if schema fails.
    if schema_errors:
        errors.append("SCHEMA_VALIDATION_FAILED")
        return VerifyEnvelope(
            ok=False,
            exit_code=EXIT_SCHEMA_VALIDATION_FAILED,
            schema_sha256=schema_sha,
            schema_errors=schema_errors,
            errors=errors,
            computed=computed,
        )

    # ---- WSS integrity (Frozen circuit breaker) ----
    computed_wss = sha256_prefixed(canon_json_bytes(wss.get("payload")))
    computed["wss_payload_hash"] = computed_wss

    if wss.get("hash") != computed_wss:
        errors.append("WSS_HASH_INTEGRITY_FAILED")
        computed["wss_payload_hash_expected"] = wss.get("hash")
        return VerifyEnvelope(
            ok=False,
            exit_code=EXIT_WSS_HASH_INTEGRITY_FAILED,
            schema_sha256=schema_sha,
            schema_errors=schema_errors,
            errors=errors,
            computed=computed,
        )

    # ---- DSS obligation (Frozen circuit breaker) ----
    if bool(dss.get("requires_non_null_hash")) and dss.get("hash") is None:
        errors.append("DSS_REQUIRES_NON_NULL_HASH")
        return VerifyEnvelope(
            ok=False,
            exit_code=EXIT_DSS_REQUIRES_NON_NULL_HASH,
            schema_sha256=schema_sha,
            schema_errors=schema_errors,
            errors=errors,
            computed=computed,
        )

    return VerifyEnvelope(
        ok=True,
        exit_code=EXIT_OK,
        schema_sha256=schema_sha,
        schema_errors=schema_errors,
        errors=errors,
        computed=computed,
    )


# ---- Fixtures ----

def _raw_sha256_prefixed(p: Path) -> str:
    return f"sha256:{_sha256_hex(p.read_bytes())}"


def _load_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def _run_vectors(repo_root: Path) -> List[str]:
    """Run P1/P2/P3 micro-vectors.

    Returns a list of failure strings (empty if OK).
    """

    failures: List[str] = []
    vectors_dir = repo_root / "fixtures" / "vectors"

    # P1 — strings
    strings_vec = _load_json(vectors_dir / "strings.json")
    for i, t in enumerate(strings_vec.get("tests", [])):
        from canon.strings import normalize_string

        got = normalize_string(t["in"])
        if got != t["expect"]:
            failures.append(f"strings[{i}]: expected {t['expect']!r}, got {got!r}")

    # P2 — ids
    ids_vec = _load_json(vectors_dir / "ids.json")
    for i, t in enumerate(ids_vec.get("tests", [])):
        got = sha256_prefixed(canon_json_bytes(t["obj"]))
        if got != t["expect"]:
            failures.append(f"ids[{i}]: expected {t['expect']!r}, got {got!r}")

    # P3 — fileref
    fileref_vec = _load_json(vectors_dir / "fileref.json")
    from canon.fileref import file_ref

    for i, t in enumerate(fileref_vec.get("tests", [])):
        p = vectors_dir / t["path"]
        got = file_ref(p).raw_sha256
        if got != t["expect"]:
            failures.append(f"fileref[{i}]: expected {t['expect']!r}, got {got!r}")

    return failures


def _run_case(repo_root: Path, case_dir: Path) -> Tuple[bool, Dict[str, Any], Dict[str, Any]]:
    """Run a single fixture case.

    Returns: (ok, actual_envelope, expected_envelope)
    """

    cap_p = case_dir / "cap.json"
    wss_p = case_dir / "wss.json"
    dss_p = case_dir / "dss.json"
    exp_p = case_dir / "expected.json"

    trace = {
        "case": case_dir.name,
        "inputs": {
            "cap": {"raw_sha256": _raw_sha256_prefixed(cap_p)},
            "wss": {"raw_sha256": _raw_sha256_prefixed(wss_p)},
            "dss": {"raw_sha256": _raw_sha256_prefixed(dss_p)},
        },
    }

    cap = _load_json(cap_p)
    wss = _load_json(wss_p)
    dss = _load_json(dss_p)

    env = verify_triplet(repo_root, cap, wss, dss).to_json()
    actual: Dict[str, Any] = {"trace": trace, "verify": env}

    expected: Dict[str, Any] = _load_json(exp_p)

    return actual == expected, actual, expected


def run_fixtures(repo_root: Path) -> int:
    """Run all fixtures in deterministic order."""

    # Vectors first.
    v_fail = _run_vectors(repo_root)
    if v_fail:
        for f in v_fail:
            print(f"VECTOR_FAIL: {f}", file=sys.stderr)
        return EXIT_FIXTURE_MISMATCH

    cases_root = repo_root / "fixtures" / "cases"
    case_dirs = sorted([p for p in cases_root.iterdir() if p.is_dir()], key=lambda p: p.name)

    mismatches: List[str] = []
    for case_dir in case_dirs:
        ok, actual, expected = _run_case(repo_root, case_dir)
        if not ok:
            mismatches.append(case_dir.name)
            print(f"CASE_MISMATCH: {case_dir.name}", file=sys.stderr)
            print("--- expected", file=sys.stderr)
            print(json.dumps(expected, indent=2, sort_keys=True), file=sys.stderr)
            print("--- actual", file=sys.stderr)
            print(json.dumps(actual, indent=2, sort_keys=True), file=sys.stderr)

    if mismatches:
        print(f"mismatched cases: {', '.join(sorted(mismatches))}", file=sys.stderr)
        return EXIT_FIXTURE_MISMATCH

    print(f"fixtures: OK ({len(case_dirs)} cases)")
    return EXIT_OK


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nre-verify-fixtures")
    ap.add_argument("--all", action="store_true", help="run all vectors + cases")

    args = ap.parse_args(argv)

    if not args.all:
        ap.print_help(sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[1]

    try:
        return run_fixtures(repo_root)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"INTERNAL_ERROR: {e}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
