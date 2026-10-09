"""`ledger` command line (protocol 4gartha.record/1, assurance contract 1).

Exit status for verify/replay: 0 the requested profile is satisfied; 2 it is
not; 3 a required dimension is ERROR (inconclusive). Refused writes and invalid
arguments exit 1 with a message (argparse usage errors exit 2).
"""
from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Dict, List

from . import canonical, records
from .assurance import PROFILES, Dimension, Report, evaluate
from .cas import CasPaths, sha256_file, store_blob, verify_existing_object
from .execution import RESTRICTED
from .locks import ingest_session_lock, ingest_session_lock_enabled
from .verifier import verify


def repo_root_from_cwd() -> Path:
    # Simple heuristic: walk up until we find 'ledger/' directory.
    p = Path.cwd().resolve()
    for _ in range(20):
        if (p / "ledger").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    raise SystemExit("Could not find repo root (missing ./ledger directory). Run inside the repo.")


def cmd_hash(args: argparse.Namespace) -> int:
    p = Path(args.path)
    if not p.exists():
        raise SystemExit(f"no such file: {p}")
    print(sha256_file(p))
    return 0


def _session(repo_root: Path, args: argparse.Namespace):
    enabled = ingest_session_lock_enabled(cli_no_session_lock=bool(args.no_session_lock))
    return ingest_session_lock(repo_root) if enabled else nullcontext()


def _require_file(path: str, what: str) -> Path:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f"no such {what}: {p}")
    return p


def _store_and_record(repo_root: Path, files: List[Path], build) -> str:
    """Hash files, check existing CAS entries, store, then write the record.

    Every check happens before anything is written, so a rejected command
    leaves neither objects nor a record behind.
    """
    cas = CasPaths.from_repo_root(repo_root)
    try:
        digests = [sha256_file(f) for f in files]
        record = build(digests)
        problems = records.validate(record)
        if problems:
            raise ValueError("invalid record: " + "; ".join(problems))
        rid = records.record_id(record)
        existing = records.load(repo_root, rid)
        if existing.problem not in (None, "missing"):
            raise records.RecordConflict(
                f"existing entry for record {rid} is not valid: " + "; ".join(existing.errors)
            )
        for d in digests:
            verify_existing_object(cas, d)
        for f, d in zip(files, digests):
            store_blob(f, cas, d)
        rid, _, created = records.write(repo_root, record)
    except (ValueError, OSError) as e:  # includes CasIntegrityError, RecordConflict
        raise SystemExit(f"refused: {e}")
    if not created:
        print(f"record {rid} already present (identical claim)", file=sys.stderr)
    return rid


def cmd_admit(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    src = _require_file(args.path, "file")
    statement = args.statement
    errs = canonical.problems(statement, "--statement")
    if errs:
        raise SystemExit("; ".join(errs))
    with _session(repo_root, args):
        rid = _store_and_record(repo_root, [src], lambda d: records.admission(d[0], statement))
    print(rid)
    return 0


def cmd_derive(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    out = _require_file(args.path, "output file")
    tf = _require_file(args.transform_file, "transform file")
    env = _require_file(args.env_file, "environment file") if args.env_file else None

    params: Dict[str, Any] = {}
    if args.params_json:
        try:
            params = canonical.parse_strict(args.params_json)
        except canonical.CanonicalError as e:
            raise SystemExit(f"--params-json: {e}")
        if not isinstance(params, dict):
            raise SystemExit("--params-json must decode to a JSON object")

    inputs = list(args.input or [])
    if not inputs:
        raise SystemExit("a derivation needs at least one --input record (use `ledger admit` for roots)")
    for rid in inputs:
        if not records.is_digest(rid):
            raise SystemExit(f"invalid --input {rid!r}: expected a 64-hex record ID")
    if RESTRICTED.argv_for(args.runtime) is None:
        print(f"warning: runtime {args.runtime!r} is not permitted by the {RESTRICTED.name!r} "
              "replay policy; this derivation will not be replayable here", file=sys.stderr)

    files = [out, tf] + ([env] if env is not None else [])
    with _session(repo_root, args):
        for rid in inputs:
            l = records.load(repo_root, rid)
            if l.problem is not None:
                raise SystemExit("refused: input record is not valid: " + "; ".join(l.errors))

        def build(d: List[str]) -> Dict[str, Any]:
            return records.derivation(d[0], inputs, d[1], args.runtime, params, d[2] if env is not None else None)

        rid = _store_and_record(repo_root, files, build)
    print(rid)
    return 0


def print_report(report: Report, profile_name: str, as_json: bool) -> int:
    result = evaluate(report, PROFILES[profile_name])
    if as_json:
        print(json.dumps({"report": report.to_dict(), "profile": result.to_dict()}, indent=2, sort_keys=True))
    else:
        print(f"records checked: {report.records_checked}; transforms executed: {report.transforms_executed}")
        for dim in Dimension:
            oc = report.outcomes[dim]
            print(f"{dim.value:<24} {oc.status.value:<15} {oc.detail}")
            for p in oc.problems:
                for line in p.splitlines():
                    print(f"    {line}")
        if result.satisfied:
            print(f"profile {profile_name}: SATISFIED")
        else:
            unmet = ", ".join(
                f"{d.value} is {s.value} (requires {'/'.join(sorted(a.value for a in acc))})"
                for d, s, acc in result.unmet
            )
            print(f"profile {profile_name}: NOT SATISFIED: {unmet}")
    if result.satisfied:
        return 0
    return 3 if result.error else 2


def cmd_verify(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    wd = Path(args.workdir).resolve() if getattr(args, "workdir", None) else None
    report = verify(repo_root, [args.id], replay=args.replay, workdir=wd, keep=getattr(args, "keep", False))
    return print_report(report, args.profile, args.json)


def cmd_replay(args: argparse.Namespace) -> int:
    args.replay = True
    return cmd_verify(args)


def ref_path(repo_root: Path, name: str) -> Path:
    """Map a ref name to a file under ledger/refs/, rejecting anything that
    escapes that directory (absolute paths, '..', symlinks pointing outside)
    or lands in immutable ledger storage."""
    # Fix the boundary *before* following symlinks below it: resolving
    # ledger/refs itself would let a symlinked refs root (e.g. refs -> nodes)
    # move the boundary onto immutable manifests. Only ledger/ is resolved, so
    # a symlinked ledger directory keeps refs/nodes/objects as siblings.
    ledger_dir = (repo_root / "ledger").resolve()
    refs_dir = ledger_dir / "refs"
    if refs_dir.is_symlink():
        raise SystemExit(f"refusing to use refs: {refs_dir} is a symlink")
    if refs_dir.exists() and not refs_dir.is_dir():
        raise SystemExit(f"refusing to use refs: {refs_dir} is not a directory")
    if not name or "\0" in name:
        raise SystemExit(f"invalid ref name: {name!r}")
    candidate = Path(name)
    if candidate.is_absolute() or candidate.drive or ".." in candidate.parts:
        raise SystemExit(f"invalid ref name: {name!r} (must be a relative path inside ledger/refs)")
    target = (refs_dir / candidate).resolve()
    if target == refs_dir or not target.is_relative_to(refs_dir):
        raise SystemExit(f"invalid ref name: {name!r} (resolves outside ledger/refs)")
    # Converse aliasing (e.g. ledger/records -> refs): never write into storage.
    for protected in ("records", "objects", "nodes"):
        if target.is_relative_to((ledger_dir / protected).resolve()):
            raise SystemExit(f"invalid ref name: {name!r} (resolves into immutable ledger/{protected})")
    return target

def cmd_refs_set(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    refp = ref_path(repo_root, args.name)
    rid = args.id.strip()
    if not records.is_digest(rid):
        raise SystemExit(f"invalid record ID {args.id!r}: expected 64 lowercase hex chars")
    refp.parent.mkdir(parents=True, exist_ok=True)
    refp.write_text(rid + "\n", encoding="utf-8")
    return 0


def cmd_refs_get(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    refp = ref_path(repo_root, args.name)
    if not refp.is_file():
        raise SystemExit(f"missing ref: {refp}")
    print(refp.read_text(encoding="utf-8").strip())
    return 0


def _add_verify_args(p: argparse.ArgumentParser, default_profile: str) -> None:
    p.add_argument("id", help="Record ID.")
    p.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=default_profile,
        help=f"Assurance profile the result must satisfy (default: {default_profile}). See ASSURANCE.md.",
    )
    p.add_argument("--json", action="store_true", help="Print the machine-readable report.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ledger",
        description="4GARTHA ledger CLI (records: 4gartha.record/1; assurance contract 1, see ASSURANCE.md).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_hash = sub.add_parser("hash", help="Compute sha256 of a file (its artifact ID).")
    p_hash.add_argument("path")
    p_hash.set_defaults(fn=cmd_hash)

    lock_help = "Disable the repo-wide ingest-session lock (not recommended)."

    p_adm = sub.add_parser("admit", help="Store an artifact and write an admission record (append-only).")
    p_adm.add_argument("path")
    p_adm.add_argument(
        "--statement",
        required=True,
        help="Declared trust basis: where the artifact came from and why it is admitted. "
             "Recorded as an 'unattested' statement; it is a claim, not evidence.",
    )
    p_adm.add_argument("--no-session-lock", action="store_true", help=lock_help)
    p_adm.set_defaults(fn=cmd_admit)

    p_der = sub.add_parser("derive", help="Store an output artifact and write a derivation record (append-only).")
    p_der.add_argument("path", help="Output artifact file.")
    p_der.add_argument("--input", action="append", help="Input record ID (ordered; repeat for each input).")
    p_der.add_argument("--transform-file", required=True, help="Transform definition; stored in the CAS.")
    p_der.add_argument("--runtime", default="python3", help="Runtime name (not argv); see ASSURANCE.md. Default: python3.")
    p_der.add_argument("--params-json", help="JSON object of transform params (canonical: no floats, NFC strings, ASCII keys).")
    p_der.add_argument("--env-file", help="Environment description (lockfile/flake/recipe); stored in the CAS. Declared, not enforced.")
    p_der.add_argument("--no-session-lock", action="store_true", help=lock_help)
    p_der.set_defaults(fn=cmd_derive)

    p_ver = sub.add_parser("verify", help="Verify a record and its lineage; print a typed assurance report.")
    _add_verify_args(p_ver, "integrity")
    p_ver.add_argument(
        "--replay",
        action="store_true",
        help="Also replay derivations. EXECUTES TRANSFORM CODE without isolation (see ASSURANCE.md).",
    )
    p_ver.set_defaults(fn=cmd_verify)

    p_rep = sub.add_parser(
        "replay",
        help="Replay every derivation in a record's lineage (verify --replay --profile replay). Executes code.",
    )
    _add_verify_args(p_rep, "replay")
    p_rep.add_argument("--workdir", help="Directory in which fresh run directories are created and kept.")
    p_rep.add_argument("--keep", action="store_true", help="Keep auto-created temp run directories.")
    p_rep.set_defaults(fn=cmd_replay)

    p_rs = sub.add_parser("refs", help="Manage mutable convenience refs (names for record IDs).")
    rs = p_rs.add_subparsers(dest="refs_cmd", required=True)
    rs_set = rs.add_parser("set", help="Point a ref at a record ID.")
    rs_set.add_argument("name")
    rs_set.add_argument("id")
    rs_set.set_defaults(fn=cmd_refs_set)
    rs_get = rs.add_parser("get", help="Print the record ID a ref points at.")
    rs_get.add_argument("name")
    rs_get.set_defaults(fn=cmd_refs_get)

    return p


def main() -> None:
    p = build_parser()
    args = p.parse_args()
    raise SystemExit(args.fn(args))


if __name__ == "__main__":
    main()
