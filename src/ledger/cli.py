from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Dict

from .cas import CasPaths, sha256_file, sha256_bytes, store_blob, verify_existing_object
from .locks import ingest_session_lock, ingest_session_lock_enabled
from .manifest import (
    Node,
    Transform,
    is_node_id,
    node_manifest_path,
    validate_manifest,
    write_node_manifest,
)
from .replay import replay_node
from .verify import verify_node, verify_reachable

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

def cmd_ingest(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    src = Path(args.path)
    if not src.is_file():
        raise SystemExit(f"no such file: {src}")

    # Validate all inputs before touching the ledger, so a rejected ingest
    # leaves no orphaned objects behind.
    parents = list(args.parent or [])
    for pid in parents:
        if not is_node_id(pid):
            raise SystemExit(f"invalid --parent {pid!r}: expected 64 lowercase hex chars")

    if args.env_digest is not None and not is_node_id(args.env_digest):
        raise SystemExit(f"invalid --env-digest {args.env_digest!r}: expected 64 lowercase hex chars")

    tf: Path | None = None
    if args.transform_file:
        tf = Path(args.transform_file)
        if not tf.is_file():
            raise SystemExit(f"no such transform file: {tf}")

    params: Dict[str, Any] = {}
    if args.params_json:
        try:
            params = json.loads(args.params_json)
        except ValueError as e:
            raise SystemExit(f"--params-json is not valid JSON: {e}")
        if not isinstance(params, dict):
            raise SystemExit("--params-json must decode to a JSON object")

    lock_enabled = ingest_session_lock_enabled(cli_no_session_lock=bool(args.no_session_lock))
    # The whole ingest transaction (hash, CAS writes, manifest existence check
    # and create) runs under the repo-wide session lock.
    with ingest_session_lock(repo_root) if lock_enabled else nullcontext():
        artifact_id = sha256_file(src)
        if artifact_id in parents:
            raise SystemExit(f"refusing to ingest {artifact_id}: a node cannot be its own parent")

        cas = CasPaths.from_repo_root(repo_root)
        try:
            # Transform digest: by default hash the provided transform string (stable identifier),
            # OR if a file path is provided via --transform-file, hash that file's bytes.
            if tf is not None:
                transform_digest = sha256_file(tf)
                transform_name = args.transform or tf.name
            else:
                transform_name = args.transform or "unspecified"
                transform_digest = sha256_bytes(transform_name.encode("utf-8"))

            node = Node(
                id=artifact_id,
                parents=parents,
                transform=Transform(
                    name=transform_name,
                    digest=transform_digest,
                    params=params,
                    runner=args.runner,
                    env_digest=args.env_digest,
                ),
                meta={"note": args.note} if args.note else None,
            )
            problems = validate_manifest(node.to_dict(), artifact_id)
            if problems:
                raise ValueError("invalid node manifest: " + "; ".join(problems))
            if node_manifest_path(repo_root, artifact_id).exists():
                raise FileExistsError(f"Node manifest already exists: {node_manifest_path(repo_root, artifact_id)}")

            # Check any objects already stored under these digests before
            # writing anything, so a corrupt CAS entry is rejected without
            # leaving new objects or a manifest behind.
            verify_existing_object(cas, artifact_id)
            if tf is not None:
                verify_existing_object(cas, transform_digest)

            store_blob(src, cas, artifact_id)
            if tf is not None:
                # Store transform definition in the CAS so it can be replayed by digest.
                store_blob(tf, cas, transform_digest)
            write_node_manifest(repo_root, node)
        except (FileExistsError, ValueError) as e:
            raise SystemExit(f"ingest failed: {e}")

    print(artifact_id)
    return 0

def cmd_verify(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    r = verify_node(repo_root, args.id, replay=args.replay)
    if r.ok:
        print("OK")
        return 0
    for e in r.errors:
        print(e)
    return 2

def cmd_verify_reachable(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    r = verify_reachable(repo_root, args.id, replay=args.replay)
    if r.ok:
        print("OK")
        return 0
    for e in r.errors:
        print(e)
    return 2


def cmd_replay(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    wd = Path(args.workdir).resolve() if args.workdir else None
    r = replay_node(repo_root, args.id, workdir=wd, keep=args.keep)
    if r.workdir is not None and (args.keep or wd is not None):
        print(f"workdir: {r.workdir}", file=sys.stderr)
    if r.ok:
        print("OK")
        return 0
    for e in r.errors:
        print(e)
    return 2

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
    # Converse aliasing (e.g. ledger/nodes -> refs): never write into storage.
    for protected in ("nodes", "objects"):
        if target.is_relative_to((ledger_dir / protected).resolve()):
            raise SystemExit(f"invalid ref name: {name!r} (resolves into immutable ledger/{protected})")
    return target

def cmd_refs_set(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    refp = ref_path(repo_root, args.name)
    refp.parent.mkdir(parents=True, exist_ok=True)
    refp.write_text(args.id.strip() + "\n", encoding="utf-8")
    return 0

def cmd_refs_get(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    refp = ref_path(repo_root, args.name)
    if not refp.is_file():
        raise SystemExit(f"missing ref: {refp}")
    print(refp.read_text(encoding="utf-8").strip())
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ledger", description="Epistemic Ledger CLI (minimal kernel).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_hash = sub.add_parser("hash", help="Compute sha256 of a file.")
    p_hash.add_argument("path")
    p_hash.set_defaults(fn=cmd_hash)

    p_ing = sub.add_parser("ingest", help="Store artifact + write immutable node manifest (append-only).")
    p_ing.add_argument("path")
    p_ing.add_argument("--parent", action="append", help="Parent node id (sha256). May be repeated.")
    p_ing.add_argument("--transform", help="Transform name/identifier (hashed if no transform file).")
    p_ing.add_argument("--transform-file", help="Path to transform definition file; digest = sha256(file).")
    p_ing.add_argument(
        "--runner",
        action="append",
        help="Replay runner command prefix (repeatable), e.g. --runner python3 --runner -I.",
    )
    p_ing.add_argument(
        "--no-session-lock",
        action="store_true",
        help="Disable repo-wide ingest-session lock (not recommended).",
    )

    p_ing.add_argument(
        "--env-digest",
        help="sha256 of the execution environment description (lockfile/nix flake/container recipe).",
    )
    p_ing.add_argument("--params-json", help="JSON object of semantic params (canonical).")
    p_ing.add_argument("--note", help="Non-semantic note.")
    p_ing.set_defaults(fn=cmd_ingest)

    p_ver = sub.add_parser(
        "verify", help="Verify node (object hash + parent reachability; optional replay)."
    )
    p_ver.add_argument("id")
    p_ver.add_argument(
        "--replay",
        action="store_true",
        help="Also replay derivation (requires transform digest artifact in CAS).",
    )
    p_ver.set_defaults(fn=cmd_verify)

    p_vr = sub.add_parser(
        "verify-reachable",
        help="Verify a node and all reachable ancestors (optional replay).",
    )
    p_vr.add_argument("id")
    p_vr.add_argument(
        "--replay",
        action="store_true",
        help="Also replay derivations for reachable nodes.",
    )
    p_vr.set_defaults(fn=cmd_verify_reachable)

    p_rep = sub.add_parser("replay", help="Replay a node derivation and verify output hash.")
    p_rep.add_argument("id")
    p_rep.add_argument(
        "--workdir",
        help="Directory in which a fresh run directory is created and kept (useful for debugging).",
    )
    p_rep.add_argument(
        "--keep",
        action="store_true",
        help="Keep the auto-created temp run directory after replay.",
    )
    p_rep.set_defaults(fn=cmd_replay)

    p_rs = sub.add_parser("refs", help="Manage mutable convenience refs.")
    rs = p_rs.add_subparsers(dest="refs_cmd", required=True)

    rs_set = rs.add_parser("set", help="Set ref to a node id.")
    rs_set.add_argument("name")
    rs_set.add_argument("id")
    rs_set.set_defaults(fn=cmd_refs_set)

    rs_get = rs.add_parser("get", help="Get node id from ref.")
    rs_get.add_argument("name")
    rs_get.set_defaults(fn=cmd_refs_get)

    return p

def main() -> None:
    p = build_parser()
    args = p.parse_args()
    raise SystemExit(args.fn(args))

if __name__ == "__main__":
    main()
