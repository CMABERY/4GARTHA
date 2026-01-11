from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict
from .locks import ingest_session_lock, ingest_session_lock_enabled


from .cas import CasPaths, sha256_file, sha256_bytes, store_blob
from .manifest import Node, Transform, write_node_manifest
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
    if not src.exists():
        raise SystemExit(f"no such file: {src}")

    artifact_id = sha256_file(src)
    cas = CasPaths.from_repo_root(repo_root)
    store_blob(src, cas, artifact_id)

    # Transform digest: by default hash the provided transform string (stable identifier),
    # OR if a file path is provided via --transform-file, hash that file's bytes.
    if args.transform_file:
        tf = Path(args.transform_file)
        if not tf.exists():
            raise SystemExit(f"no such transform file: {tf}")
        transform_digest = sha256_file(tf)
        # Store transform definition in the CAS so it can be replayed by digest.
        store_blob(tf, cas, transform_digest)
        transform_name = args.transform or tf.name
    else:
        transform_name = args.transform or "unspecified"
        transform_digest = sha256_bytes(transform_name.encode("utf-8"))

    params: Dict[str, Any] = {}
    if args.params_json:
        params = json.loads(args.params_json)
        if not isinstance(params, dict):
            raise SystemExit("--params-json must decode to a JSON object")

    node = Node(
        id=artifact_id,
        parents=args.parent or [],
        transform=Transform(
            name=transform_name,
            digest=transform_digest,
            params=params,
            runner=args.runner,
            env_digest=args.env_digest,
        ),
        meta={"note": args.note} if args.note else None,
    )
    write_node_manifest(repo_root, node)

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
    if r.ok:
        print("OK")
        return 0
    for e in r.errors:
        print(e)
    return 2

def cmd_refs_set(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    refp = repo_root / "ledger" / "refs" / args.name
    refp.parent.mkdir(parents=True, exist_ok=True)
    refp.write_text(args.id.strip() + "\n", encoding="utf-8")
    return 0

def cmd_refs_get(args: argparse.Namespace) -> int:
    repo_root = repo_root_from_cwd()
    refp = repo_root / "ledger" / "refs" / args.name
    if not refp.exists():
        raise SystemExit(f"missing ref: {refp}")
    print(refp.read_text(encoding="utf-8").strip())
    return 0
def _do_ingest() -> str:
        # existing ingest logic that ends with:
        # write_node_manifest(repo_root, node)
        # return artifact_id
    return artifact_id

    if ingest_session_lock_enabled(cli_no_session_lock=bool(getattr(args, "no_session_lock", False))):
        with ingest_session_lock(repo_root):
            artifact_id = _do_ingest()
    else:
        artifact_id = _do_ingest()

    print(artifact_id)
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
        help="Optional directory to materialize inputs/output (useful for debugging).",
    )
    p_rep.add_argument(
        "--keep",
        action="store_true",
        help="Keep the workdir (when using an auto-temp dir) after replay.",
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
