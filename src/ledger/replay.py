from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from .cas import CasPaths, sha256_file
from .manifest import read_node_manifest


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON encoding (stable across runs).

    NOTE: This does not attempt to normalize floats or NaNs. If you need that,
    pin a domain-specific canonicalization upstream.
    """

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class ReplayResult:
    ok: bool
    errors: List[str]
    output_digest: str | None = None
    workdir: Path | None = None


def replay_node(repo_root: Path, node_id: str, workdir: Path | None = None, keep: bool = False) -> ReplayResult:
    """Replay a node derivation.

    Contract (v0, minimal):
      - Node parents are materialized as files under <workdir>/parents/
      - A `parents.json` file is written with ordered parent metadata
      - A `params.json` file is written with canonical JSON of manifest.transform.params
      - The transform definition is loaded by digest from the CAS and executed as a script:

          <runner...> <transform_script> \
              --parents-manifest <workdir>/parents.json \
              --parents-dir <workdir>/parents \
              --params-path <workdir>/params.json \
              --out <workdir>/out.bin

      - Replay succeeds iff sha256(out.bin) == node_id.

    Security note:
      Replay executes code. Do not run this on untrusted transforms without sandboxing.
    """

    errors: List[str] = []

    m = read_node_manifest(repo_root, node_id)
    parents = m.get("parents", [])
    if not isinstance(parents, list):
        return ReplayResult(False, ["manifest.parents not a list"])

    # Root/admission nodes have no derivation to replay.
    if len(parents) == 0:
        return ReplayResult(True, [], output_digest=node_id, workdir=workdir)

    t = m.get("transform", {})
    if not isinstance(t, dict):
        return ReplayResult(False, ["manifest.transform not an object"])

    transform_digest = t.get("digest")
    if not isinstance(transform_digest, str) or len(transform_digest) != 64:
        return ReplayResult(False, ["manifest.transform.digest missing/invalid"])

    env_digest = t.get("env_digest")
    if env_digest is not None and (not isinstance(env_digest, str) or len(env_digest) != 64):
        return ReplayResult(False, ["manifest.transform.env_digest invalid (expected 64-hex)"])

    runner = t.get("runner")
    if runner is None:
        runner_argv: List[str] = ["python3"]
    elif isinstance(runner, list) and all(isinstance(x, str) for x in runner) and len(runner) >= 1:
        runner_argv = list(runner)
    elif isinstance(runner, str) and runner.strip():
        # Lenient fallback: allow a single-string runner.
        runner_argv = [runner.strip()]
    else:
        return ReplayResult(False, ["manifest.transform.runner invalid (expected array[str])"])

    params = t.get("params", {})
    if not isinstance(params, dict):
        return ReplayResult(False, ["manifest.transform.params not an object"])

    cas = CasPaths.from_repo_root(repo_root)
    transform_obj = cas.object_path(transform_digest)
    if not transform_obj.exists():
        return ReplayResult(
            False,
            [
                "missing transform definition in CAS",
                f"  expected: {transform_obj}",
                "  hint: ingest nodes with --transform-file to store transform bytes",
            ],
        )

    if env_digest is not None:
        env_obj = cas.object_path(env_digest)
        if not env_obj.exists():
            return ReplayResult(
                False,
                [
                    "missing environment description in CAS",
                    f"  expected: {env_obj}",
                    "  hint: store your lockfile/Nix flake/container recipe as a CAS blob",
                ],
            )

    # Workdir management
    tmp_ctx = None
    wd: Path
    if workdir is not None:
        wd = Path(workdir).resolve()
        wd.mkdir(parents=True, exist_ok=True)
    else:
        tmp_ctx = tempfile.TemporaryDirectory(prefix=f"ledger-replay-{node_id[:8]}-")
        wd = Path(tmp_ctx.name)

    try:
        parents_dir = wd / "parents"
        parents_dir.mkdir(parents=True, exist_ok=True)

        parents_manifest: List[Dict[str, Any]] = []
        for i, pid in enumerate(parents):
            if not isinstance(pid, str) or len(pid) != 64:
                errors.append(f"invalid parent id: {pid!r}")
                continue
            parent_obj = cas.object_path(pid)
            if not parent_obj.exists():
                errors.append(f"missing parent object: {parent_obj}")
                continue
            dst = parents_dir / f"{i:03d}_{pid}.bin"
            # Byte-for-byte materialization.
            dst.write_bytes(parent_obj.read_bytes())
            parents_manifest.append({"index": i, "id": pid, "path": dst.name})

        if errors:
            return ReplayResult(False, errors, workdir=wd)

        (wd / "parents.json").write_text(
            json.dumps(parents_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (wd / "params.json").write_text(_canonical_json(params) + "\n", encoding="utf-8")

        transform_path = wd / f"transform_{transform_digest}.py"
        transform_path.write_bytes(transform_obj.read_bytes())

        out_path = wd / "out.bin"

        cmd = [
            *runner_argv,
            str(transform_path),
            "--parents-manifest",
            str(wd / "parents.json"),
            "--parents-dir",
            str(parents_dir),
            "--params-path",
            str(wd / "params.json"),
            "--out",
            str(out_path),
        ]

        proc = subprocess.run(cmd, cwd=str(wd), text=True, capture_output=True)
        if proc.returncode != 0:
            errors.append(f"transform failed (exit={proc.returncode})")
            if proc.stdout.strip():
                errors.append("stdout:\n" + proc.stdout.rstrip("\n"))
            if proc.stderr.strip():
                errors.append("stderr:\n" + proc.stderr.rstrip("\n"))
            return ReplayResult(False, errors, workdir=wd)

        if not out_path.exists():
            return ReplayResult(False, ["transform produced no output (missing out.bin)"], workdir=wd)

        out_digest = sha256_file(out_path)
        if out_digest != node_id:
            return ReplayResult(
                False,
                [f"derivation mismatch: expected {node_id}, got {out_digest}"],
                output_digest=out_digest,
                workdir=wd,
            )

        return ReplayResult(True, [], output_digest=out_digest, workdir=wd)
    finally:
        if tmp_ctx is not None and not keep:
            tmp_ctx.cleanup()
