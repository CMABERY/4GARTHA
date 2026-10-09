from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .cas import CasPaths, sha256_bytes, sha256_file
from .manifest import load_node_manifest


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


def _read_verified_blob(cas: CasPaths, digest: str, what: str) -> Tuple[bytes | None, List[str]]:
    """Read a CAS blob and check that its bytes hash to the digest naming it."""
    path = cas.object_path(digest)
    if not path.is_file():
        return None, [f"missing {what} in CAS", f"  expected: {path}"]
    data = path.read_bytes()
    actual = sha256_bytes(data)
    if actual != digest:
        return None, [f"{what} hash mismatch: expected {digest}, got {actual}", f"  path: {path}"]
    return data, []


def replay_node(repo_root: Path, node_id: str, workdir: Path | None = None, keep: bool = False) -> ReplayResult:
    """Replay a node derivation.

    Contract (v0, minimal):
      - The manifest must be valid (node schema, id bound to node_id).
      - Every CAS input (transform definition, optional environment description,
        parent artifacts) is read once and must hash to its declared digest
        before anything is executed.
      - Each replay runs in a fresh, empty run directory. With ``workdir`` it is
        created inside that directory (and always kept); otherwise it is a new
        temp directory, removed afterwards unless ``keep`` is true.
      - Node parents are materialized as files under <run>/parents/
      - A `parents.json` file is written with ordered parent metadata
      - A `params.json` file is written with canonical JSON of manifest.transform.params
      - The transform definition is executed as a script:

          <runner...> <transform_script> \
              --parents-manifest <run>/parents.json \
              --parents-dir <run>/parents \
              --params-path <run>/params.json \
              --out <run>/out.bin

      - Replay succeeds iff sha256(out.bin) == node_id.

    Security note:
      Replay executes code. Do not run this on untrusted transforms without sandboxing.
    """

    m, manifest_errors = load_node_manifest(repo_root, node_id)
    if m is None:
        return ReplayResult(False, [f"invalid manifest: {e}" for e in manifest_errors])

    parents: List[str] = m["parents"]

    # Root/admission nodes have no derivation to replay.
    if len(parents) == 0:
        return ReplayResult(True, [], output_digest=node_id, workdir=workdir)

    # Shape (64-hex digests, runner as array[str], params object) is guaranteed
    # by the schema check above.
    t: Dict[str, Any] = m["transform"]
    transform_digest: str = t["digest"]
    env_digest: str | None = t.get("env_digest")
    runner = t.get("runner")
    runner_argv: List[str] = list(runner) if runner is not None else ["python3"]
    params: Dict[str, Any] = t["params"]

    # Verify the integrity of every CAS input *before* creating a workdir or
    # executing anything.
    cas = CasPaths.from_repo_root(repo_root)
    transform_bytes, errs = _read_verified_blob(cas, transform_digest, "transform definition")
    if transform_bytes is None:
        if errs[0].startswith("missing"):
            errs.append("  hint: ingest nodes with --transform-file to store transform bytes")
        return ReplayResult(False, errs)

    if env_digest is not None:
        _, errs = _read_verified_blob(cas, env_digest, "environment description")
        if errs:
            if errs[0].startswith("missing"):
                errs.append("  hint: store your lockfile/Nix flake/container recipe as a CAS blob")
            return ReplayResult(False, errs)

    errors: List[str] = []
    parent_bytes: List[bytes] = []
    for pid in parents:
        data, errs = _read_verified_blob(cas, pid, f"parent object {pid}")
        errors.extend(errs)
        if data is not None:
            parent_bytes.append(data)
    if errors:
        return ReplayResult(False, errors)

    # Workdir management: always a fresh, empty run directory so the output
    # checked below can only have been produced by this execution.
    cleanup = False
    if workdir is not None:
        base = Path(workdir).resolve()
        base.mkdir(parents=True, exist_ok=True)
        wd = Path(tempfile.mkdtemp(prefix=f"replay-{node_id[:8]}-", dir=base))
    else:
        # mkdtemp (not TemporaryDirectory): no finalizer can delete a kept dir.
        wd = Path(tempfile.mkdtemp(prefix=f"ledger-replay-{node_id[:8]}-"))
        cleanup = not keep

    try:
        parents_dir = wd / "parents"
        parents_dir.mkdir()

        parents_manifest: List[Dict[str, Any]] = []
        for i, (pid, data) in enumerate(zip(parents, parent_bytes)):
            dst = parents_dir / f"{i:03d}_{pid}.bin"
            # Byte-for-byte materialization of verified bytes.
            dst.write_bytes(data)
            parents_manifest.append({"index": i, "id": pid, "path": dst.name})

        (wd / "parents.json").write_text(
            json.dumps(parents_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (wd / "params.json").write_text(_canonical_json(params) + "\n", encoding="utf-8")

        transform_path = wd / f"transform_{transform_digest}.py"
        transform_path.write_bytes(transform_bytes)

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

        if not out_path.is_file():
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
        if cleanup:
            shutil.rmtree(wd, ignore_errors=True)
