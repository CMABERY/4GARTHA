"""Transform execution for derivation replay, under a verifier-side policy.

WHAT THIS IS NOT: an isolation boundary. A transform runs as the verifying
user, with that user's filesystem and network access. The restrictions here
narrow what a *record* can choose; they do not contain what the *code* can do.
Accordingly the verifier reports execution_safety as FAIL whenever it runs a
transform (ASSURANCE.md, "Execution safety").

What the policy does guarantee:
  - The record names a runtime (e.g. "python3"); it can never supply argv.
    Only runtimes in the verifier's policy can run; any other name is refused
    before anything executes.
  - The child gets a minimal environment (the verifier's environment
    variables, tokens included, are not passed on), stdin from /dev/null, a
    fresh empty working directory, and a wall-clock timeout after which its
    process group is killed (POSIX; the transform is started in its own
    session). Processes it leaves behind after exiting normally are not.
  - Transform, input and environment bytes are read once, hashed, and only
    those verified bytes are materialized for execution.

Transform interface ("4gartha.transform-argv/1"):

    <runtime argv...> transform.py --parents-manifest <run>/parents.json \
        --parents-dir <run>/parents --params-path <run>/params.json \
        --out <run>/out.bin

parents.json is an ordered list of {"index", "record", "artifact", "path"};
params.json holds the canonical encoding of transform.params.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import canonical
from .cas import sha256_file

TRANSFORM_INTERFACE = "4gartha.transform-argv/1"
OUTPUT_LIMIT = 4096  # characters of stdout/stderr kept for reporting


@dataclass(frozen=True)
class ReplayPolicy:
    name: str
    runtimes: Mapping[str, Tuple[str, ...]]
    timeout_s: float = 60.0

    def argv_for(self, runtime: str) -> Optional[Tuple[str, ...]]:
        return self.runtimes.get(runtime)


def restricted_policy(timeout_s: float = 60.0) -> ReplayPolicy:
    """Default policy: only "python3", meaning the verifier's own interpreter
    in isolated mode (-I: ignores PYTHON* variables, user site-packages and
    the script's directory)."""
    return ReplayPolicy(
        name="restricted",
        runtimes=MappingProxyType({"python3": (sys.executable, "-I")}),
        timeout_s=timeout_s,
    )


RESTRICTED = restricted_policy()


@dataclass(frozen=True)
class Execution:
    """status: "completed" (exit 0 with out.bin), "failed" (non-zero exit or no
    output) or "error" (could not conclude: run directory or inputs could not
    be prepared, the runtime could not be started, or a timeout).

    ``started`` is True only once the transform process was actually created;
    whether code ran is decided by this flag, never by whether a replay was
    attempted."""

    status: str
    output_digest: Optional[str] = None
    errors: Tuple[str, ...] = ()
    workdir: Optional[Path] = None
    started: bool = False


def minimal_env(run_dir: Path) -> Dict[str, str]:
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "HOME": str(run_dir),
        "TMPDIR": str(run_dir),
    }
    if os.name == "nt":  # the interpreter cannot start without these
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env["TEMP"] = env["TMP"] = str(run_dir)
    return env


def _trim(text: str) -> str:
    text = text.rstrip("\n")
    return text if len(text) <= OUTPUT_LIMIT else text[:OUTPUT_LIMIT] + "\n[... truncated]"


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run_transform(
    argv_prefix: Sequence[str],
    transform_bytes: bytes,
    inputs: Sequence[Tuple[str, str, bytes]],
    params: Dict[str, Any],
    *,
    timeout_s: float,
    label: str,
    workdir: Optional[Path] = None,
    keep: bool = False,
) -> Execution:
    """Execute one transform over verified bytes in a fresh run directory.

    ``inputs`` is an ordered list of (record ID, artifact ID, bytes). With
    ``workdir`` a fresh run directory is created inside it and kept;
    otherwise a new temp directory is used and removed unless ``keep``.
    Only output written by this execution can be observed: the run directory
    is new and empty before the transform starts.
    """
    cleanup = False
    wd: Optional[Path] = None
    try:
        if workdir is not None:
            base = Path(workdir).resolve()
            base.mkdir(parents=True, exist_ok=True)
            wd = Path(tempfile.mkdtemp(prefix=f"replay-{label[:8]}-", dir=base))
        else:
            wd = Path(tempfile.mkdtemp(prefix=f"ledger-replay-{label[:8]}-"))
            cleanup = not keep
    except OSError as e:
        return Execution("error", errors=(f"could not create a run directory: {e}",))

    try:
        try:
            parents_dir = wd / "parents"
            parents_dir.mkdir()
            manifest: List[Dict[str, Any]] = []
            for i, (rid, aid, data) in enumerate(inputs):
                name = f"{i:03d}_{aid}.bin"
                (parents_dir / name).write_bytes(data)
                manifest.append({"index": i, "record": rid, "artifact": aid, "path": name})
            (wd / "parents.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            (wd / "params.json").write_bytes(canonical.encode(params) + b"\n")
            transform_path = wd / "transform.py"
            transform_path.write_bytes(transform_bytes)
        except OSError as e:
            return Execution("error", errors=(f"could not materialize replay inputs in {wd}: {e}",), workdir=wd)
        out_path = wd / "out.bin"

        cmd = [
            *argv_prefix,
            str(transform_path),
            "--parents-manifest", str(wd / "parents.json"),
            "--parents-dir", str(parents_dir),
            "--params-path", str(wd / "params.json"),
            "--out", str(out_path),
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(wd),
                env=minimal_env(wd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                start_new_session=(os.name == "posix"),
            )
        except OSError as e:
            # Nothing ran: started stays False.
            return Execution("error", errors=(f"could not start runtime {argv_prefix[0]!r}: {e}",), workdir=wd)
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.communicate()
            return Execution("error", errors=(f"transform timed out after {timeout_s:g}s (process group killed)",),
                             workdir=wd, started=True)
        # No post-exit sweep: once the leader is reaped its PID (and so the
        # group ID) may be reused, and killpg could hit an unrelated group.
        # Processes a transform leaves running after a normal exit are
        # therefore not killed; one more reason this is not a boundary.

        if proc.returncode != 0:
            errs = [f"transform exited with status {proc.returncode}"]
            if stdout.strip():
                errs.append("stdout:\n" + _trim(stdout))
            if stderr.strip():
                errs.append("stderr:\n" + _trim(stderr))
            return Execution("failed", errors=tuple(errs), workdir=wd, started=True)
        if not out_path.is_file() or out_path.is_symlink():
            return Execution("failed", errors=("transform produced no output (missing out.bin)",), workdir=wd, started=True)
        try:
            digest = sha256_file(out_path)
        except OSError as e:
            return Execution("error", errors=(f"could not read out.bin: {e}",), workdir=wd, started=True)
        return Execution("completed", output_digest=digest, workdir=wd, started=True)
    finally:
        if cleanup:
            shutil.rmtree(wd, ignore_errors=True)
