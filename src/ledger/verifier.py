"""Record verification producing typed assurance reports (ASSURANCE.md).

verify(repo, [record IDs]) checks the targets and their entire lineage (every
record reachable through derivation inputs) and returns a Report with an
Outcome for all seven dimensions. Rules shared by every dimension:

  - FAIL only when the verifier positively established the property does not
    hold (including: required evidence is absent or contradicts its digest).
  - NOT_CHECKED when no procedure ran: not requested, refused by policy, or
    not implemented in this contract version. Never silently upgraded.
  - ERROR when a procedure started but could not conclude (I/O, timeout).
  - Nothing is executed unless artifact and provenance integrity of the whole
    lineage PASS, the caller requested replay, and the replay policy permits
    every runtime involved.
  - Governance is evaluated only against an anchor trust policy the caller
    supplies (anchor.py). Without one it is NOT_CHECKED; a policy stored in the
    repository is never loaded implicitly.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import anchor, records
from .assurance import Dimension, Outcome, Report, Status
from .cas import CasPaths, sha256_bytes
from .execution import RESTRICTED, ReplayPolicy, run_transform

MAX_LINEAGE_RECORDS = 100_000

NO_ISOLATION = (
    "no enforced isolation boundary: transforms ran as the verifying user with the "
    "verifier's filesystem and network access (runtime allowlist, minimal environment "
    "and timeout narrow what a record can choose, not what its code can do)"
)
REPRO_NOT_IMPLEMENTED = (
    "environment enforcement is not implemented for 4gartha.record/1; a matching replay "
    "shows the output was reproduced on this host, not that the declared environment was used"
)
GOVERNANCE_NO_POLICY = (
    "no anchor trust policy supplied (--anchor-policy), so no external anchoring evidence was "
    "evaluated; a policy in the repository is never used, and repository history and CI checks "
    "are controlled by the repository's writers and cannot establish independently protected history"
)


@dataclass
class _Lineage:
    order: List[str] = field(default_factory=list)  # inputs before dependents
    loaded: Dict[str, records.Loaded] = field(default_factory=dict)
    truncated: bool = False
    # Back edges between ID-valid records. Unreachable unless SHA-256 preimage
    # resistance fails (a record's ID hashes the IDs of its inputs), but the
    # verifier checks rather than assumes.
    cycles: List[List[str]] = field(default_factory=list)

    @property
    def valid(self) -> Dict[str, dict]:
        return {rid: l.record for rid, l in self.loaded.items() if l.record is not None}

    @property
    def complete(self) -> bool:
        return (not self.truncated and not self.cycles
                and all(l.record is not None for l in self.loaded.values()))


def _walk(repo_root: Path, targets: Iterable[str]) -> _Lineage:
    lin = _Lineage()
    done: set = set()
    for target in targets:
        if target in done:
            continue
        stack: List[Tuple[str, Iterable[str]]] = []
        seen_here = {target}

        def enter(rid: str) -> Iterable[str]:
            if len(lin.loaded) >= MAX_LINEAGE_RECORDS:
                lin.truncated = True
                return iter(())
            l = records.load(repo_root, rid)
            lin.loaded[rid] = l
            return iter(records.input_ids(l.record) if l.record is not None else [])

        stack.append((target, enter(target)))
        while stack:
            rid, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                if rid not in done:
                    done.add(rid)
                    lin.order.append(rid)
                continue
            if nxt in done:
                continue  # shared ancestor, already checked
            if nxt in seen_here:  # seen but not done: it is on the stack
                path = [r for r, _ in stack]
                lin.cycles.append(path[path.index(nxt):] + [nxt])
                continue
            seen_here.add(nxt)
            stack.append((nxt, enter(nxt)))
    return lin


def _check_artifact(cas: CasPaths, digest: str) -> Tuple[Optional[str], Optional[bytes]]:
    """(problem kind or None, verified bytes). Kinds: "missing", "invalid", "io"."""
    path = cas.object_path(digest)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "io", None
    if not stat.S_ISREG(st.st_mode):
        return "invalid", None
    try:
        data = path.read_bytes()
    except OSError:
        return "io", None
    if sha256_bytes(data) != digest:
        return "invalid", None
    return None, data


def _aggregate(fail: List[str], error: List[str], incomplete: bool, ok_detail: str, incomplete_detail: str) -> Outcome:
    if fail:
        return Outcome(Status.FAIL, f"{len(fail)} problem(s)", tuple(fail + error))
    if error:
        return Outcome(Status.ERROR, f"{len(error)} check(s) could not complete", tuple(error))
    if incomplete:
        return Outcome(Status.NOT_CHECKED, incomplete_detail)
    return Outcome(Status.PASS, ok_detail)


def verify(
    repo_root: Path,
    targets: Iterable[str],
    *,
    replay: bool = False,
    policy: ReplayPolicy = RESTRICTED,
    workdir: Optional[Path] = None,
    keep: bool = False,
    anchor_policy: Optional[anchor.AnchorPolicy] = None,
) -> Report:
    targets = tuple(targets)
    cas = CasPaths.from_repo_root(repo_root)
    lin = _walk(repo_root, targets)
    valid = lin.valid
    o: Dict[Dimension, Outcome] = {}

    # --- provenance integrity ---------------------------------------------
    p_fail = [e for l in lin.loaded.values() if l.problem in ("missing", "invalid") for e in l.errors]
    p_err = [e for l in lin.loaded.values() if l.problem == "io" for e in l.errors]
    if lin.truncated:
        p_err.append(f"lineage exceeds {MAX_LINEAGE_RECORDS} records; verification stopped")
    for cyc in lin.cycles:
        p_fail.append(
            "cycle among ID-valid records (implies a SHA-256 preimage; treat the ledger as "
            "compromised): " + " -> ".join(cyc)
        )
    o[Dimension.PROVENANCE_INTEGRITY] = _aggregate(
        p_fail, p_err, False,
        f"{len(valid)} record(s) canonical, schema-valid and bound to their IDs; every input record present",
        "",
    )

    # --- artifact integrity -----------------------------------------------
    a_fail: List[str] = []
    a_err: List[str] = []
    verified: Dict[str, bytes] = {}
    checked = 0
    for rid in lin.order:
        rec = valid.get(rid)
        if rec is None:
            continue
        for role, digest in records.referenced_artifacts(rec):
            if digest in verified:
                continue
            checked += 1
            problem, data = _check_artifact(cas, digest)
            if problem is None:
                verified[digest] = data  # type: ignore[assignment]
            elif problem == "missing":
                a_fail.append(f"record {rid}: {role} artifact {digest} missing from {cas.object_path(digest)}")
            elif problem == "invalid":
                a_fail.append(f"record {rid}: {role} artifact {digest} does not match its digest (or is not a regular file)")
            else:
                a_err.append(f"record {rid}: {role} artifact {digest} could not be read")
    o[Dimension.ARTIFACT_INTEGRITY] = _aggregate(
        a_fail, a_err, not lin.complete,
        f"{checked} artifact(s) present and matching their digests",
        f"{checked} artifact(s) checked, but the lineage is incomplete, so not every referenced artifact is known",
    )

    derivations = [rid for rid in lin.order if valid.get(rid, {}).get("kind") == "derivation"]
    admissions = [rid for rid in lin.order if valid.get(rid, {}).get("kind") == "admission"]

    # --- derivation verification (+ what it executed) ---------------------
    attempts = 0  # replays attempted
    executed = 0  # transform processes actually started
    if not lin.complete and not derivations:
        dv = Outcome(Status.NOT_CHECKED, "lineage could not be established")
    elif lin.cycles:
        dv = Outcome(Status.NOT_CHECKED, "lineage contains a cycle; no transform was executed")
    elif not derivations:
        dv = Outcome(Status.NOT_APPLICABLE, "lineage contains only admission records; there is no derivation to verify")
    elif not replay:
        dv = Outcome(Status.NOT_CHECKED, f"replay not requested ({len(derivations)} derivation(s) in lineage)")
    elif (o[Dimension.ARTIFACT_INTEGRITY].status is not Status.PASS
          or o[Dimension.PROVENANCE_INTEGRITY].status is not Status.PASS):
        dv = Outcome(Status.NOT_CHECKED, "integrity checks did not pass; no transform was executed")
    else:
        refused = sorted({valid[r]["transform"]["runtime"] for r in derivations
                          if policy.argv_for(valid[r]["transform"]["runtime"]) is None})
        if refused:
            dv = Outcome(
                Status.NOT_CHECKED,
                f"runtime(s) {', '.join(map(repr, refused))} not permitted by replay policy "
                f"{policy.name!r}; no transform was executed",
            )
        else:
            dv = None
            for rid in derivations:
                rec = valid[rid]
                t = rec["transform"]
                inputs = []
                for in_rid in records.input_ids(rec):
                    aid = valid[in_rid]["output"]["artifact"]
                    inputs.append((in_rid, aid, verified[aid]))
                attempts += 1
                ex = run_transform(
                    policy.argv_for(t["runtime"]),  # type: ignore[arg-type]
                    verified[t["artifact"]],
                    inputs,
                    t["params"],
                    timeout_s=policy.timeout_s,
                    label=rid,
                    workdir=workdir,
                    keep=keep,
                )
                if ex.started:
                    executed += 1
                where = (f" (run directory: {ex.workdir})" if ex.workdir is not None and (keep or workdir is not None) else "")
                if ex.status == "error":
                    dv = Outcome(Status.ERROR, f"replay of {rid} could not conclude{where}", ex.errors)
                    break
                if ex.status == "failed":
                    dv = Outcome(Status.FAIL, f"replay of {rid} failed{where}", ex.errors)
                    break
                expected = rec["output"]["artifact"]
                if ex.output_digest != expected:
                    dv = Outcome(
                        Status.FAIL,
                        f"replay of {rid} produced different bytes{where}",
                        (f"derivation mismatch: expected {expected}, got {ex.output_digest}",),
                    )
                    break
            if dv is None:
                dv = Outcome(Status.PASS, f"{len(derivations)} derivation(s) replayed; every output matched its declared artifact")
    o[Dimension.DERIVATION_VERIFICATION] = dv

    # --- execution safety -------------------------------------------------
    if executed:
        o[Dimension.EXECUTION_SAFETY] = Outcome(Status.FAIL, f"{executed} transform(s) executed with {NO_ISOLATION}")
    elif attempts:
        o[Dimension.EXECUTION_SAFETY] = Outcome(
            Status.NOT_CHECKED,
            f"{attempts} replay attempt(s), but no transform process started, and no isolation boundary was checked",
        )
    else:
        o[Dimension.EXECUTION_SAFETY] = Outcome(
            Status.NOT_CHECKED,
            "no transform was executed in this run, and no isolation boundary was checked "
            "(execution safety is a property of a verification run, not a record claim)",
        )

    # --- reproducibility --------------------------------------------------
    if lin.complete and not derivations:
        o[Dimension.REPRODUCIBILITY] = Outcome(Status.NOT_APPLICABLE, "lineage contains no derivation")
    else:
        with_env = sum(1 for r in derivations if valid[r]["environment"] is not None)
        o[Dimension.REPRODUCIBILITY] = Outcome(
            Status.NOT_CHECKED,
            f"{REPRO_NOT_IMPLEMENTED} ({with_env} of {len(derivations)} derivation(s) declare an environment artifact)",
        )

    # --- authenticity -----------------------------------------------------
    if not lin.complete:
        o[Dimension.AUTHENTICITY] = Outcome(Status.NOT_CHECKED, "lineage could not be established")
    else:
        o[Dimension.AUTHENTICITY] = Outcome(
            Status.NOT_CHECKED,
            f"{len(admissions)} admission(s), all with basis 'unattested' (a statement, not evidence); "
            "4gartha.record/1 defines no attested basis and records carry no signer, "
            "so there is no authenticity procedure to run",
        )

    # --- governance -------------------------------------------------------
    if anchor_policy is None:
        o[Dimension.GOVERNANCE] = Outcome(Status.NOT_CHECKED, GOVERNANCE_NO_POLICY)
    elif (o[Dimension.ARTIFACT_INTEGRITY].status is not Status.PASS
          or o[Dimension.PROVENANCE_INTEGRITY].status is not Status.PASS):
        o[Dimension.GOVERNANCE] = Outcome(
            Status.NOT_CHECKED, "integrity checks did not pass; anchoring evidence was not evaluated")
    else:
        o[Dimension.GOVERNANCE] = anchor.governance_outcome(repo_root, list(lin.loaded), anchor_policy)

    return Report(targets=targets, outcomes=o, records_checked=len(lin.loaded),
                  transforms_executed=executed, replay_attempts=attempts)


def verify_one(repo_root: Path, rid: str, **kw) -> Report:
    return verify(repo_root, [rid], **kw)
