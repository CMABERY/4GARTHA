"""Typed assurance results (ASSURANCE.md, contract version 1).

A verification run produces a Report with an Outcome for *every* dimension;
nothing is omitted, so an unperformed check can only ever read as
NOT_CHECKED, never as silence or success. Whether a report is acceptable is a
separate question, answered by evaluating it against a named Profile.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, List, Mapping, Tuple

CONTRACT = "4gartha.assurance/1"


class Status(str, Enum):
    PASS = "PASS"                       # procedure ran; evidence supports the claim
    FAIL = "FAIL"                       # procedure established the claim does not hold
                                        #   (including: required evidence absent or invalid)
    NOT_CHECKED = "NOT_CHECKED"         # no procedure ran: not requested, refused by
                                        #   policy, or not implemented in this version
    NOT_APPLICABLE = "NOT_APPLICABLE"   # the record makes no such claim
    ERROR = "ERROR"                     # procedure started but could not conclude

    def __str__(self) -> str:
        return self.value


class Dimension(str, Enum):
    ARTIFACT_INTEGRITY = "artifact_integrity"
    PROVENANCE_INTEGRITY = "provenance_integrity"
    DERIVATION_VERIFICATION = "derivation_verification"
    EXECUTION_SAFETY = "execution_safety"
    REPRODUCIBILITY = "reproducibility"
    AUTHENTICITY = "authenticity"
    GOVERNANCE = "governance"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Outcome:
    status: Status
    detail: str
    problems: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status.value, "detail": self.detail, "problems": list(self.problems)}


@dataclass(frozen=True)
class Report:
    targets: Tuple[str, ...]
    outcomes: Mapping[Dimension, Outcome]
    records_checked: int = 0
    # A replay attempt that never started a process (unstartable runtime, run
    # directory or inputs could not be prepared) is counted in replay_attempts
    # only: transforms_executed counts processes that were actually started.
    transforms_executed: int = 0
    replay_attempts: int = 0

    def __post_init__(self) -> None:
        missing = [d.value for d in Dimension if d not in self.outcomes]
        if missing:
            raise ValueError(f"report omits dimension(s): {', '.join(missing)}")
        object.__setattr__(self, "outcomes", MappingProxyType(dict(self.outcomes)))

    def status(self, dim: Dimension) -> Status:
        return self.outcomes[dim].status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract": CONTRACT,
            "targets": list(self.targets),
            "records_checked": self.records_checked,
            "replay_attempts": self.replay_attempts,
            "transforms_executed": self.transforms_executed,
            "outcomes": {d.value: self.outcomes[d].to_dict() for d in Dimension},
        }


@dataclass(frozen=True)
class Profile:
    """Required dimensions and the statuses each accepts. Unlisted dimensions
    are reported but not required."""

    name: str
    description: str
    requires: Mapping[Dimension, FrozenSet[Status]]


@dataclass(frozen=True)
class ProfileResult:
    """Acceptance of a report under a profile. ``unrequired_failures`` lists
    dimensions the profile does not require that are FAIL anyway: a satisfied
    profile never hides a failed assurance (for example a matching replay that
    ran without isolation)."""

    profile: str
    satisfied: bool
    error: bool  # a required dimension is ERROR (inconclusive, not refuted)
    unmet: Tuple[Tuple[Dimension, Status, FrozenSet[Status]], ...] = field(default=())
    unrequired_failures: Tuple[Dimension, ...] = field(default=())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "satisfied": self.satisfied,
            "error": self.error,
            "unmet": [
                {"dimension": d.value, "status": s.value, "accepted": sorted(a.value for a in acc)}
                for d, s, acc in self.unmet
            ],
            "unrequired_failures": [d.value for d in self.unrequired_failures],
        }


def evaluate(report: Report, profile: Profile) -> ProfileResult:
    unmet: List[Tuple[Dimension, Status, FrozenSet[Status]]] = []
    for dim in Dimension:  # stable order
        accepted = profile.requires.get(dim)
        if accepted is None:
            continue
        st = report.status(dim)
        if st not in accepted:
            unmet.append((dim, st, accepted))
    return ProfileResult(
        profile=profile.name,
        satisfied=not unmet,
        error=any(st is Status.ERROR for _, st, _ in unmet),
        unmet=tuple(unmet),
        unrequired_failures=tuple(
            d for d in Dimension if d not in profile.requires and report.status(d) is Status.FAIL
        ),
    )


_P = frozenset([Status.PASS])
_P_NA = frozenset([Status.PASS, Status.NOT_APPLICABLE])
_INTEGRITY = {Dimension.ARTIFACT_INTEGRITY: _P, Dimension.PROVENANCE_INTEGRITY: _P}


def _profile(name: str, description: str, extra: Mapping[Dimension, FrozenSet[Status]]) -> Profile:
    return Profile(name, description, MappingProxyType({**_INTEGRITY, **extra}))


PROFILES: Mapping[str, Profile] = MappingProxyType({
    p.name: p
    for p in (
        _profile("integrity", "Artifact and provenance integrity of the record and its whole lineage.", {}),
        _profile(
            "replay",
            "integrity, and every derivation in the lineage was replayed and matched. "
            "An admission-only lineage does not satisfy this (NOT_APPLICABLE is not PASS).",
            {Dimension.DERIVATION_VERIFICATION: _P},
        ),
        _profile(
            "replay-if-derived",
            "integrity, and every derivation in the lineage was replayed and matched; "
            "an admission-only lineage is accepted.",
            {Dimension.DERIVATION_VERIFICATION: _P_NA},
        ),
        _profile(
            "isolated-replay",
            "replay, with every transform executed inside an enforced isolation boundary.",
            {Dimension.DERIVATION_VERIFICATION: _P, Dimension.EXECUTION_SAFETY: _P},
        ),
        _profile(
            "reproducible",
            "isolated-replay, under an enforced, fully specified execution environment.",
            {
                Dimension.DERIVATION_VERIFICATION: _P,
                Dimension.EXECUTION_SAFETY: _P,
                Dimension.REPRODUCIBILITY: _P,
            },
        ),
        _profile(
            "authenticated-admission",
            "integrity, and every admission in the lineage carries verified authenticity evidence.",
            {Dimension.AUTHENTICITY: _P},
        ),
        _profile(
            "governed",
            "integrity, and preservation/admission verified against external anchoring evidence.",
            {Dimension.GOVERNANCE: _P},
        ),
    )
})
