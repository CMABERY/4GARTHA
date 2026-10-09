"""Helpers for anchoring tests (not a test module).

Repositories with anchored records, test-only Sigsum proofs (from
tools/anchor_fixtures.py), and trust policies held by the *verifier*: policy
files are written outside the repository under test unless a test is
deliberately planting one inside it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Optional, Sequence, Tuple

from ledger import anchor as A

from ledger_testutil import REPO, admit, concat_transform, derive, init_repo

_spec = importlib.util.spec_from_file_location("anchor_fixtures", REPO / "tools" / "anchor_fixtures.py")
F = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules.setdefault("anchor_fixtures", F)
_spec.loader.exec_module(F)  # type: ignore[union-attr]

K = F.K
ORIGIN = F.ORIGIN
T0 = F.T0
# w1 at T0+300, w2 at T0+100, w3 at T0+200; quorum 2 of 3, so the time bound is
# T0+200 (the second-smallest), never T0+100 (the earliest).
STD_COSIGNERS: Tuple[Tuple[str, int], ...] = (("w1", T0 + 300), ("w2", T0 + 100), ("w3", T0 + 200))
STD_TIME = T0 + 200


def policy(text: Optional[str] = None, **kw) -> A.AnchorPolicy:
    return A.parse_policy((text if text is not None else F.policy_text(**kw)).encode())


def write_policy(where: Path, text: Optional[str] = None, **kw) -> Path:
    where.parent.mkdir(parents=True, exist_ok=True)
    where.write_text(text if text is not None else F.policy_text(**kw), encoding="utf-8")
    return where


def batch_dir(root: Path, size: int) -> Path:
    return A.anchors_dir(root) / A.batch_name(size)


def anchor_batch(root: Path, signer: Optional[A.Signer] = None, origin: str = ORIGIN) -> int:
    """Anchor every stored record not yet in the log; return the new tree size."""
    a, new = A.plan_batch(root)
    assert new, "nothing to anchor"
    _, size, _ = A.write_batch(root, a, new, signer or K["anchor"].signer, origin)
    return size


def note_text(root: Path, size: int) -> bytes:
    return A.parse_note((batch_dir(root, size) / A.CHECKPOINT_FILE).read_bytes()).text


def log_batch(root: Path, size: int, cosigners: Sequence[Tuple[str, int]] = STD_COSIGNERS,
              submitter=None, log=None) -> A.SigsumProof:
    """Log the batch's checkpoint in a test Sigsum log and store its proof."""
    p = F.logged_proof(note_text(root, size), cosigners, submitter=submitter or K["anchor"], log=log)
    write_proof(root, size, p)
    return p


def write_proof(root: Path, size: int, p) -> None:
    data = p if isinstance(p, bytes) else A.format_sigsum_proof(p)
    (batch_dir(root, size) / A.PROOF_FILE).write_bytes(data)


def anchored_repo(root: Path) -> Tuple[Path, str, str, int]:
    """Admission a, derivation d over a, both in one logged batch. (root, a, d, size)."""
    init_repo(root)
    a = admit(root, b"hello")
    d = derive(root, b"hello!", [a], concat_transform(), params={"suffix": "!"})
    size = anchor_batch(root)
    log_batch(root, size)
    return root, a, d, size
