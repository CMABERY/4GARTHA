#!/usr/bin/env python3
"""Test keys, a test-only Sigsum log, and the language-neutral anchor vectors.

    python tools/anchor_fixtures.py --check    # committed vectors == regenerated (CI runs this via pytest)
    python tools/anchor_fixtures.py --write    # regenerate conformance/anchor-v1-vectors.json

Everything here is deterministic: keys come from fixed seeds and Ed25519 is
deterministic, so regeneration reproduces the committed file byte for byte.

TEST ONLY. Every key below is public (its seed is in this file and in the
vectors). None may ever appear in a real anchor policy.

This module computes expected values with ledger.anchor, so on its own it
cannot catch a bug that both share. The independent checks are the external
known answers in the vectors (RFC 6962 roots from transparency-dev/merkle, the
C2SP signed-note example) and ci/anchor-go, which verifies every vector with
the Sigsum reference implementation (sigsum-go) and its sigsum-verify tool.
Expected accept/reject outcomes were written by hand, per case, below.

Requires ``cryptography`` (the [anchor] extra).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
try:  # the installed package (tests, the wheel job), else this checkout's src/
    from ledger import anchor as A
except ImportError:
    sys.path.insert(0, str(REPO / "src"))
    from ledger import anchor as A

VECTORS_PATH = REPO / "conformance" / "anchor-v1-vectors.json"
ORIGIN = "4gartha.test/anchor/1"
T0 = 1767225600  # 2026-01-01T00:00:00Z


@dataclass(frozen=True)
class TestKey:
    name: str

    @property
    def seed(self) -> bytes:
        return hashlib.sha256(b"4gartha.anchor/1 test key\x00" + self.name.encode()).digest()

    @property
    def signer(self) -> A.Signer:
        return A.signer_from_seed(self.seed)

    @property
    def public(self) -> bytes:
        return self.signer.public_key

    @property
    def key_hash(self) -> bytes:
        return A.sigsum_key_hash(self.public)

    def sign(self, msg: bytes) -> bytes:
        return self.signer.sign(msg)


KEY_NAMES = ("anchor", "attacker", "other-submitter", "filler", "log", "other-log",
             "w1", "w2", "w3", "w4", "w5", "w-unknown")
K: Dict[str, TestKey] = {n: TestKey(n) for n in KEY_NAMES}


class TestSigsumLog:
    """In-memory Sigsum log (log spec v1) that signs and cosigns with test keys."""

    def __init__(self, key: TestKey = K["log"]):
        self.key = key
        self.leaves: List[bytes] = []

    def add(self, message: bytes, submitter: TestKey, *, sign_checksum: Optional[bytes] = None) -> Tuple[int, bytes]:
        checksum = A.sigsum_checksum(message)
        sig = submitter.sign(A.sigsum_leaf_signed_data(sign_checksum if sign_checksum is not None else checksum))
        self.leaves.append(A.sigsum_leaf_hash(checksum, sig, submitter.key_hash))
        return len(self.leaves) - 1, sig

    def add_filler(self, n: int, tag: str) -> None:
        for i in range(n):
            self.add(hashlib.sha256(f"filler {tag} {i}".encode()).digest(), K["filler"])

    def proof(self, index: int, submitter: TestKey, leaf_sig: bytes, cosigners: Sequence[Tuple[TestKey, int]],
              size: Optional[int] = None) -> A.SigsumProof:
        size = size or len(self.leaves)
        kh = self.key.key_hash
        root = A.root_of(self.leaves[:size])
        th = self.key.sign(A.sigsum_tree_head_text(kh, size, root))
        cos = tuple(A.Cosignature(w.key_hash, ts, w.sign(A.sigsum_cosigned_data(kh, size, root, ts)))
                    for w, ts in cosigners)
        path = tuple(A.inclusion_path(index, self.leaves[:size])) if size > 1 else ()
        return A.SigsumProof(kh, submitter.key_hash, leaf_sig, size, root, th, cos, index if size > 1 else 0, path)


def policy_text(*, origin: str = ORIGIN, anchor: TestKey = K["anchor"], logs: Sequence[TestKey] = (K["log"],),
                witnesses: Sequence[str] = ("w1", "w2", "w3"), groups: Sequence[str] = ("group quorum-rule 2 w1 w2 w3",),
                quorum: str = "quorum-rule") -> str:
    lines = [f"# {A.POLICY_FORMAT} TEST POLICY: every key here is public test data",
             f"anchor-origin {origin}", f"anchor-key {anchor.public.hex()}"]
    lines += [f"log {k.public.hex()}" for k in logs]
    lines += [f"witness {w} {K[w].public.hex()}" for w in witnesses]
    lines += list(groups) + [f"quorum {quorum}"]
    return "\n".join(lines) + "\n"


def logged_proof(note_text: bytes, cosigners: Sequence[Tuple[str, int]], *, before: int = 5, after: int = 3,
                 submitter: TestKey = K["anchor"], log: Optional[TestSigsumLog] = None) -> A.SigsumProof:
    """Log SHA-256(note_text) between filler leaves; return the proof at the log's size."""
    log = log or TestSigsumLog()
    log.add_filler(before, "before")
    idx, sig = log.add(A.sigsum_message(note_text), submitter)
    log.add_filler(after, "after")
    return log.proof(idx, submitter, sig, [(K[w], ts) for w, ts in cosigners])


def _flip(data: bytes, i: int = 0) -> bytes:
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1:]


def _txt(b: bytes) -> str:
    return b.decode("utf-8")


# --- vector sections ----------------------------------------------------------

RFC6962_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
RFC6962_ROOTS = [  # transparency-dev/merkle v0.0.2, testonly/constants.go RootHashes()
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
SIGNED_NOTE_EXAMPLE = {  # c2sp.org/signed-note@v1.1.0, "Example"
    "vkey": "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
    "note": "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n",
}


def tree_records(n: int = 7) -> List[str]:
    return sorted(hashlib.sha256(f"4gartha anchor vector record {i}".encode()).hexdigest() for i in range(n))


def anchor_tree_section() -> dict:
    rids = tree_records()
    leaves = [A.leaf_hash(A.record_leaf(r)) for r in rids]
    return {
        "records": rids,
        "leaf_hashes": [h.hex() for h in leaves],
        "roots": [A.root_of(leaves[:n]).hex() for n in range(len(leaves) + 1)],
        "inclusion": [{"index": i, "size": n, "path": [h.hex() for h in A.inclusion_path(i, leaves[:n])]}
                      for n in range(1, len(leaves) + 1) for i in range(n)],
    }


def leaves_json_section() -> List[dict]:
    r = tree_records(3)
    ok = A.leaves_document(4, r)
    cases = [
        ("valid", ok, "accept", None),
        ("valid-first-batch", A.leaves_document(0, r[:1]), "accept", None),
        ("whitespace", ok.replace(b",", b", ", 1), "reject", "not canonical JSON"),
        ("trailing-newline", ok + b"\n", "reject", "not canonical JSON"),
        ("key-order", b'{"protocol":"4gartha.anchor/1","previous_size":4,"records":' + json.dumps(r).replace(" ", "").encode() + b"}", "reject", "not canonical JSON"),
        ("unsorted-records", A.canonical.encode({"previous_size": 4, "protocol": A.PROTOCOL, "records": [r[1], r[0], r[2]]}), "reject", "strictly ascending"),
        ("duplicate-record", A.canonical.encode({"previous_size": 4, "protocol": A.PROTOCOL, "records": [r[0], r[0], r[1]]}), "reject", "strictly ascending"),
        ("extra-key", A.canonical.encode({"previous_size": 4, "protocol": A.PROTOCOL, "records": r, "size": 7}), "reject", "exactly previous_size, protocol and records"),
        ("missing-protocol", A.canonical.encode({"previous_size": 4, "records": r}), "reject", "exactly previous_size, protocol and records"),
        ("wrong-protocol", A.canonical.encode({"previous_size": 4, "protocol": "4gartha.anchor/2", "records": r}), "reject", "protocol is"),
        ("negative-previous-size", A.canonical.encode({"previous_size": -1, "protocol": A.PROTOCOL, "records": r}), "reject", "non-negative integer"),
        ("boolean-previous-size", A.canonical.encode({"previous_size": True, "protocol": A.PROTOCOL, "records": r}), "reject", "non-negative integer"),
        ("float-previous-size", ok.replace(b'"previous_size":4', b'"previous_size":4.0'), "reject", "not canonical JSON"),
        ("empty-records", A.canonical.encode({"previous_size": 4, "protocol": A.PROTOCOL, "records": []}), "reject", "non-empty array"),
        ("uppercase-record-id", A.canonical.encode({"previous_size": 4, "protocol": A.PROTOCOL, "records": [r[0].upper()]}), "reject", "not a record ID"),
        ("artifact-style-prefix", A.canonical.encode({"previous_size": 4, "protocol": A.PROTOCOL, "records": ["sha256:" + r[0]]}), "reject", "not a record ID"),
    ]
    return [{"name": n, "text": _txt(t), "expect": e, "reason": why} for n, t, e, why in cases]


def _base_checkpoint() -> Tuple[bytes, bytes]:
    rids = tree_records()
    root = A.root_of([A.leaf_hash(A.record_leaf(r)) for r in rids])
    body = A.checkpoint_body(ORIGIN, len(rids), root)
    return body, root


def _line(name: str, key: TestKey, text: bytes, *, kid_of: Optional[TestKey] = None) -> bytes:
    kid = A.note_key_id(name, A.SIG_TYPE_ED25519, (kid_of or key).public)
    return A.signature_line(name, kid, key.sign(text))


def checkpoint_section() -> List[dict]:
    body, root = _base_checkpoint()
    anchor, attacker = K["anchor"], K["attacker"]
    good = _line(ORIGIN, anchor, body)
    note = body + b"\n" + good

    def signed(text: bytes, name: str = ORIGIN) -> bytes:
        return text + b"\n" + _line(name, anchor, text)

    blob = A.b64decode_canonical(good.decode().split(" ")[2].strip())
    assert blob is not None
    sig_b64 = A.b64(blob)  # 68 bytes -> ends with one '=' (two unused bits)
    noncanon_sig = sig_b64[:-2] + chr(ord(sig_b64[-2]) + 1) + "="
    root_b64 = A.b64(root)    # 32 bytes -> one '=' (two unused bits)
    noncanon_root = root_b64[:-2] + chr(ord(root_b64[-2]) + 1) + "="
    unknown = [_line(f"unknown{i}.example/key", attacker, body) for i in range(16)]
    cases = [
        # name, note bytes, expect, reason,
        # sigsum_go: pkg/checkpoint parse + key ID + Ed25519 over the formatted body, for this origin
        # x_mod_note: golang.org/x/mod/sumdb/note.Open with this origin's vkey
        ("valid", note, "trusted", None, "accept", "accept"),
        ("valid-plus-unknown-signature", note + _line("other.example/key", K["other-submitter"], body), "trusted", None, "accept", "accept"),
        ("unknown-key-under-origin-name", body + b"\n" + _line(ORIGIN, attacker, body), "untrusted", "no signature by the policy's anchor key", "reject", "reject"),
        ("unknown-key-and-name", body + b"\n" + _line("attacker.example/key", attacker, body), "untrusted", "no signature by the policy's anchor key", "reject", "reject"),
        ("key-id-collision", body + b"\n" + _line(ORIGIN, attacker, body, kid_of=anchor), "invalid", "does not verify", "reject", "reject"),
        ("wrong-content-size", body.replace(b"\n7\n", b"\n8\n") + b"\n" + good, "invalid", "does not verify", "reject", "reject"),
        ("wrong-content-root", A.checkpoint_body(ORIGIN, 7, _flip(root)) + b"\n" + good, "invalid", "does not verify", "reject", "reject"),
        ("truncated-signature", body + b"\n" + A.signature_line(ORIGIN, A.note_key_id(ORIGIN, 1, anchor.public), anchor.sign(body)[:63]), "invalid", "not an Ed25519 signature", "reject", "reject"),
        ("crlf", note.replace(b"\n", b"\r\n"), "malformed", "control character", "reject", "reject"),
        ("no-blank-line", body + good, "malformed", "no blank line", "reject", "reject"),
        ("missing-final-newline", note[:-1], "malformed", "does not end with a newline", "reject", "reject"),
        ("extension-line", signed(body + b"extension\n"), "malformed", "no extension lines", "reject", "accept"),
        ("size-leading-zero", signed(body.replace(b"\n7\n", b"\n07\n")), "malformed", "canonical decimal", "reject", "accept"),
        ("root-noncanonical-base64", signed(body.replace(root_b64.encode(), noncanon_root.encode())), "malformed", "canonical base64", "reject", "accept"),
        ("signature-noncanonical-base64", note.replace(sig_b64.encode(), noncanon_sig.encode()), "malformed", "not canonical base64", "accept", "accept"),
        ("duplicate-signature-line", note + good, "malformed", "same key name and key ID", "reject", "accept"),
        ("hyphen-for-em-dash", body + b"\n" + good.replace("\u2014".encode(), b"-"), "malformed", "is not", "reject", "reject"),
        ("double-space-in-signature-line", body + b"\n" + good.replace(b" ", b"  ", 1), "malformed", "is not", "reject", "reject"),
        ("seventeen-signature-lines", note + b"".join(unknown), "malformed", "the limit is 16", "reject", "accept"),
        ("tab-in-origin", signed(body.replace(b"anchor/1", b"anchor\t1"), "4gartha.test/anchor\t1"), "malformed", "control character", "reject", "reject"),
    ]
    return [{"name": n, "note": _txt(t), "origin": ORIGIN, "public_key": anchor.public.hex(), "expect": e,
             "reason": why, "sigsum_go": g, "x_mod_note": x} for n, t, e, why, g, x in cases]


def policy_section() -> List[dict]:
    base = policy_text()
    w = {n: K[n].public.hex() for n in KEY_NAMES}
    zero = "00" * 32

    def edit(old: str, new: str) -> str:
        assert old in base, old
        return base.replace(old, new, 1)

    cases = [
        ("valid", base, "accept", None, "accept"),
        ("valid-tabs-comments-uppercase", "  # comment\n" + edit(f"log {w['log']}", f"log\t{w['log'].upper()}\thttps://log.example"), "accept", None, "accept"),
        ("quorum-none", edit("quorum quorum-rule", "quorum none"), "reject", "quorum none", "accept"),
        ("missing-anchor-key", edit(f"anchor-key {w['anchor']}\n", ""), "reject", "no 'anchor-key' line", "accept"),
        ("missing-anchor-origin", edit(f"anchor-origin {ORIGIN}\n", ""), "reject", "no 'anchor-origin' line", "accept"),
        ("two-anchor-keys", edit(f"anchor-key {w['anchor']}\n", f"anchor-key {w['anchor']}\nanchor-key {w['attacker']}\n"), "reject", "exactly one 'anchor-key", "accept"),
        ("origin-with-plus", edit(f"anchor-origin {ORIGIN}", "anchor-origin 4gartha.test/anchor+1"), "reject", "contains '+'", "accept"),
        ("no-log", edit(f"log {w['log']}\n", ""), "reject", "at least one Sigsum log", "accept"),
        ("small-order-witness-key", edit(f"witness w3 {w['w3']}", f"witness w3 {zero}"), "reject", "small-order point", "accept"),
        ("unknown-keyword", base + "monitor https://monitor.example\n", "reject", "unknown keyword", "reject"),
        ("crlf", base.replace("\n", "\r\n"), "reject", "control character", "accept"),  # bufio.ScanLines strips CR
        ("undefined-member", edit("group quorum-rule 2 w1 w2 w3", "group quorum-rule 2 w1 w2 w9"), "reject", "undefined name", "reject"),
        ("forward-reference", edit("group quorum-rule 2 w1 w2 w3\n", "") .replace(f"witness w1 {w['w1']}", f"group quorum-rule 2 w1 w2 w3\nwitness w1 {w['w1']}"), "reject", "undefined name", "reject"),
        ("member-twice", edit("group quorum-rule 2 w1 w2 w3", "group quorum-rule 2 w1 w2 w2"), "reject", "already a member", "reject"),
        ("none-as-member", edit("group quorum-rule 2 w1 w2 w3", "group quorum-rule 2 w1 w2 none"), "reject", "cannot be a member", "reject"),
        ("threshold-zero", edit("group quorum-rule 2 w1 w2 w3", "group quorum-rule 0 w1 w2 w3"), "reject", "out of range", "reject"),
        ("threshold-too-large", edit("group quorum-rule 2 w1 w2 w3", "group quorum-rule 4 w1 w2 w3"), "reject", "out of range", "reject"),
        ("duplicate-witness-key", edit(f"witness w3 {w['w3']}", f"witness w3 {w['w2']}"), "reject", "duplicate witness key", "reject"),
        ("duplicate-log", edit(f"log {w['log']}", f"log {w['log']}\nlog {w['log']}"), "reject", "duplicate log", "reject"),
        ("duplicate-name", edit(f"witness w3 {w['w3']}", f"witness w2 {w['w3']}"), "reject", "duplicate name", "reject"),
        ("trailing-comment", edit(f"log {w['log']}", f"log {w['log']} # production log"), "reject", "'log <hex public key> [url]'", "reject"),
        ("two-quorums", base + "quorum w1\n", "reject", "exactly one 'quorum", "reject"),
        ("short-key", edit(f"log {w['log']}", f"log {w['log'][:-1]}"), "reject", "64 hex characters", "reject"),
    ]
    return [{"name": n, "text": t, "expect": e, "reason": why, "sigsum_go": g} for n, t, e, why, g in cases]


def _v1(p: A.SigsumProof, note_text: bytes) -> bytes:
    """The same proof in the superseded format version 1 (short checksum in the leaf line)."""
    text = A.format_sigsum_proof(p).decode()
    short = A.sigsum_checksum(A.sigsum_message(note_text))[:2].hex()
    text = text.replace("version=2\n", "version=1\n").replace("leaf=", f"leaf={short} ", 1)
    return text.encode()


def proof_section() -> List[dict]:
    body, _ = _base_checkpoint()
    std = [("w1", T0 + 300), ("w2", T0 + 100), ("w3", T0 + 200)]
    p = logged_proof(body, std)
    fmt = A.format_sigsum_proof
    base = fmt(p)
    pol = policy_text()

    def cos(*edits: Tuple[int, A.Cosignature]) -> A.SigsumProof:
        c = list(p.cosignatures)
        for i, new in edits:
            c[i] = new
        return replace(p, cosignatures=tuple(c))

    w2 = p.cosignatures[1]
    single = TestSigsumLog()
    i1, s1 = single.add(A.sigsum_message(body), K["anchor"])
    p1 = single.proof(i1, K["anchor"], s1, [(K["w1"], T0 + 10), (K["w2"], T0 + 20)])
    other_log = TestSigsumLog(K["other-log"])
    p_other_log = logged_proof(body, std, log=other_log)
    p_other_sub = logged_proof(body, std, submitter=K["other-submitter"])
    bad_leaf_log = TestSigsumLog()
    bad_leaf_log.add_filler(5, "before")
    bi, bs = bad_leaf_log.add(A.sigsum_message(body), K["anchor"], sign_checksum=A.sigsum_message(body))
    bad_leaf_log.add_filler(3, "after")
    p_bad_leaf = bad_leaf_log.proof(bi, K["anchor"], bs, [(K[w], ts) for w, ts in std])
    other_body = A.checkpoint_body(ORIGIN, 6, A.root_of([A.leaf_hash(A.record_leaf(r)) for r in tree_records(6)]))
    p_mismatch = logged_proof(other_body, std)
    nested_pol = policy_text(witnesses=("w1", "w2", "w3", "w4", "w5"),
                             groups=("group org-a 2 w1 w2 w3", "group org-b any w4 w5", "group both all org-a org-b"),
                             quorum="both")
    p_nested = logged_proof(body, [("w1", T0 + 10), ("w2", T0 + 30), ("w4", T0 + 20), ("w5", T0 + 5)])
    text = base.decode()
    lines = text.split("\n")
    cos_line = next(l for l in lines if l.startswith("cosignature="))
    cases = [
        # name, policy, proof bytes, expect, T, reason, sigsum_verify
        ("valid", pol, base, "PASS", T0 + 200, None, "accept"),
        ("valid-tree-size-1", pol, fmt(p1), "PASS", T0 + 20, None, "accept"),
        ("valid-nested-groups", nested_pol, fmt(p_nested), "PASS", T0 + 30, None, "accept"),
        ("valid-plus-unknown-witness", pol, fmt(replace(p, cosignatures=p.cosignatures + (A.Cosignature(K["w-unknown"].key_hash, T0, K["w-unknown"].sign(A.sigsum_cosigned_data(p.log_key_hash, p.size, p.root, T0))),))), "PASS", T0 + 200, None, "accept"),
        ("valid-uppercase-hex", pol, text.replace(p.root.hex(), p.root.hex().upper()).encode(), "PASS", T0 + 200, None, "accept"),
        ("omitted-cosignature-raises-time-bound", pol, fmt(replace(p, cosignatures=p.cosignatures[:2])), "PASS", T0 + 300, None, "accept"),
        ("below-quorum", pol, fmt(replace(p, cosignatures=p.cosignatures[:1])), "NOT_CHECKED", None, "quorum not met", "reject"),
        ("below-quorum-unknown-witnesses-do-not-count", pol, fmt(replace(p, cosignatures=(p.cosignatures[0], A.Cosignature(K["w-unknown"].key_hash, T0, K["w-unknown"].sign(A.sigsum_cosigned_data(p.log_key_hash, p.size, p.root, T0)))))), "NOT_CHECKED", None, "quorum not met", "reject"),
        ("no-cosignatures", pol, fmt(replace(p, cosignatures=())), "NOT_CHECKED", None, "quorum not met", "reject"),
        ("tampered-cosignature-quorum-otherwise-met", pol, fmt(cos((1, replace(w2, signature=_flip(w2.signature, 5))))), "FAIL", None, "cosignature by policy witness 'w2' does not verify", "accept"),
        ("backdated-cosignature-timestamp", pol, fmt(cos((1, replace(w2, timestamp=T0 - 86400)))), "FAIL", None, "cosignature by policy witness 'w2' does not verify", "accept"),
        ("tampered-tree-head-signature", pol, fmt(replace(p, tree_head_signature=_flip(p.tree_head_signature))), "FAIL", None, "tree head signature", "reject"),
        ("tampered-root-hash", pol, fmt(replace(p, root=_flip(p.root))), "FAIL", None, "does not lead to the root hash", "reject"),
        ("tampered-inclusion-path", pol, fmt(replace(p, path=(_flip(p.path[0], 31),) + p.path[1:])), "FAIL", None, "does not lead to the root hash", "reject"),
        ("wrong-leaf-index", pol, fmt(replace(p, leaf_index=p.leaf_index + 1)), "FAIL", None, "does not log this checkpoint", "reject"),
        ("leaf-index-out-of-range", pol, fmt(replace(p, leaf_index=p.size)), "FAIL", None, "out of range", "reject"),
        ("path-too-short", pol, fmt(replace(p, path=p.path[:-1])), "FAIL", None, "inclusion path has", "reject"),
        ("path-too-long", pol, fmt(replace(p, path=p.path + (p.path[0],))), "FAIL", None, "inclusion path has", "reject"),
        ("unknown-log", pol, fmt(p_other_log), "NOT_CHECKED", None, "is not in the policy", "reject"),
        ("leaf-by-other-submitter", pol, fmt(p_other_sub), "NOT_CHECKED", None, "not the policy's anchor key", "reject"),
        ("leaf-signed-over-message-not-checksum", pol, fmt(p_bad_leaf), "FAIL", None, "Sigsum leaf signature", "reject"),
        ("proof-for-another-checkpoint", pol, fmt(p_mismatch), "FAIL", None, "does not log this checkpoint", "reject"),
        ("format-version-1", pol, _v1(p, body), "FAIL", None, "pins version 2", "accept"),
        ("format-version-3", pol, text.replace("version=2", "version=3").encode(), "FAIL", None, "pins version 2", "reject"),
        ("duplicate-cosignature-key-hash", pol, text.replace(cos_line, cos_line + "\n" + cos_line).encode(), "FAIL", None, "same key hash", "reject"),
        ("crlf", pol, text.replace("\n", "\r\n").encode(), "FAIL", None, "invalid", "reject"),
        ("double-space-in-cosignature", pol, text.replace(cos_line, cos_line.replace(" ", "  ", 1)).encode(), "FAIL", None, "exactly 3 space-separated values", "reject"),
        ("size-leading-zero", pol, text.replace(f"size={p.size}", f"size=0{p.size}").encode(), "FAIL", None, "invalid tree size", "reject"),
        ("size-zero", pol, fmt(replace(p, size=0)), "FAIL", None, "tree size is 0", "reject"),
        ("tree-size-1-with-inclusion-part", pol, fmt(p1).decode().rstrip("\n").encode() + b"\n\nleaf_index=0\nnode_hash=" + (b"00" * 32) + b"\n", "FAIL", None, "must end after the tree head", "reject"),
        ("missing-blank-line-before-inclusion", pol, text.replace("\nleaf_index=", "leaf_index=").encode(), "FAIL", None, "expected", "reject"),
        ("missing-final-newline", pol, base[:-1], "FAIL", None, "does not end with a newline", "reject"),
        ("trailing-empty-line", pol, base + b"\n", "FAIL", None, "expected node_hash", "reject"),
    ]
    out = []
    for n, pl, prf, e, t, why, g in cases:
        out.append({"name": n, "checkpoint_text": _txt(body),
                    "anchor_public_key": K["anchor"].public.hex(), "policy": pl, "proof": prf.decode("ascii"),
                    "expect": e, "anchored_no_later_than": t, "reason": why, "sigsum_verify": g})
    return out


def anchor_log_section() -> dict:
    """A complete two-batch anchor log (files byte for byte) with Sigsum proofs
    from one test log: what ledger/anchors/ looks like once anchored."""
    rids = tree_records(5)
    batches = [rids[:3], rids[3:]]
    log = TestSigsumLog()
    log.add_filler(2, "anchor-log")
    files: Dict[str, Dict[str, str]] = {}
    times: Dict[str, int] = {}
    leaves: List[bytes] = []
    prev = 0
    for n, (batch, cos) in enumerate(zip(batches, ([("w1", T0 + 50), ("w3", T0 + 40)],
                                                   [("w1", T0 + 900), ("w2", T0 + 700), ("w3", T0 + 800)]))):
        leaves += [A.leaf_hash(A.record_leaf(r)) for r in batch]
        size = prev + len(batch)
        note = A.signed_checkpoint(ORIGIN, size, A.root_of(leaves), K["anchor"].signer)
        text = A.parse_note(note).text
        idx, sig = log.add(A.sigsum_message(text), K["anchor"])
        log.add_filler(1 + n, f"anchor-log-{n}")
        proof = log.proof(idx, K["anchor"], sig, [(K[w], ts) for w, ts in cos])
        name = A.batch_name(size)
        files[name] = {A.LEAVES_FILE: _txt(A.leaves_document(prev, batch)), A.CHECKPOINT_FILE: _txt(note),
                       A.PROOF_FILE: _txt(A.format_sigsum_proof(proof))}
        times[name] = A.quorum_time(A.parse_policy(policy_text().encode()).quorum,
                                    {K[w].key_hash: ts for w, ts in cos})  # type: ignore[assignment]
        prev = size
    return {"policy": policy_text(), "batches": files, "anchored_no_later_than": times, "records": rids}


def build_vectors() -> dict:
    return {
        "description": ("Language-neutral conformance vectors for 4gartha.anchor/1 (SPEC.md, 'Anchor log'). "
                        "Text fields are exact bytes (UTF-8); hashes and keys are lowercase hex. Expected outcomes "
                        "are normative for 4GARTHA verifiers. Fields named sigsum_go / sigsum_verify record what the "
                        "Sigsum reference implementation does with the same bytes; where they differ from 'expect', "
                        "4GARTHA is deliberately stricter (ASSURANCE.md 5.7)."),
        "protocol": A.PROTOCOL,
        "policy_format": A.POLICY_FORMAT,
        "pinned_specifications": {
            "sigsum_go": "sigsum.org/sigsum-go v0.14.1 (doc/sigsum-proof.md proof format version 2, doc/policy.md)",
            "sigsum_log_spec": "github.com/sigsum/sigsum log.md at 3d7234dd7c72ae5eb3e7a35fef2cc1593bf0f4cb ('Stable version v1')",
            "c2sp": "signed-note@v1.1.0, tlog-checkpoint@v1.1.0, tlog-cosignature@v1.1.0",
            "rfc6962_known_answers": "github.com/transparency-dev/merkle v0.0.2 testonly/constants.go",
        },
        "test_keys": {"warning": "TEST ONLY: seeds are public; never use these keys in a real policy",
                      "seed_derivation": "SHA-256('4gartha.anchor/1 test key' || 0x00 || name)",
                      "keys": {n: {"seed": K[n].seed.hex(), "public_key": K[n].public.hex()} for n in KEY_NAMES}},
        "test_origin": ORIGIN,
        "rfc6962": {"leaves": RFC6962_LEAVES, "roots": RFC6962_ROOTS},
        "signed_note_example": SIGNED_NOTE_EXAMPLE,
        "anchor_tree": anchor_tree_section(),
        "leaves_json": leaves_json_section(),
        "checkpoints": checkpoint_section(),
        "policies": policy_section(),
        "sigsum_proofs": proof_section(),
        "anchor_log": anchor_log_section(),
    }


def render() -> bytes:
    return (json.dumps(build_vectors(), indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    data = render()
    if args.write:
        VECTORS_PATH.write_bytes(data)
        print(f"wrote {VECTORS_PATH} ({len(data)} bytes)")
        return 0
    if VECTORS_PATH.read_bytes() != data:
        print(f"{VECTORS_PATH} differs from the regenerated vectors", file=sys.stderr)
        return 1
    print("anchor vectors reproduce byte for byte")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
