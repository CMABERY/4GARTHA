"""External anchoring of the ledger, protocol ``4gartha.anchor/1``.

SPEC.md ("Anchor log") defines the bytes. ASSURANCE.md 5.7 defines what a
verifier may conclude from them, and against whom. In short:

  anchor log   an RFC 6962 Merkle tree whose leaves are raw 32-byte record IDs,
               appended in batches (each batch: the records not yet in the log,
               sorted ascending)
  batch        ledger/anchors/<tree size, 12 digits>/
                 leaves.json   canonical JSON {"previous_size", "protocol", "records"}
                 checkpoint    C2SP signed note: origin, tree size, base64 root,
                               signed with Ed25519 by the anchor key
                 sigsum.proof  optional: a Sigsum proof (format version 2) that
                               message = SHA-256(checkpoint note text) was logged
  policy       supplied by the verifier, never read from the repository: the
               anchor origin and key, Sigsum logs, witnesses and quorum

Nothing here uses the network. Signature checks need Ed25519, from the optional
``cryptography`` dependency (``pip install 'epistemic-ledger[anchor]'``). Without
it every structural and hash check still runs, and nothing that needs a
signature can PASS.

Outcome rules (ASSURANCE.md 5.7):

  FAIL         an anchor file is malformed or internally inconsistent, an
               anchored record is missing or invalid, or a signature by a key
               the policy trusts does not verify (including a single witness
               cosignature, even when the quorum is met without it)
  NOT_CHECKED  the files are consistent, but no trusted evidence chain exists:
               unknown keys or logs, no proof yet, quorum not met, no Ed25519
  ERROR        an anchor file or anchored record could not be read
  PASS         a checkpoint covering the lineage is signed by the policy's
               anchor key and logged in a policy log whose tree head a witness
               quorum cosigned; T bounds when that checkpoint existed
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from . import canonical, records
from .assurance import Outcome, Status

PROTOCOL = "4gartha.anchor/1"
POLICY_FORMAT = "4gartha.anchor-policy/1"
SIGSUM_PROOF_VERSION = 2
INSTALL_HINT = "pip install 'epistemic-ledger[anchor]'"

LEAVES_FILE = "leaves.json"
CHECKPOINT_FILE = "checkpoint"
PROOF_FILE = "sigsum.proof"
KEEP_FILE = ".keep"
BATCH_NAME_RE = re.compile(r"[0-9]{12}")
MAX_LOG_SIZE = 10**12 - 1          # batch directory names have 12 digits
MAX_BATCH_RECORDS = 65_536
MAX_LEAVES_BYTES = 8 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 128 * 1024  # room for 16 post-quantum signature lines
MAX_PROOF_BYTES = 64 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_NOTE_SIGNATURES = 16           # signed-note: verifiers MUST accept at least 16
MAX_PROOF_PATH = 63                # sigsum-go proofSizeLimit
MAX_UINT63 = 2**63 - 1             # Sigsum integers, and RFC 6962 sizes in practice
MAX_NAME_BYTES = 255               # tlog-cosignature: origins and cosigner names

SIG_TYPE_ED25519 = 0x01
SIGSUM_LEAF_NAMESPACE = b"sigsum.org/v1/tree-leaf"
SIGSUM_TREE_ORIGIN_PREFIX = "sigsum.org/v1/tree/"
COSIGNATURE_LABEL = "cosignature/v1"
EM_DASH = "—"


class FormatError(ValueError):
    """Bytes that are not a valid instance of the format they claim to be."""


class PolicyError(ValueError):
    """A trust policy that cannot be used. A verifier input error, never a report status."""


class AnchorRefused(ValueError):
    """``ledger anchor create`` refused to write anything."""


# --- Ed25519 (optional dependency) -------------------------------------------


class Ed25519Unavailable(RuntimeError):
    pass


def _ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError:
        return None
    return InvalidSignature, Ed25519PublicKey, Ed25519PrivateKey


def ed25519_available() -> bool:
    return _ed25519() is not None


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 verification. Raises Ed25519Unavailable without ``cryptography``."""
    lib = _ed25519()
    if lib is None:
        raise Ed25519Unavailable(f"Ed25519 is not available ({INSTALL_HINT})")
    invalid, public_cls, _ = lib
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_cls.from_public_bytes(public_key).verify(signature, message)
    except (invalid, ValueError):
        return False
    return True


# Encodings of the eight small-order points (and their non-canonical aliases),
# sign bit ignored, as in libsodium's blocklist. Under such a "public key"
# signatures can be forged without any private key; OpenSSL accepts them
# (tests/test_anchor.py demonstrates it). The policy parser rejects them.
_P = 2**255 - 19
_SMALL_ORDER_Y = (
    0, 1, _P - 1, _P, _P + 1,
    int.from_bytes(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"),
    int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little"),
)


def is_small_order_encoding(public_key: bytes) -> bool:
    if len(public_key) != 32:
        return False
    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    return y in _SMALL_ORDER_Y


@dataclass(frozen=True)
class Signer:
    """An Ed25519 signing key held by this process (test keys, or a local key file)."""

    public_key: bytes
    _sign: Callable[[bytes], bytes] = field(repr=False)

    def sign(self, message: bytes) -> bytes:
        sig = self._sign(message)
        if len(sig) != 64:
            raise ValueError("signer returned a signature that is not 64 bytes")
        return sig


def _raw_public(key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signer_from_seed(seed: bytes) -> Signer:
    lib = _ed25519()
    if lib is None:
        raise Ed25519Unavailable(f"Ed25519 is not available ({INSTALL_HINT})")
    key = lib[2].from_private_bytes(seed)
    return Signer(_raw_public(key), key.sign)


def load_signer(path: Path) -> Signer:
    """An unencrypted Ed25519 private key file: OpenSSH (``ssh-keygen -t ed25519
    -N ''``) or PKCS#8 PEM (``openssl genpkey -algorithm ed25519``)."""
    lib = _ed25519()
    if lib is None:
        raise Ed25519Unavailable(f"Ed25519 is not available ({INSTALL_HINT})")
    from cryptography.hazmat.primitives import serialization

    data = Path(path).read_bytes()
    key = None
    errors = []
    for loader in (serialization.load_ssh_private_key, serialization.load_pem_private_key):
        try:
            key = loader(data, password=None)
            break
        except (ValueError, TypeError) as e:  # wrong format, or encrypted
            errors.append(str(e))
    if key is None:
        raise ValueError(f"{path}: not an unencrypted OpenSSH or PKCS#8 private key ({'; '.join(errors)})")
    if not isinstance(key, lib[2]):
        raise ValueError(f"{path}: not an Ed25519 private key")
    return Signer(_raw_public(key), key.sign)


# --- small strict encoders/decoders ------------------------------------------

_DECIMAL_RE = re.compile(r"0|[1-9][0-9]*")
_HEX_RE = {n: re.compile(f"[0-9a-fA-F]{{{2 * n}}}") for n in (32, 64)}
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode_canonical(text: str) -> Optional[bytes]:
    """Standard base64 with padding; None unless ``text`` is the canonical
    encoding (RFC 4648 3.5: padding bits zero), as signed-note requires."""
    if not text or _B64_RE.fullmatch(text) is None:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if b64(raw) == text else None


_MAX_DECIMAL_DIGITS = len(str(MAX_UINT63))


def _decimal(text: str) -> Optional[int]:
    """``0|[1-9][0-9]*`` up to 2**63 - 1 (Sigsum and C2SP ASCII decimals).
    The length is bounded before conversion: int() refuses strings of more
    than sys.get_int_max_str_digits() digits with a ValueError, and a file
    within its size limit can hold far more."""
    if len(text) > _MAX_DECIMAL_DIGITS or _DECIMAL_RE.fullmatch(text) is None:
        return None
    value = int(text)
    return value if value <= MAX_UINT63 else None


def _clip(text: str, n: int = 40) -> str:
    """``text`` for an error message, shortened if it is long."""
    return text if len(text) <= n else f"{text[:n]}... ({len(text)} characters)"


def _hex(text: str, n: int) -> Optional[bytes]:
    """Exactly ``n`` bytes of hex; either case, as on the Sigsum wire."""
    if _HEX_RE[n].fullmatch(text) is None:
        return None
    return bytes.fromhex(text)


def name_problem(name: str) -> Optional[str]:
    """Why ``name`` is not a valid key name / origin / cosigner name, or None."""
    if not name:
        return "is empty"
    if len(name.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
        return f"is longer than {MAX_NAME_BYTES} bytes"
    for ch in name:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            return "contains a control character"
        if ch == "+":
            return "contains '+'"
        if ch.isspace() or unicodedata.category(ch) == "Zs":
            return "contains a space"
        if 0xD800 <= ord(ch) <= 0xDFFF:
            return "is not valid UTF-8"
    return None


_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
MAX_UTC_TIMESTAMP = 253_402_300_799   # 9999-12-31T23:59:59Z, the last second datetime can represent


def utc(timestamp: int) -> Optional[str]:
    """``timestamp`` (Unix seconds) as ``YYYY-MM-DDTHH:MM:SSZ``, or None if it
    is after 9999-12-31T23:59:59Z. Sigsum timestamps go up to 2**63 - 1, so a
    valid cosignature can carry a time no calendar date here represents; the
    integer remains the time bound. Computed without the platform's time
    functions, whose range varies."""
    if not 0 <= timestamp <= MAX_UTC_TIMESTAMP:
        return None
    return (_EPOCH + _dt.timedelta(seconds=timestamp)).strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_time(timestamp: int) -> str:
    """A time bound for a report's text: UTC when representable, otherwise the
    integer, saying why. Never a different value."""
    text = utc(timestamp)
    if text is not None:
        return text
    return f"Unix time {timestamp} (after 9999-12-31T23:59:59Z, so no UTC date is shown)"


# --- RFC 6962 Merkle tree ----------------------------------------------------

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def record_leaf(rid: str) -> bytes:
    """A record ID's leaf: its 32 raw bytes (the ID is already domain-separated)."""
    if not records.is_digest(rid):
        raise ValueError(f"not a record ID: {rid!r}")
    return bytes.fromhex(rid)


def _split(n: int) -> int:
    """Largest power of two smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def root_of(leaf_hashes: Sequence[bytes]) -> bytes:
    """MTH(D[n]) exactly as RFC 6962 section 2.1 defines it (recursive)."""
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return node_hash(root_of(leaf_hashes[:k]), root_of(leaf_hashes[k:]))


def inclusion_path(index: int, leaf_hashes: Sequence[bytes]) -> List[bytes]:
    """PATH(m, D[n]) from RFC 6962 section 2.1.1."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(index, leaf_hashes[:k]) + [root_of(leaf_hashes[k:])]
    return inclusion_path(index - k, leaf_hashes[k:]) + [root_of(leaf_hashes[:k])]


def _path_length(index: int, size: int) -> int:
    k = (index ^ (size - 1)).bit_length()
    return k + bin(index >> k).count("1")


def verify_inclusion(leaf: bytes, index: int, size: int, root: bytes, path: Sequence[bytes]) -> Optional[str]:
    """None if ``path`` proves ``leaf`` (a leaf hash) at ``index`` in the tree of
    ``size`` with ``root``; otherwise why not. RFC 9162 2.1.3.2, as sigsum-go."""
    if size < 1 or not 0 <= index < size:
        return f"leaf index {index} out of range for tree size {size}"
    want = _path_length(index, size)
    if len(path) != want:
        return f"inclusion path has {len(path)} node(s), tree size {size} index {index} needs {want}"
    r, fn, sn, i = leaf, index, size - 1, 0
    while sn > 0:
        if fn & 1:
            r = node_hash(path[i], r)
            i += 1
        elif fn < sn:
            r = node_hash(r, path[i])
            i += 1
        fn >>= 1
        sn >>= 1
    if r != root:
        return "inclusion path does not lead to the root hash"
    return None


class Tree:
    """Append-only RFC 6962 tree (compact range); ``root()`` at the current size."""

    def __init__(self) -> None:
        self._range: List[Tuple[int, bytes]] = []
        self.size = 0

    def append(self, leaf: bytes) -> None:
        height, node = 0, leaf
        while self._range and self._range[-1][0] == height:
            node = node_hash(self._range.pop()[1], node)
            height += 1
        self._range.append((height, node))
        self.size += 1

    def root(self) -> bytes:
        if not self._range:
            return EMPTY_ROOT
        r = self._range[-1][1]
        for _, h in reversed(self._range[:-1]):
            r = node_hash(h, r)
        return r


# --- C2SP signed notes and checkpoints ----------------------------------------


def note_key_id(name: str, sig_type: int, public_key: bytes) -> bytes:
    """signed-note: SHA-256(key name || 0x0A || type || public key)[:4]. An
    identifier, not a cryptographic commitment: always verify with the key."""
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([sig_type]) + public_key).digest()[:4]


@dataclass(frozen=True)
class NoteSignature:
    name: str
    key_id: bytes
    signature: bytes


@dataclass(frozen=True)
class Note:
    text: bytes
    signatures: Tuple[NoteSignature, ...]


def signature_line(name: str, key_id: bytes, signature: bytes) -> bytes:
    return f"{EM_DASH} {name} {b64(key_id + signature)}\n".encode("utf-8")


def parse_note(data: bytes) -> Note:
    """Strict C2SP signed-note (v1.1.0) syntax. Signatures are not verified here."""
    if len(data) > MAX_CHECKPOINT_BYTES:
        raise FormatError(f"note exceeds {MAX_CHECKPOINT_BYTES} bytes")
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("note is not valid UTF-8") from None
    for ch in s:
        if ord(ch) < 0x20 and ch != "\n":
            raise FormatError(f"note contains control character U+{ord(ch):04X} (only newline is allowed)")
    if not s.endswith("\n"):
        raise FormatError("note does not end with a newline")
    sep = s.rfind("\n\n")
    if sep < 0:
        raise FormatError("note has no blank line between its text and its signatures")
    text, block = s[: sep + 1], s[sep + 2:]
    lines = block.split("\n")[:-1]
    if not lines:
        raise FormatError("note has no signature lines")
    if len(lines) > MAX_NOTE_SIGNATURES:
        raise FormatError(f"note has {len(lines)} signature lines; the limit is {MAX_NOTE_SIGNATURES}")
    sigs: List[NoteSignature] = []
    seen = set()
    for n, line in enumerate(lines, 1):
        fields = line.split(" ")
        if len(fields) != 3 or fields[0] != EM_DASH:
            raise FormatError(f"signature line {n} is not '{EM_DASH} <key name> <base64 signature>'")
        name, blob_text = fields[1], fields[2]
        problem = name_problem(name)
        if problem:
            raise FormatError(f"signature line {n}: key name {problem}")
        blob = b64decode_canonical(blob_text)
        if blob is None:
            raise FormatError(f"signature line {n}: signature is not canonical base64")
        if len(blob) < 5:
            raise FormatError(f"signature line {n}: signature is shorter than a key ID plus one byte")
        key = (name, blob[:4])
        if key in seen:
            raise FormatError(f"signature line {n}: a second signature with the same key name and key ID")
        seen.add(key)
        sigs.append(NoteSignature(name, blob[:4], blob[4:]))
    return Note(text.encode("utf-8"), tuple(sigs))


def checkpoint_body(origin: str, size: int, root: bytes) -> bytes:
    """The checkpoint note text (C2SP tlog-checkpoint, no extension lines)."""
    return f"{origin}\n{size}\n{b64(root)}\n".encode("utf-8")


@dataclass(frozen=True)
class CheckpointBody:
    origin: str
    size: int
    root: bytes


def parse_checkpoint_body(text: bytes) -> CheckpointBody:
    lines = text.decode("utf-8").split("\n")
    if lines[-1] != "" or len(lines) != 4:
        raise FormatError("checkpoint text must be exactly three lines: origin, tree size, root hash "
                          "(4gartha.anchor/1 defines no extension lines)")
    origin, size_text, root_text = lines[:3]
    problem = name_problem(origin)
    if problem:
        raise FormatError(f"checkpoint origin {problem}")
    size = _decimal(size_text)
    if size is None:
        raise FormatError(f"checkpoint tree size {_clip(size_text)!r} is not a canonical decimal "
                          f"of at most {MAX_UINT63}")
    root = b64decode_canonical(root_text)
    if root is None or len(root) != 32:
        raise FormatError("checkpoint root hash is not the canonical base64 of 32 bytes")
    return CheckpointBody(origin, size, root)


def signed_checkpoint(origin: str, size: int, root: bytes, signer: Signer) -> bytes:
    body = checkpoint_body(origin, size, root)
    sig = signer.sign(body)
    return body + b"\n" + signature_line(origin, note_key_id(origin, SIG_TYPE_ED25519, signer.public_key), sig)


# --- Sigsum (log spec v1; proof format version 2, sigsum-go v0.14.1) ----------


def sigsum_message(note_text: bytes) -> bytes:
    """What is submitted to Sigsum for a checkpoint: SHA-256 of its note text.
    (``sigsum-submit`` and ``sigsum-verify`` hash their input once to get this.)"""
    return hashlib.sha256(note_text).digest()


def sigsum_checksum(message: bytes) -> bytes:
    """What the log stores: checksum = SHA-256(message)."""
    return hashlib.sha256(message).digest()


def sigsum_key_hash(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()


def sigsum_leaf_signed_data(checksum: bytes) -> bytes:
    return SIGSUM_LEAF_NAMESPACE + b"\x00" + checksum


def sigsum_leaf_hash(checksum: bytes, signature: bytes, key_hash: bytes) -> bytes:
    return leaf_hash(checksum + signature + key_hash)


def sigsum_tree_head_text(log_key_hash: bytes, size: int, root: bytes) -> bytes:
    return checkpoint_body(SIGSUM_TREE_ORIGIN_PREFIX + log_key_hash.hex(), size, root)


def sigsum_cosigned_data(log_key_hash: bytes, size: int, root: bytes, timestamp: int) -> bytes:
    return f"{COSIGNATURE_LABEL}\ntime {timestamp}\n".encode("ascii") + sigsum_tree_head_text(log_key_hash, size, root)


@dataclass(frozen=True)
class Cosignature:
    key_hash: bytes
    timestamp: int
    signature: bytes


@dataclass(frozen=True)
class SigsumProof:
    log_key_hash: bytes
    leaf_key_hash: bytes
    leaf_signature: bytes
    size: int
    root: bytes
    tree_head_signature: bytes
    cosignatures: Tuple[Cosignature, ...]
    leaf_index: int
    path: Tuple[bytes, ...]


def parse_sigsum_proof(data: bytes) -> SigsumProof:
    """Strict Sigsum proof, format version 2 only (doc/sigsum-proof.md, v0.14.1)."""
    if len(data) > MAX_PROOF_BYTES:
        raise FormatError(f"proof exceeds {MAX_PROOF_BYTES} bytes")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise FormatError("proof is not ASCII") from None
    if not text.endswith("\n"):
        raise FormatError("proof does not end with a newline")
    lines = text[:-1].split("\n")
    pos = 0

    def value(key: str) -> str:
        nonlocal pos
        if pos >= len(lines):
            raise FormatError(f"proof ends before its {key}= line")
        line = lines[pos]
        k, sep, v = line.partition("=")
        if line == "" or not sep or k != key:
            raise FormatError(f"proof line {pos + 1}: expected {key}=..., found {line[:40]!r}")
        pos += 1
        return v

    def blank(why: str) -> None:
        nonlocal pos
        if pos >= len(lines) or lines[pos] != "":
            raise FormatError(f"proof line {pos + 1}: expected the empty line {why}")
        pos += 1

    def need(parsed, what: str):
        if parsed is None:
            raise FormatError(f"proof line {pos}: invalid {what}")
        return parsed

    version = need(_decimal(value("version")), "version")
    if version != SIGSUM_PROOF_VERSION:
        raise FormatError(f"Sigsum proof format version {version}; {PROTOCOL} pins version {SIGSUM_PROOF_VERSION}")
    log = need(_hex(value("log"), 32), "log key hash")
    leaf = value("leaf").split(" ")
    if len(leaf) != 2:
        raise FormatError(f"proof line {pos}: leaf= needs exactly 2 space-separated values (key hash, signature)")
    leaf_kh, leaf_sig = need(_hex(leaf[0], 32), "leaf key hash"), need(_hex(leaf[1], 64), "leaf signature")
    blank("after the leaf")
    size = need(_decimal(value("size")), "tree size")
    if size == 0:
        raise FormatError("proof tree size is 0 (always invalid)")
    root = need(_hex(value("root_hash"), 32), "root hash")
    th_sig = need(_hex(value("signature"), 64), "tree head signature")
    cosigs: List[Cosignature] = []
    seen = set()
    while pos < len(lines) and lines[pos] != "":
        parts = value("cosignature").split(" ")
        if len(parts) != 3:
            raise FormatError(f"proof line {pos}: cosignature= needs exactly 3 space-separated values")
        kh = need(_hex(parts[0], 32), "cosignature key hash")
        ts = need(_decimal(parts[1]), "cosignature timestamp")
        sig = need(_hex(parts[2], 64), "cosignature")
        if kh in seen:
            raise FormatError(f"proof line {pos}: second cosignature with the same key hash")
        seen.add(kh)
        cosigs.append(Cosignature(kh, ts, sig))
    if size == 1:
        if pos != len(lines):
            raise FormatError("a proof for tree size 1 must end after the tree head (no inclusion part)")
        return SigsumProof(log, leaf_kh, leaf_sig, size, root, th_sig, tuple(cosigs), 0, ())
    blank("before the inclusion proof")
    index = need(_decimal(value("leaf_index")), "leaf index")
    path: List[bytes] = []
    while pos < len(lines):
        path.append(need(_hex(value("node_hash"), 32), "node hash"))
        if len(path) > MAX_PROOF_PATH:
            raise FormatError(f"inclusion path longer than {MAX_PROOF_PATH} nodes")
    if not path:
        raise FormatError("inclusion path is empty (tree size > 1)")
    return SigsumProof(log, leaf_kh, leaf_sig, size, root, th_sig, tuple(cosigs), index, tuple(path))


def format_sigsum_proof(p: SigsumProof) -> bytes:
    out = [f"version={SIGSUM_PROOF_VERSION}", f"log={p.log_key_hash.hex()}",
           f"leaf={p.leaf_key_hash.hex()} {p.leaf_signature.hex()}", "",
           f"size={p.size}", f"root_hash={p.root.hex()}", f"signature={p.tree_head_signature.hex()}"]
    out += [f"cosignature={c.key_hash.hex()} {c.timestamp} {c.signature.hex()}" for c in p.cosignatures]
    if p.size > 1:
        out += ["", f"leaf_index={p.leaf_index}"] + [f"node_hash={h.hex()}" for h in p.path]
    return ("\n".join(out) + "\n").encode("ascii")


def sigsum_inclusion_problem(p: SigsumProof, note_text: bytes) -> Optional[str]:
    """None if the proof's Sigsum tree head includes the leaf this proof claims
    for ``note_text``. Hashes only: no key, no policy, no Ed25519."""
    checksum = sigsum_checksum(sigsum_message(note_text))
    lh = sigsum_leaf_hash(checksum, p.leaf_signature, p.leaf_key_hash)
    if p.size == 1:
        return None if lh == p.root else "Sigsum leaf for this checkpoint is not the root of the size-1 tree"
    return verify_inclusion(lh, p.leaf_index, p.size, p.root, p.path)


# --- trust policy (verifier input) --------------------------------------------


@dataclass(frozen=True)
class Witness:
    name: str
    public_key: bytes

    @property
    def key_hash(self) -> bytes:
        return sigsum_key_hash(self.public_key)


@dataclass(frozen=True)
class Group:
    name: str
    threshold: int
    members: Tuple[Union["Group", Witness], ...]


@dataclass(frozen=True)
class AnchorPolicy:
    origin: str
    anchor_key: bytes
    logs: Mapping[bytes, bytes]          # Sigsum key hash -> log public key
    witnesses: Mapping[bytes, Witness]   # Sigsum key hash -> witness
    quorum: Union[Group, Witness]
    sha256: str                          # of the policy file's bytes

    @property
    def anchor_key_hash(self) -> bytes:
        return sigsum_key_hash(self.anchor_key)


def quorum_time(node: Union[Group, Witness], verified: Mapping[bytes, int]) -> Optional[int]:
    """Earliest time t such that the cosignatures with timestamp <= t satisfy
    ``node``; None if the verified cosignatures never satisfy it. For a group of
    threshold k this is the k-th smallest member time (never the earliest
    cosignature: a minority of dishonest witnesses could backdate that)."""
    if isinstance(node, Witness):
        return verified.get(node.key_hash)
    times = sorted(t for t in (quorum_time(m, verified) for m in node.members) if t is not None)
    return times[node.threshold - 1] if len(times) >= node.threshold else None


def _policy_key(text: str, what: str, lineno: int) -> bytes:
    key = _hex(text, 32)
    if key is None:
        raise PolicyError(f"line {lineno}: {what} must be 64 hex characters (a raw Ed25519 public key)")
    if is_small_order_encoding(key):
        raise PolicyError(f"line {lineno}: {what} is a small-order point; anyone can forge signatures for it")
    return key


def parse_policy(data: bytes) -> AnchorPolicy:
    """Parse ``4gartha.anchor-policy/1``: Sigsum policy syntax (sigsum-go v0.14.1,
    doc/policy.md) plus exactly one ``anchor-origin`` and one ``anchor-key`` line.
    Stricter than Sigsum: at least one log, and ``quorum none`` is refused (a
    governance PASS always rests on witness cosignatures)."""
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy exceeds {MAX_POLICY_BYTES} bytes")
    for i, b in enumerate(data):
        if not (b in (0x09, 0x0A) or 0x20 <= b <= 0x7E or b >= 0x80):
            raise PolicyError(f"byte {i}: control character 0x{b:02x} (only tab and newline are allowed)")
    origin: Optional[str] = None
    anchor_key: Optional[bytes] = None
    logs: Dict[bytes, bytes] = {}
    witnesses: Dict[bytes, Witness] = {}
    names: Dict[str, Union[Group, Witness, None]] = {"none": None}
    used: Dict[str, str] = {"none": ""}
    quorum: Optional[Union[Group, Witness]] = None
    quorum_seen = False
    for lineno, raw in enumerate(data.split(b"\n"), 1):
        fields = [f.decode("utf-8", "surrogateescape") for f in re.split(rb"[ \t]+", raw.strip(b" \t")) if f]
        if not fields or fields[0].startswith("#"):
            continue
        kw, args = fields[0], fields[1:]
        if kw == "anchor-origin":
            if origin is not None or len(args) != 1:
                raise PolicyError(f"line {lineno}: exactly one 'anchor-origin <origin>' line is required")
            problem = name_problem(args[0])
            if problem:
                raise PolicyError(f"line {lineno}: anchor origin {problem}")
            origin = args[0]
        elif kw == "anchor-key":
            if anchor_key is not None or len(args) != 1:
                raise PolicyError(f"line {lineno}: exactly one 'anchor-key <hex public key>' line is required")
            anchor_key = _policy_key(args[0], "anchor key", lineno)
        elif kw == "log":
            if not 1 <= len(args) <= 2:
                raise PolicyError(f"line {lineno}: 'log <hex public key> [url]'")
            key = _policy_key(args[0], "log key", lineno)
            if sigsum_key_hash(key) in logs:
                raise PolicyError(f"line {lineno}: duplicate log")
            logs[sigsum_key_hash(key)] = key
        elif kw == "witness":
            if not 2 <= len(args) <= 3:
                raise PolicyError(f"line {lineno}: 'witness <name> <hex public key> [url]'")
            name = args[0]
            if name in names:
                raise PolicyError(f"line {lineno}: duplicate name {name!r}")
            key = _policy_key(args[1], "witness key", lineno)
            if sigsum_key_hash(key) in witnesses:
                raise PolicyError(f"line {lineno}: duplicate witness key")
            w = Witness(name, key)
            witnesses[w.key_hash] = w
            names[name] = w
        elif kw == "group":
            if len(args) < 3:
                raise PolicyError(f"line {lineno}: 'group <name> <all|any|k> <member>...'")
            name, k_text, members = args[0], args[1], args[2:]
            if name in names:
                raise PolicyError(f"line {lineno}: duplicate name {name!r}")
            if k_text == "all":
                k = len(members)
            elif k_text == "any":
                k = 1
            elif _DECIMAL_RE.fullmatch(k_text):
                k = _decimal(k_text)   # bounded before conversion
                if k is None:
                    raise PolicyError(f"line {lineno}: threshold {_clip(k_text)} out of range for "
                                      f"{len(members)} member(s)")
            else:
                raise PolicyError(f"line {lineno}: threshold {_clip(k_text)!r} is not all, any or a decimal")
            if not 1 <= k <= len(members):
                raise PolicyError(f"line {lineno}: threshold {k} out of range for {len(members)} member(s)")
            nodes = []
            for m in members:
                if m in used:
                    raise PolicyError(f"line {lineno}: {m!r} cannot be a member here"
                                      + (f" (already a member of {used[m]!r})" if used[m] else ""))
                if m not in names:
                    raise PolicyError(f"line {lineno}: undefined name {m!r} (define it on an earlier line)")
                used[m] = name
                nodes.append(names[m])
            g = Group(name, k, tuple(nodes))  # type: ignore[arg-type]
            names[name] = g
        elif kw == "quorum":
            if quorum_seen or len(args) != 1:
                raise PolicyError(f"line {lineno}: exactly one 'quorum <name>' line is required")
            quorum_seen = True
            if args[0] == "none":
                raise PolicyError(f"line {lineno}: 'quorum none' is not accepted for anchoring: "
                                  "a governance PASS requires witness cosignatures")
            if args[0] not in names:
                raise PolicyError(f"line {lineno}: undefined name {args[0]!r}")
            quorum = names[args[0]]
        else:
            raise PolicyError(f"line {lineno}: unknown keyword {kw!r}")
    if origin is None:
        raise PolicyError("no 'anchor-origin' line")
    if anchor_key is None:
        raise PolicyError("no 'anchor-key' line")
    if not logs:
        raise PolicyError("no 'log' line: at least one Sigsum log is required")
    if quorum is None:
        raise PolicyError("no 'quorum' line")
    return AnchorPolicy(origin, anchor_key, logs, witnesses, quorum, hashlib.sha256(data).hexdigest())


def load_policy(path: Path) -> AnchorPolicy:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyError(f"{p}: policy exceeds {MAX_POLICY_BYTES} bytes")
        data = p.read_bytes()
    except OSError as e:
        raise PolicyError(f"cannot read anchor policy {p}: {e}") from None
    try:
        return parse_policy(data)
    except PolicyError as e:
        raise PolicyError(f"{p}: {e}") from None


# --- the anchor log in a repository -------------------------------------------


def anchors_dir(repo_root: Path) -> Path:
    return repo_root / "ledger" / "anchors"


def batch_name(size: int) -> str:
    return f"{size:012d}"


def leaves_document(previous_size: int, rids: Sequence[str]) -> bytes:
    return canonical.encode({"previous_size": previous_size, "protocol": PROTOCOL, "records": list(rids)})


def parse_leaves(data: bytes) -> Tuple[int, Tuple[str, ...]]:
    """(previous_size, record IDs) of a canonical leaves.json, or FormatError."""
    try:
        doc = canonical.decode(data)
    except canonical.CanonicalError as e:
        raise FormatError(f"leaves.json is not canonical JSON: {e}") from None
    if not isinstance(doc, dict) or set(doc) != {"previous_size", "protocol", "records"}:
        raise FormatError("leaves.json must be an object with exactly previous_size, protocol and records")
    if doc["protocol"] != PROTOCOL:
        raise FormatError(f"leaves.json protocol is {doc['protocol']!r}, expected {PROTOCOL!r}")
    prev = doc["previous_size"]
    if type(prev) is not int or prev < 0:
        raise FormatError("leaves.json previous_size must be a non-negative integer")
    rids = doc["records"]
    if not isinstance(rids, list) or not rids:
        raise FormatError("leaves.json records must be a non-empty array")
    if len(rids) > MAX_BATCH_RECORDS:
        raise FormatError(f"leaves.json lists more than {MAX_BATCH_RECORDS} records")
    for rid in rids:
        if not records.is_digest(rid):
            raise FormatError(f"leaves.json lists {rid!r}, which is not a record ID (64 lowercase hex)")
    if any(a >= b for a, b in zip(rids, rids[1:])):
        raise FormatError("leaves.json records are not strictly ascending (sorted, without duplicates)")
    return prev, tuple(rids)


@dataclass
class Batch:
    name: str
    size: int
    previous_size: Optional[int] = None
    records: Tuple[str, ...] = ()
    note: Optional[Note] = None
    body: Optional[CheckpointBody] = None
    proof: Optional[SigsumProof] = None
    has_proof_file: bool = False
    inclusion_problem: Optional[str] = None
    sound: bool = False   # every file present and well-formed
    errors: List[str] = field(default_factory=list)   # this batch's directory or files could not be read


@dataclass
class CheckpointTrust:
    size: int
    status: Status
    reasons: Tuple[str, ...] = ()
    time: Optional[int] = None
    log_key_hash: Optional[bytes] = None
    witnesses: Tuple[str, ...] = ()   # policy witnesses that cosigned no later than time

    def to_dict(self) -> Dict[str, object]:
        return {
            "size": self.size, "status": self.status.value, "reasons": list(self.reasons),
            "anchored_no_later_than": self.time,
            "anchored_no_later_than_utc": utc(self.time) if self.time is not None else None,
            "log_key_hash": self.log_key_hash.hex() if self.log_key_hash else None,
            "witnesses": list(self.witnesses),
        }


@dataclass
class Audit:
    batches: List[Batch] = field(default_factory=list)
    positions: Dict[str, int] = field(default_factory=dict)
    size: int = 0
    origin: Optional[str] = None
    fail: List[str] = field(default_factory=list)
    error: List[str] = field(default_factory=list)
    policy: Optional[AnchorPolicy] = None
    crypto: bool = False
    trust: List[CheckpointTrust] = field(default_factory=list)


def _read_error(a: Audit, b: Optional[Batch], message: str) -> None:
    a.error.append(message)
    if b is not None:
        b.errors.append(message)


def _read_regular(path: Path, limit: int, a: Audit, label: str, b: Optional[Batch] = None) -> Optional[bytes]:
    try:
        st = os.lstat(path)
    except OSError as e:
        _read_error(a, b, f"{label}: cannot stat: {e}")
        return None
    if not stat.S_ISREG(st.st_mode):
        a.fail.append(f"{label}: not a regular file")
        return None
    if st.st_size > limit:
        a.fail.append(f"{label}: exceeds {limit} bytes")
        return None
    try:
        return path.read_bytes()
    except OSError as e:
        _read_error(a, b, f"{label}: cannot read: {e}")
        return None


def _scan(repo_root: Path, a: Audit) -> None:
    adir = anchors_dir(repo_root)
    try:
        st = os.lstat(adir)
    except FileNotFoundError:
        return  # no anchor log: nothing has been anchored
    except OSError as e:
        a.error.append(f"ledger/anchors: cannot stat: {e}")
        return
    if not stat.S_ISDIR(st.st_mode):
        a.fail.append("ledger/anchors is not a directory")
        return
    try:
        names = sorted(os.listdir(adir))
    except OSError as e:
        a.error.append(f"ledger/anchors: cannot list: {e}")
        return
    for name in names:
        path = adir / name
        try:
            mode = os.lstat(path).st_mode
        except OSError as e:
            a.error.append(f"ledger/anchors/{name}: cannot stat: {e}")
            continue
        if name == KEEP_FILE and stat.S_ISREG(mode):
            continue
        if BATCH_NAME_RE.fullmatch(name) is None or not stat.S_ISDIR(mode):
            a.fail.append(f"ledger/anchors/{name!r}: unexpected entry (only .keep and <12-digit tree size>/ directories)")
            continue
        size = int(name)
        b = Batch(name, size)
        a.batches.append(b)
        label = f"anchor batch {name}"
        if size == 0:
            a.fail.append(f"{label}: tree size 0 (a batch adds at least one record)")
            continue
        try:
            files = sorted(os.listdir(path))
        except OSError as e:
            _read_error(a, b, f"{label}: cannot list: {e}")
            continue
        extra = [f for f in files if f not in (LEAVES_FILE, CHECKPOINT_FILE, PROOF_FILE)]
        missing = [f for f in (LEAVES_FILE, CHECKPOINT_FILE) if f not in files]
        for f in extra:
            a.fail.append(f"{label}: unexpected file {f!r}")
        for f in missing:
            a.fail.append(f"{label}: missing {f}")
        ok = not extra and not missing
        if LEAVES_FILE in files:
            data = _read_regular(path / LEAVES_FILE, MAX_LEAVES_BYTES, a, f"{label}/{LEAVES_FILE}", b)
            if data is None:
                ok = False
            else:
                try:
                    b.previous_size, b.records = parse_leaves(data)
                except FormatError as e:
                    a.fail.append(f"{label}: {e}")
                    ok = False
                else:
                    if b.previous_size + len(b.records) != size:
                        a.fail.append(f"{label}: previous_size {b.previous_size} plus {len(b.records)} record(s) "
                                      f"is not the directory's tree size {size}")
                        ok = False
        if CHECKPOINT_FILE in files:
            data = _read_regular(path / CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES, a, f"{label}/{CHECKPOINT_FILE}", b)
            if data is None:
                ok = False
            else:
                try:
                    b.note = parse_note(data)
                    b.body = parse_checkpoint_body(b.note.text)
                except FormatError as e:
                    a.fail.append(f"{label}: checkpoint: {e}")
                    ok = False
        if PROOF_FILE in files:
            b.has_proof_file = True
            data = _read_regular(path / PROOF_FILE, MAX_PROOF_BYTES, a, f"{label}/{PROOF_FILE}", b)
            if data is None:
                ok = False
            else:
                try:
                    b.proof = parse_sigsum_proof(data)
                except FormatError as e:
                    a.fail.append(f"{label}: sigsum.proof: {e}")
                    ok = False
        b.sound = ok
    a.batches.sort(key=lambda b: b.size)


def _check_structure(repo_root: Path, a: Audit, check_records: bool) -> None:
    if not a.batches or not all(b.sound for b in a.batches):
        if a.batches and not a.fail and not a.error:
            a.fail.append("anchor log is malformed")
        return
    expected = 0
    for b in a.batches:
        if b.previous_size != expected:
            a.fail.append(f"anchor batch {b.name}: previous_size {b.previous_size}, but the log before it ends at "
                          f"size {expected} (batches must be contiguous)")
        expected = b.size
        for i, rid in enumerate(b.records):
            if rid in a.positions:
                a.fail.append(f"anchor batch {b.name}: record {rid} was already anchored at leaf {a.positions[rid]}")
            else:
                a.positions[rid] = (b.previous_size or 0) + i
    if a.fail:
        return  # positions and roots would not be meaningful
    a.size = a.batches[-1].size
    tree = Tree()
    origins = set()
    for b in a.batches:
        for rid in b.records:
            tree.append(leaf_hash(record_leaf(rid)))
        assert b.body is not None and b.note is not None
        origins.add(b.body.origin)
        root = tree.root()
        # parse_checkpoint_body admits only the canonical text, so equal fields
        # mean the note text is exactly checkpoint_body(origin, size, root).
        if b.body.size != b.size:
            a.fail.append(f"anchor batch {b.name}: checkpoint is for tree size {b.body.size}")
        elif b.body.root != root:
            a.fail.append(f"anchor batch {b.name}: checkpoint root hash {b.body.root.hex()} does not match the root "
                          f"{root.hex()} recomputed from leaves.json")
        if b.proof is not None:
            b.inclusion_problem = sigsum_inclusion_problem(b.proof, b.note.text)
            if b.inclusion_problem:
                a.fail.append(f"anchor batch {b.name}: sigsum.proof does not log this checkpoint: {b.inclusion_problem}")
    if len(origins) > 1:
        a.fail.append(f"anchor log checkpoints name {len(origins)} different origins: {sorted(origins)}")
    a.origin = a.batches[-1].body.origin if a.batches[-1].body else None
    if check_records:
        for rid in sorted(a.positions):
            loaded = records.load(repo_root, rid)
            if loaded.problem in ("missing", "invalid"):
                a.fail.append(f"anchored record {rid} (leaf {a.positions[rid]}) is "
                              + ("missing" if loaded.problem == "missing" else "not a valid record")
                              + ": " + "; ".join(loaded.errors))
            elif loaded.problem == "io":
                a.error.append(f"anchored record {rid}: " + "; ".join(loaded.errors))


def note_signature_problems(note: Note, origin: str, public_key: bytes, crypto: bool) -> Tuple[List[str], List[str]]:
    """(fail, not_checked) reasons for the anchor key's signature on ``note``.
    signed-note rules: lines whose (key name, key ID) do not match the trusted
    key are ignored; a matching line MUST verify, or the note is rejected."""
    kid = note_key_id(origin, SIG_TYPE_ED25519, public_key)
    mine = [s for s in note.signatures if s.name == origin and s.key_id == kid]
    if not mine:
        return [], ["checkpoint carries no signature by the policy's anchor key (signatures by unknown keys are ignored)"]
    if len(mine[0].signature) != 64:
        return ["the checkpoint signature line for the policy's anchor key is not an Ed25519 signature"], []
    if crypto and not ed25519_verify(public_key, note.text, mine[0].signature):
        return ["checkpoint signature by the policy's anchor key does not verify"], []
    return [], []


@dataclass
class ProofTrust:
    fail: List[str] = field(default_factory=list)
    not_checked: List[str] = field(default_factory=list)
    verified: Dict[bytes, int] = field(default_factory=dict)   # witness key hash -> timestamp
    time: Optional[int] = None


def sigsum_proof_trust(p: SigsumProof, note_text: bytes, policy: AnchorPolicy, crypto: bool) -> ProofTrust:
    """Check a parsed Sigsum proof for ``note_text`` against ``policy``
    (doc/sigsum-proof.md steps 1-6), stricter than sigsum-go in one respect: an
    invalid cosignature by a policy witness is a FAIL even if the quorum is met
    without it, because contradictory evidence must never be skipped."""
    r = ProofTrust()
    problem = sigsum_inclusion_problem(p, note_text)
    if problem:
        r.fail.append(f"sigsum.proof does not log this checkpoint: {problem}")
    checksum = sigsum_checksum(sigsum_message(note_text))
    if p.leaf_key_hash != policy.anchor_key_hash:
        r.not_checked.append(f"Sigsum leaf is attributed to key hash {p.leaf_key_hash.hex()}, not the policy's anchor key")
    elif crypto and not ed25519_verify(policy.anchor_key, sigsum_leaf_signed_data(checksum), p.leaf_signature):
        r.fail.append("Sigsum leaf signature by the policy's anchor key does not verify for this checkpoint")
    log_key = policy.logs.get(p.log_key_hash)
    if log_key is None:
        r.not_checked.append(f"Sigsum log {p.log_key_hash.hex()} is not in the policy")
    elif crypto and not ed25519_verify(log_key, sigsum_tree_head_text(p.log_key_hash, p.size, p.root),
                                       p.tree_head_signature):
        r.fail.append(f"tree head signature by policy log {p.log_key_hash.hex()} does not verify")
    if not crypto:
        r.not_checked.append(f"Ed25519 verification is not installed ({INSTALL_HINT}); no signature was checked")
        return r
    for c in p.cosignatures:
        w = policy.witnesses.get(c.key_hash)
        if w is None:
            continue  # unknown witnesses are ignored, as in signed-note and Sigsum
        if ed25519_verify(w.public_key, sigsum_cosigned_data(p.log_key_hash, p.size, p.root, c.timestamp), c.signature):
            r.verified[c.key_hash] = c.timestamp
        else:
            r.fail.append(f"cosignature by policy witness {w.name!r} does not verify")
    r.time = quorum_time(policy.quorum, r.verified)
    if r.time is None:
        r.not_checked.append(f"witness quorum not met: {len(r.verified)} valid cosignature(s) by policy witnesses")
    return r


def _checkpoint_trust(b: Batch, policy: AnchorPolicy, crypto: bool) -> CheckpointTrust:
    """One checkpoint's evidence under ``policy``, from whatever of its batch
    was read. A file that could not be read makes the result ERROR, unless what
    was read already contradicts a key the policy trusts: FAIL > ERROR."""
    errors = list(b.errors)
    if b.note is None or b.body is None:
        # audit() evaluates trust only when nothing FAILs, so the checkpoint was not read.
        return CheckpointTrust(b.size, Status.ERROR, tuple(errors) or (f"{CHECKPOINT_FILE} was not read",))
    if b.has_proof_file and b.proof is None and not errors:
        errors.append(f"{PROOF_FILE} was not read")
    if b.body.origin != policy.origin:
        return CheckpointTrust(b.size, Status.ERROR if errors else Status.NOT_CHECKED, tuple(errors) + (
            f"checkpoint origin {b.body.origin!r} is not the policy's anchor origin {policy.origin!r}",))
    fail, nc = note_signature_problems(b.note, policy.origin, policy.anchor_key, crypto)
    pt = None
    if b.proof is None:
        if not b.has_proof_file:
            nc.append("no sigsum.proof: the checkpoint has not been shown to be externally logged")
        if not crypto:
            nc.append(f"Ed25519 verification is not installed ({INSTALL_HINT}); no signature was checked")
    else:
        pt = sigsum_proof_trust(b.proof, b.note.text, policy, crypto)
        fail += pt.fail
        nc += pt.not_checked
    if fail:
        return CheckpointTrust(b.size, Status.FAIL, tuple(fail + errors + nc))
    if errors:
        return CheckpointTrust(b.size, Status.ERROR, tuple(errors + nc))
    if nc or pt is None or pt.time is None:
        return CheckpointTrust(b.size, Status.NOT_CHECKED, tuple(nc))
    names = tuple(sorted(policy.witnesses[kh].name for kh, ts in pt.verified.items() if ts <= pt.time))
    return CheckpointTrust(b.size, Status.PASS, (), pt.time, b.proof.log_key_hash, names)  # type: ignore[union-attr]


def audit(repo_root: Path, policy: Optional[AnchorPolicy] = None, *, check_records: bool = True) -> Audit:
    """Check the whole anchor log; with a policy, also every checkpoint's trust."""
    a = Audit(policy=policy, crypto=ed25519_available())
    _scan(repo_root, a)
    _check_structure(repo_root, a, check_records)
    if policy is not None and not a.fail:
        # Also when files could not be read: each checkpoint's own evidence is
        # still checked, so a contradiction in what was read is a FAIL.
        a.trust = [_checkpoint_trust(b, policy, a.crypto) for b in a.batches]
    return a


def integrity_outcome(a: Audit) -> Outcome:
    if a.fail:
        return Outcome(Status.FAIL, f"{len(a.fail)} problem(s) in the anchor log", tuple(a.fail + a.error))
    if a.error:
        return Outcome(Status.ERROR, f"{len(a.error)} anchor check(s) could not complete", tuple(a.error))
    if not a.batches:
        return Outcome(Status.NOT_APPLICABLE, "the anchor log is empty: nothing has been anchored")
    proofs = sum(1 for b in a.batches if b.proof is not None)
    return Outcome(Status.PASS,
                   f"{len(a.batches)} batch(es) contiguous; {len(a.batches)} checkpoint root(s) recomputed from "
                   f"leaves.json; {proofs} Sigsum proof(s) include their checkpoint; {len(a.positions)} anchored "
                   "record(s) present and valid (no signature or trust was checked)")


def _log_fail_or_error(a: Audit) -> Optional[Outcome]:
    """The whole log's FAIL or ERROR, if any, with FAIL > ERROR (ASSURANCE.md
    2): a contradiction in the files, or in a checkpoint's evidence under the
    policy, outranks a file that could not be read. None if neither."""
    integ = integrity_outcome(a)
    if integ.status is Status.FAIL:
        return Outcome(Status.FAIL, f"anchor log: {integ.detail}", integ.problems)
    failing = [t for t in a.trust if t.status is Status.FAIL]
    if failing:
        fails = [f"checkpoint {batch_name(t.size)}: {r}" for t in failing for r in t.reasons]
        listed = {r for t in failing for r in t.reasons}
        return Outcome(Status.FAIL, f"{len(fails)} problem(s) with checkpoint evidence",
                       tuple(fails) + tuple(e for e in a.error if e not in listed))
    if integ.status is Status.ERROR:
        return Outcome(Status.ERROR, f"anchor log: {integ.detail}", integ.problems)
    return None


def trust_outcome(a: Audit) -> Outcome:
    """Whole-log trust: PASS iff every leaf is covered by a trusted checkpoint."""
    failed = _log_fail_or_error(a)
    if failed is not None:
        return failed
    if a.policy is None:
        return Outcome(Status.NOT_CHECKED, "no anchor policy supplied (a policy in the repository is never used)")
    if not a.batches:
        return Outcome(Status.NOT_CHECKED, "the anchor log is empty: nothing is anchored")
    covered = max((t.size for t in a.trust if t.status is Status.PASS), default=0)
    if covered == a.size:
        last = next(t for t in a.trust if t.size == covered)
        return Outcome(Status.PASS, f"all {a.size} leaves covered by trusted checkpoint {batch_name(covered)}, "
                                    f"logged no later than {describe_time(last.time)}")  # type: ignore[arg-type]
    reasons = tuple(f"checkpoint {batch_name(t.size)}: {r}" for t in a.trust if t.size > covered for r in t.reasons)
    detail = f"{covered} of {a.size} leaves covered by trusted, externally logged checkpoints"
    if not a.crypto:
        detail += f"; Ed25519 verification is not installed ({INSTALL_HINT})"
    return Outcome(Status.NOT_CHECKED, detail, reasons)


SCOPE = ("inclusion no later than T only: not freshness, completeness, absence of forks, "
         "when records were created, or that their content is true (ASSURANCE.md 5.7)")


def governance_outcome(repo_root: Path, lineage: Sequence[str], policy: AnchorPolicy) -> Outcome:
    """Governance for a lineage whose integrity already PASSed (verifier.py)."""
    a = audit(repo_root, policy)
    failed = _log_fail_or_error(a)
    if failed is not None:
        return failed
    lineage = sorted(set(lineage))
    missing = [rid for rid in lineage if rid not in a.positions]
    if missing:
        return Outcome(Status.NOT_CHECKED,
                       f"{len(missing)} of {len(lineage)} lineage record(s) not yet anchored "
                       f"(anchor log size {a.size})", tuple(f"not anchored: {rid}" for rid in missing))
    needed = max(a.positions[rid] for rid in lineage) + 1
    candidates = [t for t in a.trust if t.size >= needed]
    chosen = next((t for t in candidates if t.status is Status.PASS), None)
    if chosen is None:
        detail = (f"no checkpoint covering the lineage (tree size >= {needed}) has trusted, "
                  "externally logged evidence")
        if not a.crypto:
            detail = f"Ed25519 verification is not installed ({INSTALL_HINT}); " + detail
        return Outcome(Status.NOT_CHECKED, detail,
                       tuple(f"checkpoint {batch_name(t.size)}: {r}" for t in candidates for r in t.reasons))
    assert chosen.time is not None and chosen.log_key_hash is not None
    return Outcome(
        Status.PASS,
        f"{len(lineage)} lineage record(s) in checkpoint {batch_name(chosen.size)} of {policy.origin}, "
        f"logged in Sigsum log {chosen.log_key_hash.hex()[:16]} and cosigned by a witness quorum "
        f"no later than {describe_time(chosen.time)}; {SCOPE}",
        (),
        {
            "policy_sha256": policy.sha256,
            "origin": policy.origin,
            "checkpoint_size": chosen.size,
            "anchor_log_size": a.size,
            "log_key_hash": chosen.log_key_hash.hex(),
            "anchored_no_later_than": chosen.time,
            "anchored_no_later_than_utc": utc(chosen.time),   # None after 9999-12-31T23:59:59Z
            "quorum_witnesses": list(chosen.witnesses),
            "scope": SCOPE,
        },
    )


# --- writing a batch (ledger anchor create) -----------------------------------


def stored_record_ids(repo_root: Path) -> List[str]:
    rdir = records.records_dir(repo_root)
    try:
        names = sorted(os.listdir(rdir))
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        if name == KEEP_FILE:
            continue
        rid = name[: -len(".json")] if name.endswith(".json") else ""
        if not records.is_digest(rid):
            raise AnchorRefused(f"unexpected file in ledger/records: {name!r}")
        out.append(rid)
    return out


def plan_batch(repo_root: Path) -> Tuple[Audit, List[str]]:
    """The audited current log, and the records a new batch would add (sorted)."""
    a = audit(repo_root)
    if a.fail or a.error:
        raise AnchorRefused("the existing anchor log does not pass integrity:\n  "
                            + "\n  ".join(a.fail + a.error))
    new = sorted(set(stored_record_ids(repo_root)) - set(a.positions))
    return a, new


def write_batch(repo_root: Path, a: Audit, new: Sequence[str], signer: Signer,
                origin: Optional[str] = None) -> Tuple[Path, int, bytes]:
    """Write leaves.json and the signed checkpoint for ``new`` (the caller has
    checked that every new record passes the integrity profile). Never
    overwrites: the batch directory is created exclusively."""
    if not new:
        raise AnchorRefused("nothing to anchor: every stored record is already in the anchor log")
    if list(new) != sorted(set(new)):
        raise AnchorRefused("internal error: batch records must be sorted and unique")
    if a.origin is not None and origin is not None and origin != a.origin:
        raise AnchorRefused(f"--origin {origin!r} differs from the anchor log's origin {a.origin!r}")
    origin = origin or a.origin
    if origin is None:
        raise AnchorRefused("the anchor log is empty: pass --origin for its first checkpoint")
    problem = name_problem(origin)
    if problem:
        raise AnchorRefused(f"origin {problem}")
    size = a.size + len(new)
    if size > MAX_LOG_SIZE or len(new) > MAX_BATCH_RECORDS:
        raise AnchorRefused("batch too large")
    tree = Tree()
    for b in a.batches:
        for rid in b.records:
            tree.append(leaf_hash(record_leaf(rid)))
    for rid in new:
        tree.append(leaf_hash(record_leaf(rid)))
    root = tree.root()
    leaves = leaves_document(a.size, new)
    note = signed_checkpoint(origin, size, root, signer)
    adir = anchors_dir(repo_root)
    adir.mkdir(parents=True, exist_ok=True)
    bdir = adir / batch_name(size)
    try:
        bdir.mkdir()
    except FileExistsError:
        raise AnchorRefused(f"{bdir} already exists") from None
    for name, data in ((LEAVES_FILE, leaves), (CHECKPOINT_FILE, note)):
        with open(bdir / name, "xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    return bdir, size, root
