"""ledger.anchor unit behaviour and the `ledger anchor` commands (C10 has the
assurance-level cases; this file covers the mechanics around them)."""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
from pathlib import Path

import pytest

from ledger import anchor as A

from ledger_testutil import PYTHON, REPO, admit, cli_env, init_repo, run_cli, write_record_raw

needs_ed25519 = pytest.mark.skipif(not A.ed25519_available(), reason="needs the [anchor] extra (cryptography)")

if A.ed25519_available():
    from anchor_testutil import F, K, ORIGIN, anchor_batch, anchored_repo, batch_dir, log_batch, note_text, write_policy


# --- Merkle tree ----------------------------------------------------------------


def test_compact_tree_matches_the_recursive_definition_and_paths_verify() -> None:
    rng = random.Random(6962)
    leaves = [A.leaf_hash(rng.randbytes(32)) for _ in range(70)]
    tree = A.Tree()
    for n in range(1, len(leaves) + 1):
        tree.append(leaves[n - 1])
        assert tree.root() == A.root_of(leaves[:n]), n
    for n in (1, 2, 3, 5, 8, 13, 31, 32, 33, 64, 70):
        root = A.root_of(leaves[:n])
        for i in {0, n - 1, n // 2, rng.randrange(n)}:
            path = A.inclusion_path(i, leaves[:n])
            assert A.verify_inclusion(leaves[i], i, n, root, path) is None
            assert A.verify_inclusion(leaves[i], i, n, root, path + [bytes(32)]) is not None
            if n > 1:
                assert A.verify_inclusion(leaves[i], (i + 1) % n, n, root, path) is not None


def test_leaves_are_raw_record_ids_and_nodes_are_domain_separated() -> None:
    rid = "ab" * 32
    assert A.leaf_hash(A.record_leaf(rid)) == hashlib.sha256(b"\x00" + bytes.fromhex(rid)).digest()
    l, r = A.leaf_hash(b"l"), A.leaf_hash(b"r")
    assert A.node_hash(l, r) == hashlib.sha256(b"\x01" + l + r).digest()
    with pytest.raises(ValueError):
        A.record_leaf("AB" * 32)


# --- quorum time ----------------------------------------------------------------


def _w(name: str) -> A.Witness:
    return A.Witness(name, hashlib.sha256(name.encode()).digest())


def test_quorum_time_is_when_the_quorum_was_first_satisfied() -> None:
    w = {n: _w(n) for n in ("a", "b", "c", "d", "e")}
    t = lambda **ts: {w[n].key_hash: v for n, v in ts.items()}  # noqa: E731
    two_of_three = A.Group("g", 2, (w["a"], w["b"], w["c"]))
    assert A.quorum_time(two_of_three, t(a=30, b=10, c=20)) == 20
    assert A.quorum_time(two_of_three, t(a=30, b=10)) == 30
    assert A.quorum_time(two_of_three, t(b=10)) is None
    nested = A.Group("all", 2, (two_of_three, A.Group("any", 1, (w["d"], w["e"]))))
    assert A.quorum_time(nested, t(a=30, b=10, c=20, d=50, e=40)) == 40
    assert A.quorum_time(nested, t(a=30, b=10, c=20)) is None
    assert A.quorum_time(w["a"], t(a=7)) == 7


# --- small-order keys -------------------------------------------------------------


@needs_ed25519
def test_small_order_keys_admit_forgeries_and_policies_refuse_them() -> None:
    # Why the blocklist exists: under each listed encoding OpenSSL accepts a
    # signature nobody computed (R = identity, S = 0) for some messages.
    identity = (1).to_bytes(32, "little")
    forged = identity + bytes(32)
    for y in A._SMALL_ORDER_Y:
        for sign in (0, 1):
            key = bytearray(y.to_bytes(32, "little"))
            key[31] = (key[31] & 0x7F) | (sign << 7)
            key = bytes(key)
            assert A.is_small_order_encoding(key)
            assert any(A.ed25519_verify(key, b"m%d" % i, forged) for i in range(64)), (y, sign)
            text = F.policy_text().replace(K["w1"].public.hex(), key.hex())
            with pytest.raises(A.PolicyError, match="small-order"):
                A.parse_policy(text.encode())
    assert not A.is_small_order_encoding(K["anchor"].public)
    assert not any(A.ed25519_verify(K["anchor"].public, b"m%d" % i, forged) for i in range(64))


# --- parsing details not covered by the vectors -----------------------------------


def test_decimals_are_bounded_before_conversion() -> None:
    # int() raises ValueError past sys.get_int_max_str_digits() digits, so the
    # length is checked first; C10 covers the files that carry these decimals.
    assert A._decimal("0") == 0 and A._decimal(str(A.MAX_UINT63)) == A.MAX_UINT63
    # "\uff11" is a fullwidth digit one, which int() would accept.
    for bad in (str(A.MAX_UINT63 + 1), "1" + "0" * 19, "9" * 5000, "01", "", "+1", "1_000", "\uff11"):
        assert A._decimal(bad) is None, bad[:30]
    with pytest.raises(A.FormatError) as exc:
        A.parse_checkpoint_body(b"origin\n" + b"9" * 5000 + b"\n" + A.b64(bytes(32)).encode() + b"\n")
    assert "is not a canonical decimal" in str(exc.value) and len(str(exc.value)) < 200


@needs_ed25519
def test_policy_threshold_is_bounded_before_conversion(tmp_path: Path) -> None:
    text = F.policy_text()
    huge = text.replace("quorum-rule 2 ", "quorum-rule " + "9" * 5000 + " ")
    assert huge != text and len(huge) < A.MAX_POLICY_BYTES
    with pytest.raises(A.PolicyError, match="out of range") as exc:
        A.parse_policy(huge.encode())
    assert len(str(exc.value)) < 200
    root = init_repo(tmp_path / "repo")
    bad = tmp_path / "verifier" / "huge-threshold"
    bad.parent.mkdir()
    bad.write_text(huge)
    proc = run_cli(root, "anchor", "verify", "--anchor-policy", str(bad))
    assert proc.returncode == 1 and "invalid anchor policy" in proc.stderr, proc.stderr
    assert "Traceback" not in proc.stderr


def test_utc_formatting_covers_what_datetime_can_show_and_says_so_beyond() -> None:
    assert A.utc(0) == "1970-01-01T00:00:00Z"
    assert A.utc(1767225800) == "2026-01-01T00:03:20Z"
    assert A.utc(A.MAX_UTC_TIMESTAMP) == "9999-12-31T23:59:59Z"
    assert A.utc(A.MAX_UTC_TIMESTAMP + 1) is None and A.utc(A.MAX_UINT63) is None
    assert A.describe_time(A.MAX_UTC_TIMESTAMP) == "9999-12-31T23:59:59Z"
    assert A.describe_time(A.MAX_UINT63).startswith(f"Unix time {A.MAX_UINT63} ")


def test_canonical_base64_rejects_padding_bits_and_bad_alphabet() -> None:
    assert A.b64decode_canonical("AA==") == b"\x00"
    for bad in ("AB==", "AA=", "AA", "A===", "AA==\n", "-_8=", ""):
        assert A.b64decode_canonical(bad) is None, bad


def test_policy_names_are_opaque_bytes() -> None:
    kelvin = F.policy_text().replace("w1", "K").replace("quorum-rule 2 K", "quorum-rule 2 K")
    pol = A.parse_policy(kelvin.encode())
    assert {w.name for w in pol.witnesses.values()} == {"K", "w2", "w3"}
    with pytest.raises(A.PolicyError, match="undefined name 'K'"):
        A.parse_policy(kelvin.replace("quorum-rule 2 K", "quorum-rule 2 K").encode())


def test_policy_file_errors_are_reported_not_raised_as_os_errors(tmp_path: Path) -> None:
    with pytest.raises(A.PolicyError, match="cannot read anchor policy"):
        A.load_policy(tmp_path / "absent")
    big = tmp_path / "big"
    big.write_bytes(b"#" * (A.MAX_POLICY_BYTES + 1))
    with pytest.raises(A.PolicyError, match="exceeds"):
        A.load_policy(big)


def test_unknown_anchors_dir_kinds_are_reported(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    (root / "ledger" / "anchors").write_text("not a directory")
    a = A.audit(root)
    assert a.fail == ["ledger/anchors is not a directory"]
    assert A.integrity_outcome(a).status.value == "FAIL"


def test_absent_anchor_log_is_empty_not_an_error(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    a = A.audit(root)
    assert (a.fail, a.error, a.batches) == ([], [], [])
    assert A.integrity_outcome(a).status.value == "NOT_APPLICABLE"
    proc = run_cli(root, "anchor", "verify")
    assert proc.returncode == 0 and "the anchor log is empty" in proc.stdout


# --- ledger anchor create / verify / body ------------------------------------------


def _ssh_key(tmp_path: Path, name: str = "anchor-key") -> Path:
    """An unencrypted OpenSSH Ed25519 private key holding a known test seed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(K["anchor"].seed)
    path = tmp_path / name
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                       serialization.NoEncryption()))
    return path


def _pkcs8_key(tmp_path: Path) -> Path:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(K["anchor"].seed)
    path = tmp_path / "anchor.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return path


@needs_ed25519
@pytest.mark.parametrize("key_format", ["openssh", "pkcs8"])
def test_anchor_create_then_log_then_verify(tmp_path: Path, key_format: str) -> None:
    root = init_repo(tmp_path / "repo")
    a = admit(root, b"one")
    b = admit(root, b"two")
    key = (_ssh_key if key_format == "openssh" else _pkcs8_key)(tmp_path)
    proc = run_cli(root, "anchor", "create", "--key", str(key), "--origin", ORIGIN)
    assert proc.returncode == 0, proc.stderr
    assert "anchored 2 record(s): ledger/anchors/000000000002" in proc.stdout
    assert K["anchor"].public.hex() in proc.stdout
    leaves = json.loads((batch_dir(root, 2) / A.LEAVES_FILE).read_text())
    assert leaves == {"previous_size": 0, "protocol": A.PROTOCOL, "records": sorted([a, b])}
    body = run_cli(root, "anchor", "body", "2")
    assert body.returncode == 0 and body.stdout.encode() == note_text(root, 2)
    assert A.sigsum_message(body.stdout.encode()) == hashlib.sha256(note_text(root, 2)).digest()
    integrity = run_cli(root, "anchor", "verify")
    assert integrity.returncode == 0 and "integrity                PASS" in integrity.stdout
    pol = write_policy(tmp_path / "verifier" / "policy")
    pending = run_cli(root, "anchor", "verify", "--anchor-policy", str(pol))
    assert pending.returncode == 2 and "no sigsum.proof" in pending.stdout
    log_batch(root, 2)
    done = run_cli(root, "anchor", "verify", "--anchor-policy", str(pol), "--json")
    assert done.returncode == 0, done.stdout
    doc = json.loads(done.stdout)
    assert doc["trust"]["status"] == "PASS" and doc["checkpoints"][0]["anchored_no_later_than"] == F.T0 + 200


@needs_ed25519
def test_anchor_create_refusals(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    key = _ssh_key(tmp_path)
    first = run_cli(root, "anchor", "create", "--key", str(key))
    assert first.returncode == 1 and "nothing to anchor" in first.stderr
    admit(root, b"one")
    proc = run_cli(root, "anchor", "create", "--key", str(key))
    assert proc.returncode == 1 and "pass --origin" in proc.stderr
    assert not (root / "ledger" / "anchors").exists() or not any((root / "ledger" / "anchors").iterdir())
    assert run_cli(root, "anchor", "create", "--key", str(key), "--origin", ORIGIN).returncode == 0
    admit(root, b"two")
    proc = run_cli(root, "anchor", "create", "--key", str(key), "--origin", "4gartha.test/other")
    assert proc.returncode == 1 and "differs from the anchor log's origin" in proc.stderr
    bad_key = tmp_path / "not-a-key"
    bad_key.write_text("hello")
    proc = run_cli(root, "anchor", "create", "--key", str(bad_key))
    assert proc.returncode == 1 and "cannot load the anchor key" in proc.stderr
    # A broken existing log is never extended.
    (batch_dir(root, 1) / A.LEAVES_FILE).write_bytes(b"{}")
    proc = run_cli(root, "anchor", "create", "--key", str(key))
    assert proc.returncode == 1 and "existing anchor log does not pass integrity" in proc.stderr
    assert not batch_dir(root, 2).exists()


@needs_ed25519
def test_anchor_create_refuses_records_that_fail_integrity(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    admit(root, b"one")
    write_record_raw(root, "0" * 64, "{not json")
    proc = run_cli(root, "anchor", "create", "--key", str(_ssh_key(tmp_path)), "--origin", ORIGIN)
    assert proc.returncode == 1 and "do not satisfy the integrity profile" in proc.stderr
    assert not A.anchors_dir(root).exists()


@needs_ed25519
def test_write_batch_never_overwrites(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    admit(root, b"one")
    a, new = A.plan_batch(root)
    batch_dir(root, 1).mkdir(parents=True)
    with pytest.raises(A.AnchorRefused, match="already exists"):
        A.write_batch(root, a, new, K["anchor"].signer, ORIGIN)
    assert list(batch_dir(root, 1).iterdir()) == []


@needs_ed25519
def test_anchor_verify_exit_codes(tmp_path: Path) -> None:
    root, a, d, size = anchored_repo(tmp_path / "repo")
    pol = write_policy(tmp_path / "verifier" / "policy")
    assert run_cli(root, "anchor", "verify", "--anchor-policy", str(pol)).returncode == 0
    (batch_dir(root, size) / A.LEAVES_FILE).write_bytes(b"{}")
    proc = run_cli(root, "anchor", "verify")
    assert proc.returncode == 2 and "integrity                FAIL" in proc.stdout
    bad_policy = tmp_path / "bad"
    bad_policy.write_text("quorum none\n")
    assert run_cli(root, "anchor", "verify", "--anchor-policy", str(bad_policy)).returncode == 1


@needs_ed25519
@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX permissions")
def test_unreadable_anchor_file_is_an_error_not_a_failure(tmp_path: Path) -> None:
    from ledger.assurance import Dimension, Status
    from ledger.verifier import verify
    from anchor_testutil import policy

    root, a, d, size = anchored_repo(tmp_path / "repo")
    proof = batch_dir(root, size) / A.PROOF_FILE
    proof.chmod(0)
    try:
        oc = verify(root, [d], anchor_policy=policy()).outcomes[Dimension.GOVERNANCE]
    finally:
        proof.chmod(0o644)
    assert oc.status is Status.ERROR and any("cannot read" in p for p in oc.problems)
