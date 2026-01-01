from __future__ import annotations

from ledger.cas import sha256_bytes

def test_sha256_bytes_stable():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
