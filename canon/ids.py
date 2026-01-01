"""P2 — Canonical bytes + deterministic hashing.

Sprint-1 fencepost primitives:
  - `canon_json_bytes`: deterministic JSON-to-bytes encoding.
  - `sha256_prefixed`: stable, self-describing digest string.

This layer is intentionally policy-free: it defines *how* bytes are hashed,
not *what* should be hashed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canon_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON bytes.

    Encoding (Sprint-1):
      - UTF-8
      - keys sorted
      - separators without whitespace
      - ensure_ascii = False (preserve Unicode)

    Note: float canonicalization (NaN/-0.0) is domain policy and out of scope.
    """

    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_prefixed(data: bytes, prefix: str = "sha256") -> str:
    """Return a stable digest string.

    Format: "<prefix>:<64-hex>" (prefix defaults to "sha256").
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256_prefixed expects bytes-like input")
    return f"{prefix}:{sha256_hex(bytes(data))}"


def is_sha256_prefixed(s: str, prefix: str = "sha256") -> bool:
    if not isinstance(s, str):
        return False
    if not s.startswith(prefix + ":"):
        return False
    hexpart = s.split(":", 1)[1]
    if len(hexpart) != 64:
        return False
    return all(c in "0123456789abcdef" for c in hexpart)
