"""P1 — Canonical string handling.

Sprint-1 scope is deliberately narrow: provide deterministic normalization primitives
that can be used by higher layers without importing policy.
"""

from __future__ import annotations

import unicodedata


def normalize_string(s: str) -> str:
    """Return a canonicalized string.

    Rules (Sprint-1):
      - input must be `str`
      - Unicode normalization: NFC

    No trimming, case folding, or locale behavior is introduced at this layer.
    """

    if not isinstance(s, str):
        raise TypeError(f"expected str, got {type(s).__name__}")
    return unicodedata.normalize("NFC", s)
