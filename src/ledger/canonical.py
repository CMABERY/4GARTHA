"""Canonical JSON encoding for identity-bearing ledger records.

A record's identity is a hash over its canonical bytes, so every value must
have exactly one encoding. Anything that would need a normalization policy is
*rejected*, never normalized (silent normalization would let two different
inputs share an identity, or one input acquire two):

  - floats, NaN and Infinity            (no portable canonical form)
  - integers outside +/-(2**53 - 1)     (not exact in IEEE-754 doubles)
  - strings that are not NFC-normalized (visually equal, byte-different)
  - strings containing lone surrogates  (not encodable as UTF-8)
  - object keys that are not ASCII      (keeps code-point key order equal to
                                         the UTF-16 order other JSON
                                         canonicalizations use)
  - duplicate object keys, a UTF-8 BOM, non-UTF-8 bytes (when decoding)
  - nesting deeper than MAX_DEPTH

Encoding: UTF-8; object keys sorted; separators "," and ":" with no
whitespace; non-ASCII characters emitted literally (ensure_ascii=False); no
trailing newline. ``decode`` accepts only bytes that ``encode`` would produce.
"""
from __future__ import annotations

import json
import unicodedata
from typing import Any, List

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 32


class CanonicalError(ValueError):
    """The value or bytes have no (or not this) canonical encoding."""


def problems(obj: Any, path: str = "$", _depth: int = 0) -> List[str]:
    """Return every reason ``obj`` cannot be canonically encoded (empty == ok)."""
    if _depth > MAX_DEPTH:
        return [f"{path}: nesting deeper than {MAX_DEPTH}"]
    if obj is None or isinstance(obj, bool):
        return []
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INTEGER:
            return [f"{path}: integer outside +/-(2**53 - 1)"]
        return []
    if isinstance(obj, float):
        return [f"{path}: floats are not permitted in canonical records"]
    if isinstance(obj, str):
        return _string_problems(obj, path)
    if isinstance(obj, list):
        out: List[str] = []
        for i, item in enumerate(obj):
            out.extend(problems(item, f"{path}[{i}]", _depth + 1))
        return out
    if isinstance(obj, dict):
        out = []
        for key, value in obj.items():
            if not isinstance(key, str):
                out.append(f"{path}: object key {key!r} is not a string")
                continue
            if not key.isascii():
                out.append(f"{path}: object key {key!r} is not ASCII")
            out.extend(_string_problems(key, f"{path} key {key!r}"))
            out.extend(problems(value, f"{path}.{key}", _depth + 1))
        return out
    return [f"{path}: {type(obj).__name__} is not a JSON value"]


def _string_problems(s: str, path: str) -> List[str]:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return [f"{path}: string is not valid Unicode (lone surrogate)"]
    if not unicodedata.is_normalized("NFC", s):
        return [f"{path}: string is not NFC-normalized"]
    return []


def encode(obj: Any) -> bytes:
    """Canonical bytes for ``obj``; raises CanonicalError if it has none."""
    errs = problems(obj)
    if errs:
        raise CanonicalError("; ".join(errs))
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_duplicates(pairs: List[Any]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate object key {key!r}")
        out[key] = value
    return out


def _reject_float(text: str) -> Any:
    raise CanonicalError(f"floats are not permitted in canonical records: {text}")


def _reject_constant(text: str) -> Any:
    raise CanonicalError(f"{text} is not permitted in canonical records")


def parse_strict(text: str) -> Any:
    """Parse JSON text, rejecting what canonical records cannot hold
    (duplicate keys, floats, NaN/Infinity) and then any other canonical
    problem. Unlike ``decode`` the text itself need not be canonical."""
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalError:
        raise
    except RecursionError:
        raise CanonicalError("nesting too deep") from None
    except ValueError as e:
        raise CanonicalError(f"not JSON: {e}") from None
    errs = problems(obj)
    if errs:
        raise CanonicalError("; ".join(errs))
    return obj


def decode(data: bytes) -> Any:
    """Parse ``data`` and require it to be exactly the canonical encoding."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalError("UTF-8 byte-order mark is not permitted")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CanonicalError(f"not UTF-8: {e}") from None
    obj = parse_strict(text)
    if encode(obj) != data:
        raise CanonicalError("bytes are valid JSON but not the canonical encoding")
    return obj
