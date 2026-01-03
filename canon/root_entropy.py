"""Shared canonicalization utilities for root entropy fixtures.

This module provides common functions for canonical JSON processing
used by both ingest and verification scripts.
"""

import json
import hashlib
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """Produce canonical JSON bytes with sorted keys and compact separators.
    
    This follows RFC 8785-style canonicalization with:
    - Sorted keys (sort_keys=True)
    - Compact separators (',', ':')
    - UTF-8 encoding without ASCII escaping
    
    Args:
        obj: Any JSON-serializable Python object
        
    Returns:
        Canonical JSON representation as UTF-8 bytes
    """
    s = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return s.encode('utf-8')


def sha256_hex(data: bytes) -> str:
    """Compute SHA256 hex digest of bytes.
    
    Args:
        data: Input bytes to hash
        
    Returns:
        Hex string representation of SHA256 digest (64 characters)
    """
    return hashlib.sha256(data).hexdigest()
