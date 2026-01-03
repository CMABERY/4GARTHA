#!/usr/bin/env python3
"""Ingest root_entropy fixture and produce node_id + canonical node_record.

This script reads a root_entropy commit fixture JSON file and produces a 
canonical node_record with its computed node_id (sha256 of canonical record).

Output format (JSON to stdout):
{
  "node_id": "sha256_hex_of_canonical_node_record",
  "node_record": { ... canonical fields ... }
}
"""

import json
import hashlib
import sys
from pathlib import Path
from typing import Any, Dict


def canonical_json_bytes(obj: Any) -> bytes:
    """Produce canonical JSON bytes with sorted keys and compact separators."""
    s = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return s.encode('utf-8')


def sha256_hex(data: bytes) -> str:
    """Compute SHA256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def ingest_root_entropy(fixture_path: Path) -> Dict[str, Any]:
    """
    Ingest a root_entropy fixture and produce node_id + node_record.
    
    Args:
        fixture_path: Path to commit_noquote.json fixture
        
    Returns:
        Dict with 'node_id' and 'node_record' keys
    """
    # Load the fixture
    with open(fixture_path, 'r', encoding='utf-8') as f:
        fixture = json.load(f)
    
    # Extract required fields from fixture
    algorithm = fixture.get('algorithm')
    entropy_length_bytes = int(fixture.get('entropy_length_bytes', 0))
    root_hash = fixture.get('root_hash')
    ak_pubkey_fp_sha256 = fixture.get('ak_pubkey_fp_sha256')
    tpm_quote_sha256 = fixture.get('tpm_quote_sha256')
    tpm_quote_nonce_sha256 = fixture.get('tpm_quote_nonce_sha256')
    
    # Construct canonical node_record (matching the signed statement structure)
    node_record = {
        "v": 1,
        "node_type": "root_entropy",
        "algorithm": algorithm,
        "entropy_length_bytes": entropy_length_bytes,
        "root_hash": root_hash,
        "ak_pubkey_fp_sha256": ak_pubkey_fp_sha256,
        "tpm_quote_sha256": tpm_quote_sha256,
        "tpm_quote_nonce_sha256": tpm_quote_nonce_sha256
    }
    
    # Compute node_id as sha256 of canonical node_record
    canonical_bytes = canonical_json_bytes(node_record)
    node_id = sha256_hex(canonical_bytes)
    
    return {
        "node_id": node_id,
        "node_record": node_record
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: ingest_root_entropy.py <fixture.json>", file=sys.stderr)
        return 1
    
    fixture_path = Path(sys.argv[1])
    if not fixture_path.exists():
        print(f"Error: fixture file not found: {fixture_path}", file=sys.stderr)
        return 1
    
    try:
        result = ingest_root_entropy(fixture_path)
        # Output canonical JSON to stdout
        print(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
        return 0
    except Exception as e:
        print(f"Error ingesting fixture: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
