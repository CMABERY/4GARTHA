#!/usr/bin/env python3
"""Assert node_id contract: verify node_id matches canonical node_record hash and pinned value.

This script verifies that:
1. The node_id in the ingest output matches the sha256 of the canonical node_record
2. The node_id matches the pinned value in the .node_id file

Usage:
    python ci/assert_node_id.py <ingest_output.json> <pinned_node_id_file>
"""

import json
import sys
from pathlib import Path
from typing import Any

# Import shared canonicalization utilities
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
from canon.ids import canon_json_bytes, sha256_hex


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: assert_node_id.py <ingest_output.json> <pinned_node_id_file>", file=sys.stderr)
        return 1
    
    ingest_output_path = Path(sys.argv[1])
    pinned_node_id_path = Path(sys.argv[2])
    
    # Load ingest output
    if not ingest_output_path.exists():
        print(f"Error: ingest output file not found: {ingest_output_path}", file=sys.stderr)
        return 1
    
    with open(ingest_output_path, 'r', encoding='utf-8') as f:
        ingest_output = json.load(f)
    
    # Load pinned node_id
    if not pinned_node_id_path.exists():
        print(f"Error: pinned node_id file not found: {pinned_node_id_path}", file=sys.stderr)
        return 1
    
    with open(pinned_node_id_path, 'r', encoding='utf-8') as f:
        pinned_node_id = f.read().strip()
    
    # Extract node_id and node_record from ingest output
    node_id = ingest_output.get('node_id')
    node_record = ingest_output.get('node_record')
    
    if not node_id:
        print("Error: ingest output missing 'node_id' field", file=sys.stderr)
        return 1
    
    if not node_record:
        print("Error: ingest output missing 'node_record' field", file=sys.stderr)
        return 1
    
    # Recompute node_id from node_record
    canonical_bytes = canon_json_bytes(node_record)
    recomputed_node_id = sha256_hex(canonical_bytes)
    
    # Verify node_id matches recomputed hash
    if node_id != recomputed_node_id:
        print("FAIL: node_id does not match canonical node_record hash", file=sys.stderr)
        print(f"  node_id from ingest: {node_id}", file=sys.stderr)
        print(f"  recomputed sha256   : {recomputed_node_id}", file=sys.stderr)
        print(f"  canonical bytes: {canonical_bytes.decode('utf-8')}", file=sys.stderr)
        return 1
    
    # Verify node_id matches pinned value
    if node_id != pinned_node_id:
        print("FAIL: node_id does not match pinned value", file=sys.stderr)
        print(f"  node_id from ingest: {node_id}", file=sys.stderr)
        print(f"  pinned node_id     : {pinned_node_id}", file=sys.stderr)
        return 1
    
    # All checks passed
    print("OK")
    print(f"  node_id verified: {node_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
