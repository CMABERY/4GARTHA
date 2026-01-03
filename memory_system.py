"""Memory system with defensive guards for law-kernel."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


def sha256_bytes(b: bytes) -> str:
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(b).hexdigest()


@dataclass
class MemNode:
    """Memory node with data and parent references."""
    data: bytes
    parents: Tuple[str, ...]
    
    def __init__(self, data: bytes, parents: Tuple[str, ...] = ()):
        self.data = data
        self.parents = parents


class MemoryStore:
    """Content-addressed memory store."""
    
    def __init__(self):
        self._store: Dict[str, MemNode] = {}
    
    def put(self, node: MemNode) -> str:
        """Store a memory node and return its hash.
        
        Hash is computed as: sha256(data_hash + parent_hashes)
        """
        data_hash = sha256_bytes(node.data)
        # Compute combined hash: data_hash concatenated with all parent hashes
        combined = data_hash.encode('utf-8')
        for parent in node.parents:
            combined += parent.encode('utf-8')
        node_hash = sha256_bytes(combined)
        self._store[node_hash] = node
        return node_hash
    
    def get(self, node_hash: str) -> MemNode | None:
        """Retrieve a memory node by hash."""
        return self._store.get(node_hash)
    
    def contains(self, node_hash: str) -> bool:
        """Check if a node exists in the store."""
        return node_hash in self._store


@dataclass
class Step:
    """Execution step with input and output references."""
    input_node: str
    opcode: str
    output_node: str


@dataclass
class Receipt:
    """Receipt with declared output node."""
    output_node: str
    payload: Dict[str, Any]


class Critic:
    """Critic validates execution traces against memory."""
    
    def __init__(self, memory: MemoryStore):
        self.memory = memory
    
    def replay_and_verify(self, steps: List[Step]) -> Tuple[bool, str]:
        """Replay steps and verify against memory.
        
        Returns (success, error_code).
        Defensive: returns "MISSING_MEMNODE" if a referenced node is missing.
        """
        for step in steps:
            # Check if input node exists in memory
            if not self.memory.contains(step.input_node):
                return (False, "MISSING_MEMNODE")
            
            # Check if output node exists in memory
            if not self.memory.contains(step.output_node):
                return (False, "MISSING_MEMNODE")
        
        return (True, "OK")
    
    def _validate_receipts(self, receipts: List[Receipt]) -> Tuple[bool, str]:
        """Validate that receipt output nodes exist in memory.
        
        Returns (success, error_code).
        Returns "MISSING_RECEIPT_OUTPUT_NODE" when a receipt's output_node is missing.
        """
        for receipt in receipts:
            if not self.memory.contains(receipt.output_node):
                return (False, "MISSING_RECEIPT_OUTPUT_NODE")
        
        return (True, "OK")
    
    def verify_execution(self, steps: List[Step], receipts: List[Receipt]) -> Tuple[bool, str]:
        """Full verification: replay steps and validate receipts."""
        # First verify steps
        success, error = self.replay_and_verify(steps)
        if not success:
            return (success, error)
        
        # Then validate receipts
        return self._validate_receipts(receipts)
