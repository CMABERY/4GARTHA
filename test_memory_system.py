"""Tests for memory_system with defensive guards."""
from __future__ import annotations

import pytest

from memory_system import Critic, MemNode, MemoryStore, Receipt, Step, sha256_bytes


def test_missing_memnode_in_replay():
    """Test that replay_and_verify returns MISSING_MEMNODE for missing node."""
    memory = MemoryStore()
    critic = Critic(memory)
    
    # Reference a node that doesn't exist
    steps = [Step(input_node="nonexistent", opcode="ADD", output_node="also_missing")]
    
    success, error = critic.replay_and_verify(steps)
    assert not success
    assert error == "MISSING_MEMNODE"


def test_missing_receipt_output_node():
    """Test that _validate_receipts returns MISSING_RECEIPT_OUTPUT_NODE."""
    memory = MemoryStore()
    critic = Critic(memory)
    
    # Create a receipt referencing a non-existent output node
    receipts = [Receipt(output_node="missing_output", payload={"status": "complete"})]
    
    success, error = critic._validate_receipts(receipts)
    assert not success
    assert error == "MISSING_RECEIPT_OUTPUT_NODE"


def test_successful_roundtrip_and_commit():
    """Test successful execution roundtrip with correct hash computation."""
    memory = MemoryStore()
    critic = Critic(memory)
    
    # Create input node
    inp_data = b"input_payload"
    inp_node = MemNode(data=inp_data, parents=())
    inp_hash = memory.put(inp_node)
    
    # Simulate execution: opcode transforms input to output
    opcode = "TRANSFORM"
    out_bytes = inp_data + opcode.encode('utf-8')  # Simple transformation
    
    # Compute output node hash exactly as MemoryStore.put would:
    # 1. Hash the data
    data_sha256 = sha256_bytes(out_bytes)
    # 2. Compute node hash: sha256(data_hash + parent_hashes)
    combined = data_sha256.encode('utf-8') + inp_hash.encode('utf-8')
    expected_out_hash = sha256_bytes(combined)
    
    # Store output node with input as parent
    out_node = MemNode(data=out_bytes, parents=(inp_hash,))
    out_hash = memory.put(out_node)
    
    # Verify the hash matches our expectation
    assert out_hash == expected_out_hash
    
    # Create step referencing both nodes
    step = Step(input_node=inp_hash, opcode=opcode, output_node=out_hash)
    
    # Verify replay succeeds
    success, error = critic.replay_and_verify([step])
    assert success
    assert error == "OK"
    
    # Create receipt for output node
    receipt = Receipt(output_node=out_hash, payload={"result": "success"})
    
    # Verify receipt validation succeeds
    success, error = critic._validate_receipts([receipt])
    assert success
    assert error == "OK"
    
    # Verify full execution
    success, error = critic.verify_execution([step], [receipt])
    assert success
    assert error == "OK"


def test_memory_store_hashing():
    """Test that MemoryStore computes hashes correctly."""
    store = MemoryStore()
    
    # Test with no parents
    node1 = MemNode(data=b"hello", parents=())
    hash1 = store.put(node1)
    data_hash1 = sha256_bytes(b"hello")
    expected_hash1 = sha256_bytes(data_hash1.encode('utf-8'))
    assert hash1 == expected_hash1
    
    # Test with one parent
    node2 = MemNode(data=b"world", parents=(hash1,))
    hash2 = store.put(node2)
    data_hash2 = sha256_bytes(b"world")
    combined2 = data_hash2.encode('utf-8') + hash1.encode('utf-8')
    expected_hash2 = sha256_bytes(combined2)
    assert hash2 == expected_hash2
    
    # Verify retrieval
    retrieved1 = store.get(hash1)
    assert retrieved1 is not None
    assert retrieved1.data == b"hello"
    assert retrieved1.parents == ()
    
    retrieved2 = store.get(hash2)
    assert retrieved2 is not None
    assert retrieved2.data == b"world"
    assert retrieved2.parents == (hash1,)


def test_multiple_steps_with_missing_node():
    """Test that replay fails on first missing node in a chain."""
    memory = MemoryStore()
    critic = Critic(memory)
    
    # Create one valid node
    node1 = MemNode(data=b"valid", parents=())
    hash1 = memory.put(node1)
    
    # Create steps where second step references missing node
    steps = [
        Step(input_node=hash1, opcode="OP1", output_node=hash1),
        Step(input_node="missing", opcode="OP2", output_node="also_missing"),
    ]
    
    success, error = critic.replay_and_verify(steps)
    assert not success
    assert error == "MISSING_MEMNODE"


def test_mutating_inserted_node_cannot_change_stored_content():
    """Finding 9: content stored under a hash must not change afterwards."""
    from dataclasses import FrozenInstanceError

    memory = MemoryStore()
    parent = memory.put(MemNode(b"parent"))
    node = MemNode(b"original", (parent,))
    key = memory.put(node)

    with pytest.raises(FrozenInstanceError):
        node.data = b"changed"
    with pytest.raises(FrozenInstanceError):
        node.parents = ()

    stored = memory.get(key)
    assert stored.data == b"original"
    assert stored.parents == (parent,)
    with pytest.raises(FrozenInstanceError):
        stored.data = b"changed"


def test_mutable_inputs_are_snapshotted():
    """bytearray data and list parents cannot be changed through the caller's references."""
    memory = MemoryStore()
    parent = memory.put(MemNode(b"parent"))
    buf = bytearray(b"original")
    parents = [parent]
    key = memory.put(MemNode(buf, parents))

    buf[:] = b"changed!"
    parents.append("injected")

    stored = memory.get(key)
    assert stored.data == b"original" and isinstance(stored.data, bytes)
    assert stored.parents == (parent,)
    # The stored node still matches its address.
    expected = sha256_bytes((sha256_bytes(b"original") + parent).encode("utf-8"))
    assert key == expected


def test_memnode_rejects_non_bytes_data_and_non_str_parents():
    with pytest.raises(TypeError):
        MemNode("text")
    with pytest.raises(TypeError):
        MemNode(b"x", (1,))
