import pytest
import json
from memory_system import (
    MemoryStore, Critic, Controller, Phase, Step, Proof, StepType,
    PhaseAllowlistMonitor, HiddenPremiseMonitor, LAW_HASH, canonical_json, sha256
)

def test_missing_memnode_replay():
    mem = MemoryStore()
    monitors = [PhaseAllowlistMonitor(), HiddenPremiseMonitor()]
    critic = Critic(mem, monitors, LAW_HASH)

    # Create a step that references a non-existent input node
    missing_input = "deadbeef"  # not in mem.store
    step = Step(
        step_type=StepType.INFER,
        rule_id="r1",
        inputs=(missing_input,),
        params={},
        output_node="outnode"
    )
    proof = Proof(goal_id="g", steps=[step], receipt_deps=())

    ok, code = critic.replay_and_verify(proof, Phase.ANALYZE)
    assert not ok
    assert code == "MISSING_MEMNODE"

def test_receipt_validation_missing_output_node():
    mem = MemoryStore()
    monitors = [PhaseAllowlistMonitor(), HiddenPremiseMonitor()]
    critic = Critic(mem, monitors, LAW_HASH)

    # Construct a receipt JSON that references an output_node which does not exist
    fake_receipt = {
        "law_hash": LAW_HASH,
        "phase": "ANALYZE",
        "goal_id": "g",
        "output_node": "nonexistent_output_node"
    }
    # Put the fake receipt into memory (as a node) — but its referenced output_node is missing.
    r_h = mem.put(canonical_json(fake_receipt), parents=())

    # replay_and_verify short-circuits on EMPTY_PROOF (emptiness check first)
    proof = Proof(goal_id="g", steps=[ ], receipt_deps=(r_h,))
    ok, code = critic.replay_and_verify(proof, Phase.ANALYZE)
    assert not ok
    assert code == "EMPTY_PROOF"

    # But call _validate_receipts directly to exercise the missing output node check
    ok2, code2 = critic._validate_receipts((r_h,))
    assert not ok2
    assert code2 == "MISSING_RECEIPT_OUTPUT_NODE"

def test_successful_roundtrip_and_commit():
    mem = MemoryStore()
    monitors = [PhaseAllowlistMonitor(), HiddenPremiseMonitor()]
    critic = Critic(mem, monitors, LAW_HASH)
    ctrl = Controller(mem, critic)

    # Seed an input node
    inp = mem.put(b"input-data", parents=())

    # Compute expected output bytes exactly as the kernel does (opcode_eval payload)
    out_bytes = canonical_json({
        "op": StepType.EXTRACT.name,
        "rule": "r_extract",
        "params": {"k": "v"},
        "inputs_data": [
            sha256(b"input-data")
        ],
        "inputs_parents": [
            list(())
        ],
    })

    # Compute expected output node hash exactly as MemoryStore.put does (with parents=(inp,))
    expected_out_h = sha256(canonical_json({
        "data_sha256": sha256(out_bytes),
        "parents": [inp],
    }))

    step = Step(
        step_type=StepType.EXTRACT,
        rule_id="r_extract",
        inputs=(inp,),
        params={"k": "v"},
        output_node=expected_out_h,
    )

    proof = Proof(goal_id="goal1", steps=[step], receipt_deps=())

    ok, code = critic.replay_and_verify(proof, Phase.TRAVERSE)
    assert ok and code == "ACCEPT"

    ok2, code2 = ctrl.submit(proof)
    assert ok2 and code2 == "COMMITTED"
    assert ctrl.last_receipt_id is not None
