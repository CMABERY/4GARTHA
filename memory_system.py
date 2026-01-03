from __future__ import annotations
from dataclasses import dataclass, replace, asdict
from enum import Enum, auto
from typing import Dict, Tuple, List, Set, Optional
import hashlib
import json

# -------------------------------------------------
# Utilities
# -------------------------------------------------

def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# -------------------------------------------------
# Phase + Step Types
# -------------------------------------------------

class Phase(Enum):
    INGEST = auto()
    TRAVERSE = auto()
    ANALYZE = auto()
    HYPOTHESIZE = auto()
    DECIDE = auto()
    ACT = auto()

class StepType(Enum):
    PARSE = auto()
    EXTRACT = auto()
    INFER = auto()
    AGGREGATE = auto()
    ENTITY_BIND = auto()
    DECIDE = auto()
    ACT = auto()

PHASE_ALLOWED = {
    Phase.INGEST:      {StepType.PARSE},
    Phase.TRAVERSE:    {StepType.EXTRACT},
    Phase.ANALYZE:     {StepType.EXTRACT, StepType.AGGREGATE, StepType.INFER},
    Phase.HYPOTHESIZE: {StepType.EXTRACT, StepType.AGGREGATE, StepType.INFER},
    Phase.DECIDE:      {StepType.DECIDE},
    Phase.ACT:         {StepType.ACT},
}

# -------------------------------------------------
# Merkle DAG Memory
# -------------------------------------------------

@dataclass(frozen=True)
class MemNode:
    data: bytes
    parents: Tuple[str, ...]

class MemoryStore:
    def __init__(self):
        self.store: Dict[str, MemNode] = {}

    def put(self, data: bytes, parents: Tuple[str, ...] = ()) -> str:
        h = sha256(canonical_json({
            "data_sha256": sha256(data),
            "parents": list(parents),
        }))
        if h not in self.store:
            self.store[h] = MemNode(data=data, parents=parents)
        return h

    def get(self, h: str) -> MemNode:
        return self.store[h]

# -------------------------------------------------
# Step + Proof
# -------------------------------------------------

@dataclass(frozen=True)
class Step:
    step_type: StepType
    rule_id: str
    inputs: Tuple[str, ...]
    params: Dict
    output_node: str

@dataclass
class Proof:
    goal_id: str
    steps: List[Step]
    receipt_deps: Tuple[str, ...] = ()

# -------------------------------------------------
# Opcode Semantics (Deterministic)
# -------------------------------------------------

def opcode_eval(step: Step, in_nodes: List[MemNode]) -> bytes:
    payload = {
        "op": step.step_type.name,
        "rule": step.rule_id,
        "params": step.params,
        "inputs_data": [sha256(n.data) for n in in_nodes],
        "inputs_parents": [list(n.parents) for n in in_nodes],
    }
    return canonical_json(payload)

# -------------------------------------------------
# Norms + Obs
# -------------------------------------------------

@dataclass(frozen=True)
class Norms:
    infer_count: int = 0
    aggregate_count: int = 0
    decision_count: int = 0
    goal_id: str = ""

@dataclass(frozen=True)
class ObsEvent:
    phase: Phase
    step_type: StepType
    rule_id: str
    deps_count: int
    norms: Norms

# -------------------------------------------------
# Monitors
# -------------------------------------------------

class Monitor:
    def step(self, event: ObsEvent) -> bool:
        raise NotImplementedError

class PhaseAllowlistMonitor(Monitor):
    def step(self, event: ObsEvent) -> bool:
        return event.step_type in PHASE_ALLOWED[event.phase]

class HiddenPremiseMonitor(Monitor):
    def step(self, event: ObsEvent) -> bool:
        if event.step_type in {StepType.INFER, StepType.DECIDE, StepType.ACT}:
            return event.deps_count > 0
        return True

# -------------------------------------------------
# Law Hash (Pinned, Deterministic)
# -------------------------------------------------

LAW_BUNDLE = canonical_json({
    "phases": {
        p.name: sorted([s.name for s in PHASE_ALLOWED[p]])
        for p in sorted(PHASE_ALLOWED.keys(), key=lambda x: x.name)
    },
    "opcodes": sorted([s.name for s in StepType]),
    "monitors": sorted([
        "PhaseAllowlistMonitor",
        "HiddenPremiseMonitor",
    ]),
})
LAW_HASH = sha256(LAW_BUNDLE)

# -------------------------------------------------
# Receipt
# -------------------------------------------------

@dataclass(frozen=True)
class Receipt:
    law_hash: str
    phase: str
    goal_id: str
    output_node: str

# -------------------------------------------------
# Critic
# -------------------------------------------------

class Critic:
    def __init__(self, memory: MemoryStore, monitors: List[Monitor], law_hash: str):
        self.memory = memory
        self.monitors = monitors
        self.law_hash = law_hash

    def _validate_receipts(self, receipt_deps: Tuple[str, ...]) -> Tuple[bool, str]:
        for r_h in receipt_deps:
            try:
                node = self.memory.get(r_h)
            except KeyError:
                return False, "MISSING_RECEIPT_NODE"

            try:
                r = json.loads(node.data.decode("utf-8"))
            except Exception:
                return False, "BAD_RECEIPT_ENCODING"

            if not isinstance(r, dict):
                return False, "BAD_RECEIPT_ENCODING"

            if r.get("law_hash") != self.law_hash:
                return False, "RECEIPT_LAW_MISMATCH"

            if "output_node" not in r or "phase" not in r or "goal_id" not in r:
                return False, "BAD_RECEIPT_SCHEMA"

            # Ensure the receipt's output_node actually exists in memory.
            if r["output_node"] not in self.memory.store:
                return False, "MISSING_RECEIPT_OUTPUT_NODE"

        return True, "OK"

    def replay_and_verify(self, proof: Proof, phase: Phase) -> Tuple[bool, str]:
        if not proof.steps:
            return False, "EMPTY_PROOF"

        ok, code = self._validate_receipts(proof.receipt_deps)
        if not ok:
            return False, code

        norms = Norms(goal_id=proof.goal_id)

        for step in proof.steps:
            # Defensive: ensure every referenced input node exists.
            in_nodes: List[MemNode] = []
            for h in step.inputs:
                try:
                    in_nodes.append(self.memory.get(h))
                except KeyError:
                    return False, "MISSING_MEMNODE"

            out_bytes = opcode_eval(step, in_nodes)
            out_h = self.memory.put(out_bytes, parents=step.inputs)

            if out_h != step.output_node:
                return False, "REPLAY_MISMATCH"

            norms = replace(
                norms,
                infer_count=norms.infer_count + (step.step_type == StepType.INFER),
                aggregate_count=norms.aggregate_count + (step.step_type == StepType.AGGREGATE),
                decision_count=norms.decision_count + (step.step_type in {StepType.DECIDE, StepType.ACT}),
            )

            event = ObsEvent(
                phase=phase,
                step_type=step.step_type,
                rule_id=step.rule_id,
                deps_count=len(step.inputs),
                norms=norms,
            )

            for m in self.monitors:
                if not m.step(event):
                    return False, "MONITOR_REJECT"

        if phase == Phase.ACT:
            if len(proof.steps) != 1 or proof.steps[0].step_type != StepType.ACT:
                return False, "BAD_ACT_SHAPE"

        return True, "ACCEPT"

# -------------------------------------------------
# Controller
# -------------------------------------------------

class Controller:
    def __init__(self, memory: MemoryStore, critic: Critic):
        self.memory = memory
        self.critic = critic
        self.phase = Phase.INGEST
        self.law_hash = critic.law_hash
        self.last_receipt_id: Optional[str] = None

    def advance_phase(self, phase: Phase):
        self.phase = phase

    def submit(self, proof: Proof) -> Tuple[bool, str]:
        ok, code = self.critic.replay_and_verify(proof, self.phase)
        if not ok:
            return False, code

        final_node = proof.steps[-1].output_node
        receipt = Receipt(
            law_hash=self.law_hash,
            phase=self.phase.name,
            goal_id=proof.goal_id,
            output_node=final_node,
        )
        r_h = self.memory.put(canonical_json(asdict(receipt)), parents=(final_node,))
        self.last_receipt_id = r_h
        return True, "COMMITTED"
