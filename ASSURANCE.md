# 4GARTHA Assurance Contract

Contract `4gartha.assurance/1` · Records `4gartha.record/1` ([SPEC.md](SPEC.md)) · Conformance
suite [`tests/test_conformance.py`](tests/test_conformance.py)

> **4GARTHA is a content-addressed evidence and provenance system whose assurance claims are
> explicitly scoped, independently testable, and limited to the guarantees its implementation can
> demonstrate.**

**Engineering rule:** no claim without a named adversary, a defined verification procedure, and a
reproducible acceptance condition.

This document is the engineering contract for what the verifier may report. Under
[LAW-0001](LAW-0001_Names_NonNormative_Tests_Normative.md) the conformance tests, not this prose,
are normative. A sentence here that no test backs is a defect in this document. It is not a
property of the system.

## 1. What version 1 can and cannot establish

| Dimension | v1 can report PASS? | Established by | Conformance |
| --- | --- | --- | --- |
| Artifact integrity | **Yes** | Hashing every referenced artifact | C8, `test_verifier.py`, `test_cas_existing_objects.py` |
| Provenance integrity | **Yes** | Canonical, schema-valid records bound to their IDs; lineage complete | C3, C4, `test_records.py` |
| Derivation verification | **Yes**, when replay is requested locally | Re-executing each derivation and comparing bytes | C1, C2, `test_verifier.py` |
| Execution safety | **No.** FAIL whenever a transform runs | Nothing: no isolation boundary exists | C2, C8 |
| Reproducibility | **No.** NOT_CHECKED | Nothing: environments are declared, not enforced | C8 |
| Authenticity | **No.** NOT_CHECKED | Nothing: the only admission basis is `unattested` | C5, C8 |
| Governance | **No.** NOT_CHECKED | Nothing: no external anchoring exists | C6, C8 |

The last four rows are defined now so that their absence is visible in every report and cannot be
mistaken for success. Section 5 says, for each, what a later version must build before it may report
PASS.

## 2. Result vocabulary

Every verification produces a report with an outcome for **all seven** dimensions. A report that
omits a dimension cannot be constructed (C8).

| Status | Meaning |
| --- | --- |
| `PASS` | The procedure ran and the evidence supports the claim. |
| `FAIL` | The procedure established that the claim does not hold, including when required evidence (a referenced record or artifact) is absent or contradicts its digest. |
| `NOT_CHECKED` | No procedure ran: not requested, refused by policy, prevented by an earlier failure, or not implemented in this contract version. The detail says which. |
| `NOT_APPLICABLE` | The record makes no such claim. Example: an admission has no derivation to replay. |
| `ERROR` | A procedure started but could not reach a conclusion (unreadable file, timeout, runtime would not start). |

Rules:

- `FAIL` is reported only when the verifier positively established the negative. An absent
  procedure is `NOT_CHECKED`, never `FAIL` and never `PASS`.
- When one dimension aggregates many checks, the precedence is FAIL > ERROR > NOT_CHECKED > PASS.
- No transform executes unless replay was explicitly requested, artifact and provenance integrity
  of the whole lineage are PASS, and the replay policy permits every runtime involved.
- A status never decides acceptability on its own. Profiles do (section 3).

## 3. Profiles

A profile names the dimensions a caller requires and the statuses each accepts. Unlisted dimensions
are still reported.

| Profile | Requires |
| --- | --- |
| `integrity` (default for `verify` and CI) | artifact and provenance integrity PASS |
| `replay` (default for `replay`) | integrity, plus derivation verification PASS. An admission-only lineage does **not** satisfy it, because NOT_APPLICABLE is not PASS. |
| `replay-if-derived` | integrity, plus derivation verification PASS or NOT_APPLICABLE |
| `isolated-replay` | `replay`, plus execution safety PASS (unsatisfiable in v1) |
| `reproducible` | `isolated-replay`, plus reproducibility PASS (unsatisfiable in v1) |
| `authenticated-admission` | integrity, plus authenticity PASS (unsatisfiable in v1) |
| `governed` | integrity, plus governance PASS (unsatisfiable in v1) |

CLI exit status: `0` profile satisfied; `2` not satisfied; `3` a required dimension is ERROR
(inconclusive rather than refuted). `--json` prints the machine-readable report and profile result.

Replaying a root is the canonical case. `ledger replay <admission>` reports
`derivation_verification NOT_APPLICABLE` and exits 2 under `replay`. Under
`--profile replay-if-derived` the same report exits 0 (C1).

## 4. Adversaries and trust assumptions

| ID | Adversary | Capabilities |
| --- | --- | --- |
| A1 | Outside contributor | Opens pull requests whose records, artifacts, transforms, tests and workflow files they fully control. |
| A2 | Storage corrupter | Alters bytes in a clone, checkout or object store (accidentally or deliberately), without changing the verifier. |
| A3 | Claim forger | Writes well-formed records asserting derivations or lineage that did not happen. |
| A4 | Repository writer | Anyone with push or admin rights: controls history, CI configuration, branch settings and what CI reports. |
| A5 | Compromised runner | Controls the machine a verification runs on. |

Assumed for every claim:

- SHA-256 is collision- and second-preimage-resistant.
- The verifier's own code, its Python runtime and the host it runs on form the trusted base. A
  report from a modified verifier, or from a host controlled by A5, establishes nothing.
- No claim in v1 holds against A4 or A5. That is the governance gap in section 5.7, stated rather
  than hidden.

## 5. The seven assurances

Each assurance below gives its claim, adversary, evidence, procedure, results and limits; the
current state and the requirements for a later version follow where they apply.

### 5.1 Artifact integrity

- **Claim.** Every artifact referenced by a record in the lineage (output, transform, environment)
  is stored at `ledger/objects/<aa>/<id>` as a regular file whose SHA-256 is `<id>`.
- **Adversary.** A2. Also A1/A3 submitting bytes that do not match the IDs they cite.
- **Evidence.** CAS objects.
- **Procedure.** `lstat` (symlinks rejected), read, hash, compare.
- **Results.**
  - PASS: all referenced artifacts match.
  - FAIL: any artifact is missing, mismatched or not a regular file.
  - ERROR: an artifact is unreadable.
  - NOT_CHECKED: the lineage is incomplete, so the set of referenced artifacts is unknown.
- **Does not establish.** That the bytes are accurate, legitimate or meaningful.
- **Write side.** `admit`/`derive` refuse to reuse a corrupt existing CAS entry and never overwrite one.

### 5.2 Provenance integrity

- **Claim.** Every record in the lineage satisfies all of the following:
  - Its bytes are the canonical encoding.
  - It is schema-valid.
  - It is stored under `SHA-256(tag ‖ bytes)`.
  - Every input record it names exists and satisfies the same conditions.

  Inputs are named by record ID, so the target's ID commits to the whole lineage. Changing any
  field anywhere in it changes the target's ID (C4).
- **Adversary.** A2, A3. A forger cannot alter a committed record without changing its ID, and
  cannot construct a cycle.
- **Evidence.** Record files.
- **Procedure.** For every record reachable from the target:
  1. Decode strictly.
  2. Re-encode and compare byte for byte.
  3. Validate against the packaged schema.
  4. Recompute the ID.
  5. Recurse into inputs (shared ancestors are checked once; the lineage is bounded at 100,000
     records).
- **Results.**
  - PASS: every record is valid and present.
  - FAIL: any record is missing, non-canonical, schema-invalid or stored under the wrong ID.
  - ERROR: a record is unreadable, or the bound is exceeded.
- **Does not establish.** That a claimed derivation happened (5.3), who made a claim (5.6), or that a
  record is the *only* claim about an artifact. Several claims about the same bytes coexist by design
  (C3).

### 5.3 Derivation verification

- **Claim.** For every derivation in the lineage: running the declared transform bytes, under the
  declared runtime, with the declared params, over the input records' artifacts in order, produced
  exactly the declared output bytes, on this host, in this run.
- **Adversary.** A3 (false derivation claims).
- **Evidence.** Transform, input and environment artifacts, and an execution.
- **Procedure.** Runs only when requested (`ledger replay`, `ledger verify --replay`) and only after
  5.1 and 5.2 PASS. Each derivation then runs, inputs before dependents, using the interface in
  SPEC.md. Bytes are read once and hashed, and only those verified bytes are materialized. Each run
  uses a fresh, empty directory, so stale output cannot be observed.
- **Results.**
  - PASS: every derivation replayed and matched.
  - FAIL: an output mismatched, a run exited non-zero, or no output was written.
  - NOT_CHECKED: replay not requested, integrity not PASS, or a runtime not permitted by policy.
  - NOT_APPLICABLE: the lineage has admissions only.
  - ERROR: timeout, or the runtime would not start.
- **Does not establish:**
  - That the transform does what its author says. A transform that ignores its inputs and writes
    constant bytes replays perfectly. Transform review is a human process.
  - That another host gets the same result (5.5).
  - That execution was safe (5.4).
- **Never in CI** (section 7).

### 5.4 Execution safety

- **Target claim.** Replay runs transforms inside an enforced isolation boundary. A transform
  cannot read verifier secrets or files outside its run directory, write outside that directory,
  reach the network, or exceed resource limits.
- **Adversary.** A1/A3 supplying hostile transform code.
- **v1 status.** No boundary exists. The verifier reports **FAIL** whenever it executed a transform,
  because it knows the property does not hold, and NOT_APPLICABLE when nothing ran (C2, C8).
- **What v1 does provide (policy, not a boundary; pinned by C2):**
  - A record names a runtime and can never supply argv.
  - The `restricted` policy defines one runtime: `python3` maps to the verifier's interpreter with
    `-I`. Any other name is refused before anything executes.
  - The child gets a minimal environment (no verifier variables or tokens are passed), empty stdin
    and a fresh working directory.
  - A wall-clock timeout (default 60 s) kills the process group (POSIX; on Windows, only the
    process itself). Processes a transform leaves running after it exits normally are not
    killed.
- **Why that is not a boundary.** The transform runs as the verifying user. It can read anything
  that user can (SSH keys, credentials files), write anywhere that user can, use the network, start
  processes that leave its process group, and possibly read its parent's environment via `/proc`,
  depending on kernel ptrace policy.
- **Before PASS may be reported.** Two things are required:
  - An OS-enforced sandbox: separate UID or user namespace, no network, read-only filesystem except
    the run directory, resource limits, syscall filtering.
  - A verifier procedure that confirms the sandbox was in effect for the run, and refuses to execute
    otherwise.

  Tests can pin this policy. They cannot create the boundary.

### 5.5 Reproducibility

- **Target claim.** The record fully specifies the execution environment, and replay enforces it,
  so independent verifiers reach the same result.
- **v1 status.** NOT_CHECKED whenever the lineage contains a derivation; NOT_APPLICABLE for
  admission-only lineages.
  - `environment` is declared and integrity-checked but never used to build anything.
  - The runtime `python3` means "whatever interpreter the verifier runs", and its version is not
    recorded.
  - A replay PASS shows reproduction on one host only.
- **Before PASS may be reported.** Requires all three of:
  - An environment description format that pins interpreter and dependencies (for example a
    container image digest or a Nix derivation).
  - A replay that materializes exactly that environment.
  - Conformance tests showing a mismatched environment is detected.

### 5.6 Authenticity

- **Target claim.** The identity or authority behind each admission, and behind each derivation
  claim, is supported by verifiable evidence: a signature under a key in the verifier's trust
  policy, or a hardware attestation.
- **v1 status.** NOT_CHECKED always.
  - The only admission basis is `unattested`, an identity-bearing statement that no procedure can
    verify.
  - The schema rejects every other basis kind and any signature-like field, so no v1 record can
    *appear* authenticated (C5).
  - Derivation records carry no signer.
- **Limit even when implemented.** A signature authenticates a key relationship. It does not
  establish that the signed content is true.
- **Before PASS may be reported.** Requires all three of:
  - A new protocol version with attested basis kinds.
  - A verifier-held trust policy (keys and roots, never taken from the record).
  - A signature or attestation verification procedure with conformance vectors, including
    wrong-key, wrong-content and revoked-key cases.

  The TPM root-entropy pipeline (section 6.2) is a candidate input, not an implementation.

### 5.7 Governance assurance

- **Target claim.** Admission and preservation of records were enforced under an identifiable
  policy against a named adversary. Where independent historical verification is claimed, history is
  checkable against an external commitment that the repository's writers do not control.
- **v1 status.** NOT_CHECKED always (C6).
- **Controls that exist, and what they are:**
  - **Append-only check** (`tools/check_append_only.py`, in CI and the opt-in pre-commit hook).
    Detects modification, deletion, rename or copy under `ledger/objects/`, `ledger/records/` and
    `ledger/nodes/` within a PR or pushed range. It runs after a push has landed: it reports a
    rewrite but cannot prevent one.
  - **Record gate** (`tools/verify_new_records.py`, in CI). Applies the `integrity` profile to new
    records and their lineage, and rejects malformed record paths and legacy v0 manifests.

  These produce CI results, not evidence a verifier can check later, and A4 controls all of them.
  They defend against honest mistakes and against A1 when maintainers act on their results. They do
  not defend against A4.
- **Repository state observed on 2026-10-08:**
  - `main` has no branch protection.
  - The only ruleset (`AGARTHIAN-SURVIVAL`: required signatures, pull requests, required deployments)
    is disabled.
  - The repository's default workflow token permission is `write`; `ci.yml` overrides it to `read`
    for its own jobs.
  - Fork-PR workflow approval is required only for accounts new to GitHub.
  - The latest pushed commit (`18e21d7`) is unsigned; earlier web-UI commits carry GitHub's
    signature. Enabling `required_signatures` unchanged would block command-line pushes until
    signing is set up.
- **Before PASS may be reported.** Requires all of:
  - External anchoring: periodic checkpoints that commit to the ledger's records (for example a
    Merkle root), signed and published to a log not controlled by A4, such as a transparency log or
    witness cosignatures.
  - A verifier procedure that checks a record's inclusion and the checkpoint's signatures.
  - Enforced repository controls: branch protection with required checks, and a signing policy
    compatible with the actual contribution workflow.

## 6. Identity model

### 6.1 Decisions (protocol `4gartha.record/1`)

Settled before any ledger record was committed, so no migration exists or is needed. The
byte-level definition is in [SPEC.md](SPEC.md).

1. **Artifact identity is separate from record identity.** An artifact ID hashes bytes. A record ID
   hashes a claim, under a domain tag. Any number of claims can reference identical bytes, each
   under its own record ID (C3).
2. **Derivations name input records, not input artifacts,** so a record ID commits to its entire
   lineage, and cycles are infeasible rather than merely detected.
3. **Every field is identity-bearing.** There is no `meta` or display name, so "changing any field
   changes the ID" is checked mechanically over every schema field (C4). Labels live in refs.
4. **The record names a runtime, never a command** (C2).
5. **One admission basis, `unattested`.** Bases the verifier cannot check are rejected, not accepted
   and ignored (C5).
6. **Canonical encoding rejects instead of normalizing** (floats, non-NFC strings, duplicate keys,
   and so on).
7. **v0 is retired.** The v0 node manifest (`ledger/nodes/<artifact ID>.json`, with unhashed
   manifests and one derivation per artifact forever) was removed before any v0 node existed. CI
   rejects additions under `ledger/nodes/`.

### 6.2 Evaluation of the `ingest_root_entropy.py` identifier

`node_id = SHA-256(canon_json_bytes(node_record))`. It was evaluated as a starting point and **not
adopted as the ledger identity**:

- **No domain separation.** The ID is the plain SHA-256 of the record's bytes. It therefore equals
  the artifact ID those same bytes would get as an artifact, so record and artifact namespaces
  collide.
- **Versioning in the body only.** `"v": 1` and `node_type` are inside the record, which is good,
  but there is no protocol tag in the hash preimage.
- **Canonicalization without policy.** `canon_json_bytes` has no rule for floats, NFC or non-ASCII
  keys. The fixture is parsed with `json.load`, which accepts duplicate keys, and
  `int(entropy_length_bytes)` silently coerces values such as `"32"` or `32.9`.
- **Weak provenance commitments.** The record copies fixture fields. The fixture checker requires
  the ingested record's canonical bytes to equal the signed statement, but the record does not
  commit to the signature, the key (only its fingerprint) or the verification result. No ledger
  record references it.

It remains a candidate input for a future attested admission basis. It would have to be re-encoded
under the record canonicalization and domain tag, with the signature and key bound into the record.
The pipeline itself is unchanged.

## 7. CI posture (P0: no transform execution in CI)

- **No workflow executes transform code.** `tools/verify_new_records.py` is verify-only (profile
  `integrity`). Replay requires an explicit `--replay`, which no workflow passes. C7 asserts this
  over every workflow file and checks the gate's behavior.
- **Read-only token.** `ci.yml` declares top-level `permissions: contents: read`, and no job
  requests write (C7).
- **What this does not cover:**
  - `pull_request` workflows run PR-supplied code by design (tests, tools). The read-only token and
    the absence of secrets are the mitigation.
  - A PR can edit `ci.yml` and `tests/` themselves. C7 then runs inside that PR's own suite, so it
    is a regression guard for honest changes, not a control against A1 or A4. The control is review
    of `.github/` changes enforced by branch protection with required checks. That is a repository
    setting, not configured (5.7).
- **Owner actions recommended, not performed:**
  - Set the default workflow permission to read.
  - Protect `main` with the `Ledger Integrity` check required.
  - Resolve commit signing before enabling `required_signatures`.
  - Consider requiring approval for all outside contributors' workflow runs.

## 8. Conformance index

| ID | Establishes | Tests (`tests/test_conformance.py`) |
| --- | --- | --- |
| C1 | Root-node replay never reports that an unperformed derivation succeeded; unrequested replay is NOT_CHECKED; acceptability depends on the profile. | `test_C1_*` |
| C2 | A record cannot select an arbitrary runner under the restricted policy, and the transform does not inherit the verifier's environment. Timeouts are ERROR, and execution is never reported as safe. | `test_C2_*` |
| C3 | Different derivations (and admissions) of identical bytes have distinct record IDs; identical claims have the same ID. | `test_C3_*` |
| C4 | Changing any identity-bearing field changes the record ID. The field list is derived from the schema, so a field added later without coverage fails. IDs are domain-separated. | `test_C4_*` |
| C5 | An unattested admission cannot satisfy `authenticated-admission`; records claiming unverifiable authenticity are rejected. | `test_C5_*` |
| C6 | Passing repository controls (append-only check, record gate) do not yield governance assurance without external evidence. | `test_C6_*` |
| C7 | No workflow replays; the CI token is read-only; the CI record gate executes nothing. | `test_C7_*` |
| C8 | Every report covers all seven dimensions. Execution safety, reproducibility, authenticity and governance never PASS in v1. Broken or missing records fail rather than pass. | `test_C8_*` |

The suite was checked against deliberately broken builds (16 planted defects, each planted
separately). Every one made at least one conformance test fail:

- root replay reported PASS
- any runtime permitted
- verifier environment inherited
- no domain tag
- inputs or params excluded from the ID
- governance, authenticity or execution safety reported PASS
- schema accepting `runner` or a signature basis
- `--replay`, a write token, or a job-level write grant in `ci.yml`
- the gate replaying by default
- unrequested replay reported PASS

**What tests cannot establish:** that a sandbox exists, that repository settings are configured, or
that a given CI result came from an unmodified workflow. Those assurances stay NOT_CHECKED or FAIL
until real controls exist, and the tests guarantee that the reports say so.

## 9. Milestones

| Priority | Item | Acceptance condition | State |
| --- | --- | --- | --- |
| P0 | No transform execution in CI | No untrusted transform can inherit CI privileges | Done: replay removed from CI; read-only token; C7 |
| P1 | This contract and its conformance suite | Every assurance has semantics, failure states and adversary assumptions | Done: sections 2–5, C1–C8 |
| P1 | Artifact IDs separate from record IDs | Multiple derivations reference identical bytes without ambiguity | Done: `4gartha.record/1`, C3/C4 |
| P1 | Accurate README/CONTRIBUTING/SECURITY | No documentation claims a guarantee the implementation does not provide | Done (this revision) |
| P2 | External governance anchoring | History independently checkable against an external commitment | Not started (5.7) |
| P2 | Branch protection and signing policy | Required checks and signing work with the actual contribution workflow | Owner action (5.7, section 7) |
| Later | Isolated replay; enforced environments; attested admission | 5.4, 5.5 and 5.6 may report PASS | Not started |

## 10. Changing this contract

A change to dimension semantics, the result vocabulary or profile definitions bumps
`4gartha.assurance/N`. A change to record identity bumps `4gartha.record/N` (new domain tag). Tests
for a new claim land with or before the claim. Records are never reinterpreted under a later
protocol.
