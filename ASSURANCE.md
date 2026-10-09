# 4GARTHA Assurance Contract

Contract `4gartha.assurance/1` · Records `4gartha.record/1` ([SPEC.md](SPEC.md)) · Conformance
suite [`tests/test_conformance.py`](tests/test_conformance.py)

> **4GARTHA is a content-addressed evidence and provenance system whose assurance claims are
> explicitly scoped, independently testable, and limited to the guarantees its implementation can
> demonstrate.**

**Engineering rule:** no claim without a named adversary, a defined verification procedure, and a
reproducible acceptance condition.

## Controlling statement (v1)

> 4GARTHA v1 establishes artifact and provenance-record integrity through independently checkable,
> cryptographically committed evidence. It distinguishes verified facts from declared claims,
> unperformed checks, and external trust assumptions. No operation may report an assurance that its
> implementation has not actually established.

Everything below elaborates this statement. Where a section seems to promise more, the statement
governs.

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
| Execution safety | **No.** FAIL whenever a transform runs; NOT_CHECKED otherwise | Nothing: no isolation boundary exists | C1, C2, C8 |
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
| `NOT_APPLICABLE` | The record makes no such claim. Example: an admission has no derivation to replay. Never used for execution safety, which is a property of the verification run rather than of a record. |
| `ERROR` | A procedure started but could not reach a conclusion (unreadable file, timeout, runtime would not start). |

Rules:

- `FAIL` is reported only when the verifier positively established the negative. An absent
  procedure is `NOT_CHECKED`, never `FAIL` and never `PASS`.
- When one dimension aggregates many checks, the precedence is FAIL > ERROR > NOT_CHECKED > PASS.
- No transform executes unless replay was explicitly requested, artifact and provenance integrity
  of the whole lineage are PASS, and the replay policy permits every runtime involved.
- A status never decides acceptability on its own. Profiles do (section 3). The verifier reports
  what it established; it does not adjust a status to suit a profile.

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

A satisfied profile never conceals a failure. If a dimension the profile does not require is FAIL,
the profile result lists it under `unrequired_failures`, and the CLI prints a `note:` line. The
standard case is a matching replay that ran without isolation (C2).

Reference case: an unattested root verified the way CI verifies it (no replay). Pinned by C1.

| Dimension | Status | Why |
| --- | --- | --- |
| Artifact integrity | PASS | the admitted artifact is present and matches |
| Provenance integrity | PASS | the record is canonical, schema-valid and bound to its ID |
| Derivation verification | NOT_APPLICABLE | an admission claims no derivation |
| Execution safety | NOT_CHECKED | nothing ran, and no boundary was checked |
| Reproducibility | NOT_APPLICABLE | an admission claims no derivation, so there is nothing to reproduce. This says nothing about whether the artifact's original creation could be reproduced (5.5) |
| Authenticity | NOT_CHECKED | the basis is an unattested statement |
| Governance | NOT_CHECKED | no external anchoring exists |

`integrity` accepts this report. `replay`, `authenticated-admission`, `governed`, `isolated-replay`
and `reproducible` do not.

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

- SHA-256 is preimage-, second-preimage- and collision-resistant. Every statement in this document
  that two identifiers differ, that a change alters an ID, or that a structure (such as a cycle)
  cannot be built means *computationally infeasible under this assumption*, never mathematically
  impossible. If the assumption fails, these claims fail with it.
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
- **Write side.** `admit`/`derive` refuse to reuse a corrupt existing CAS entry and never overwrite one,
  including one a concurrent writer creates mid-write: publication is no-clobber (SPEC.md, Storage
  rules).
  `derive` refuses any input record that does not satisfy the `integrity` profile (record, lineage
  and artifacts), and `refs set` applies the same rule to its target. Writing an identical claim
  again reuses its ID only after the stored copy has been checked: canonical, schema-valid and bound
  to that ID. Otherwise the write is refused and the stored file is left untouched.

### 5.2 Provenance integrity

- **Claim.** Every record in the lineage satisfies all of the following:
  - Its bytes are the canonical encoding.
  - It is schema-valid.
  - It is stored under `SHA-256(tag ‖ bytes)`.
  - Every input record it names exists and satisfies the same conditions.

  Inputs are named by record ID, so the target's ID commits to the whole lineage. Changing any
  field anywhere in it changes the target's ID (C4).
- **Adversary.** A2, A3. A forger cannot feasibly alter a committed record without changing its ID:
  that would require a SHA-256 second preimage. Nor can they feasibly construct a cycle, which would
  require a SHA-256 preimage. Neither is mathematically impossible, so the verifier still checks for
  cycles.
- **Evidence.** Record files.
- **Procedure.** For every record reachable from the target:
  1. Decode strictly.
  2. Re-encode and compare byte for byte.
  3. Validate against the packaged schema.
  4. Recompute the ID.
  5. Recurse into inputs (shared ancestors are checked once; the lineage is bounded at 100,000
     records).
  6. Report any cycle as FAIL. A cycle among ID-valid records means the hash assumption has failed,
     and the ledger should be treated as compromised.
- **Results.**
  - PASS: every record is valid and present.
  - FAIL: any record is missing, non-canonical, schema-invalid, stored under the wrong ID, or part
    of a cycle.
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
- **v1 status.** No boundary exists. The verifier reports **FAIL** whenever a transform process
  actually started, because it knows the property does not hold. When nothing ran it reports
  NOT_CHECKED, never NOT_APPLICABLE, because no boundary was checked (C1, C2, C8).
  - "Ran" means a process was created. A replay attempt whose runtime could not start, or whose
    run directory or inputs could not be prepared, is an ERROR for derivation verification. It
    counts in `replay_attempts` but not in `transforms_executed`, and leaves execution safety
    NOT_CHECKED. A replay that matches still
  satisfies the `replay` profile, and the failed safety assurance is reported alongside it
  (`unrequired_failures`), never hidden.
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
  - Reproducibility is applicable only to lineages containing a derivation claim. An
    admission-only lineage is NOT_APPLICABLE, regardless of whether replay was requested. This
    status makes no claim about the independent reproducibility of the admitted artifact's
    original creation.
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
    `ledger/nodes/` within a PR or pushed range. On a PR it runs before merge, and branch
    protection (below) blocks the merge if it fails. On a push to `main` it runs after the push
    has landed and can only report.
  - **Record gate** (`tools/verify_new_records.py`, in CI). Applies the `integrity` profile to new
    records and their lineage, and rejects malformed record paths and legacy v0 manifests.
  - **Branch protection** (repository ruleset `main-governance`, active since 2026-10-09, no bypass
    actors, so it binds admins too). Changes to `main` must be merged from a pull request whose
    `Ledger Integrity` and `Built-wheel tests` checks, reported by GitHub Actions, passed. Both
    controls above run in `Ledger Integrity`. Force-pushes to `main` and its deletion are blocked.
    No approving review is required, and a PR need not be up to date with `main`, so its checks
    may have run against an older `main`. A PR's checks run that PR's own workflow and tests,
    so A1 can make them pass by changing them (section 7). A4 can edit or disable the ruleset, and
    nothing anchors its history externally.

  These produce CI results and repository settings, not evidence a verifier can check later, and
  A4 controls all of them. They defend against honest mistakes, and against A1 when maintainers
  review what they merge. They do not defend against A4.
- **Repository state observed on 2026-10-09:**
  - Ruleset `main-governance` is active on `refs/heads/main` as described above. Anyone can list
    the rules in force without authenticating:
    `curl -s https://api.github.com/repos/CMABERY/4GARTHA/rules/branches/main`. The classic
    branch-protection endpoint still reports `main` as unprotected, because the rules come from
    the ruleset.
  - The older ruleset (`AGARTHIAN-SURVIVAL`: required signatures, pull requests, required
    deployments) is disabled.
  - The repository's default workflow token permission is `read` (set 2026-10-09), so a workflow
    without a `permissions` block gets a read-only token. A workflow can still declare write
    permissions, as the Pages workflows do. `ci.yml` declares `read` itself (C7). GitHub Actions
    is still allowed to approve pull requests; while the ruleset requires no approval, that grants
    nothing.
  - Fork-PR workflow approval is required for all outside contributors (set 2026-10-09; previously
    only for accounts new to GitHub). Workflow runs on a pull request from anyone who is not a
    collaborator wait until a maintainer approves them. Approving a run is not a review: the
    approved run still executes the PR's code.
  - Commits pushed from the command line (for example `18e21d7` and `e8d2136`) are unsigned;
    web-UI commits and merges made on GitHub (for example `15887a4`) carry GitHub's signature. The
    ruleset does not require signed commits.
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
   hashes a claim, under a domain tag. Domain-separated preimages establish distinct identity
   namespaces. Equality across them is computationally infeasible under SHA-256's assumed security,
   not mathematically impossible. Any number of claims can reference identical bytes, each under
   its own record ID (C3).
2. **Derivations name input records, not input artifacts,** so a record ID commits to its entire
   lineage. Cycles are computationally infeasible under SHA-256 preimage resistance, though not
   logically impossible. The verifier still detects any cycle and reports it as FAIL.
3. **Every field is identity-bearing.** There is no `meta` or display name, so "changing any field
   changes the ID" is checked mechanically over every schema field (C4). Labels live in refs, which
   are mutable conveniences and not historical evidence. If auditable annotations are needed later,
   they will be a separate record kind in a new protocol, referencing the record they annotate.
4. **The record names a runtime, never a command** (C2).
5. **One admission basis, `unattested`.** Bases the verifier cannot check are rejected, not accepted
   and ignored (C5).
6. **Canonical encoding rejects instead of normalizing** (floats, non-NFC strings, duplicate keys,
   and so on).
7. **v0 is retired.** The v0 node manifest (`ledger/nodes/<artifact ID>.json`, with unhashed
   manifests and one derivation per artifact forever) was removed before any v0 node existed. CI
   rejects additions under `ledger/nodes/`. This is a breaking protocol change, released as
   package 0.2.0 ([CHANGELOG.md](CHANGELOG.md)).
8. **Canonicalization is frozen** for `4gartha.record/1`. Its exact rules, including escaping, are
   pinned by language-neutral vectors in
   [`conformance/record-v1-vectors.json`](conformance/record-v1-vectors.json) (C9). Changing any
   rule is a new protocol with a new domain tag.

### 6.2 Evaluation of the `ingest_root_entropy.py` identifier

`node_id = SHA-256(canon_json_bytes(node_record))`. It was evaluated as a starting point and **not
adopted as the ledger identity**:

- **No domain separation.** The ID is the plain SHA-256 of the record's bytes, so it is, by
  definition, the artifact ID those same bytes would get as an artifact. Record and artifact IDs
  share one namespace. (v1's domain tag separates them. Equality then becomes computationally
  infeasible rather than definitional, though not mathematically impossible.)
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

## 7. CI posture (P0)

**The claim, exactly:** CI does not replay newly submitted ledger records as part of its admission gate. The test suite deliberately executes fixture transforms to test replay behavior. Pull-request builds, tests, and tools still execute contributor-controlled code and are not sandboxed.

CI execution remains subject to GitHub Actions' workflow permissions, contributor trust policies,
and execution-environment protections.

- **Admission gate does not replay.** `tools/verify_new_records.py` is verify-only (profile
  `integrity`), and replay requires an explicit `--replay`. C7 asserts that the workflow invokes the
  gate exactly once, without `--replay`, and that the gate executes nothing. C7 also scans workflow
  text for direct replay invocations. That scan is a regression check, not proof that nothing in CI
  replays.
- **The test suite does replay.** `pytest`, which both CI jobs run, deliberately executes fixture
  transforms to test replay behavior (for example C2). These are the repository's own fixtures, run
  without isolation like any replay. In a pull request they are contributor-controlled code, like
  the rest of the suite.
- **Read-only token.** `ci.yml` declares top-level `permissions: contents: read`, and no job
  requests write (C7).
- **Built-wheel job.** The `Built-wheel tests` job runs the full suite against the built, installed
  wheel and checks the wheel's contents. The packaged verifier is what CI proves, not only an
  editable checkout.
- **Independent record-ID check.** The `Ledger Integrity` job runs `ci/verify_record_ids.sh`. Using
  only `jq` and `sha256sum`, it serializes each committed record-ID fixture from its record object
  and checks the canonical bytes, the domain-separated record ID and the plain SHA-256. It fails
  closed on a missing tool, a changed fixture set, a missing field or any mismatch. It is a second
  implementation path for those four fixtures, not a replacement for the C9 rejection vectors.
- **What this does not cover.** Pull-request CI is not a sandbox. A PR's workflow run executes
  contributor-controlled code: `pip install` builds the PR's package, and `pytest` runs the PR's
  tests and tools. The mitigations are the read-only token, the absence of repository secrets, and
  GitHub's fork-PR approval policy, which holds every outside contributor's runs for a maintainer's
  approval (5.7). A PR can also edit `ci.yml` and `tests/` themselves. C7 then
  runs inside that PR's own suite, so it guards honest changes against regression. It is not a
  control against A1 or A4. Against A1 the control is the maintainer's review of `.github/`,
  `tests/` and `tools/` changes before merging. Branch protection (5.7) requires the checks to pass
  before any merge into `main`, but it does not require an approving review, and a PR's required
  checks are produced by that PR's own workflow.
- **Owner actions.** Repository settings are kept out of source PRs.
  - Done 2026-10-09: `main` is protected by ruleset `main-governance`, with the `Ledger Integrity`
    and `Built-wheel tests` checks required and no bypass (5.7).
  - Done 2026-10-09: the default workflow token permission is `read` (5.7).
  - Done 2026-10-09: workflow runs from all outside contributors require approval (5.7).
  - Do not enforce signed commits until the contribution workflow produces them.

## 8. Conformance index

| ID | Establishes | Tests (`tests/test_conformance.py`) |
| --- | --- | --- |
| C1 | Root-node replay never reports that an unperformed derivation succeeded; unrequested replay is NOT_CHECKED; acceptability depends on the profile. The reference case (unattested root, integrity-only) produces exactly the table in section 3. | `test_C1_*` |
| C2 | A record cannot select an arbitrary runner under the restricted policy, and the transform does not inherit the verifier's environment. Timeouts are ERROR. Execution is never reported as safe, and a satisfied `replay` profile still reports the failed safety assurance. Execution safety is FAIL only once a transform process actually started; an unstartable runtime is an ERROR with nothing executed. | `test_C2_*` |
| C3 | Different derivations (and admissions) of identical bytes have distinct record IDs; identical claims have the same ID. | `test_C3_*` |
| C4 | Changing any identity-bearing field changes the record ID, both as the hash of the stored bytes and through the public `record_id()`. The field list is derived from the schema, so a field added later without coverage fails. IDs are domain-separated. | `test_C4_*` |
| C5 | An unattested admission cannot satisfy `authenticated-admission`; records claiming unverifiable authenticity are rejected. | `test_C5_*` |
| C6 | Passing repository controls (append-only check, record gate) do not yield governance assurance without external evidence. | `test_C6_*` |
| C7 | The CI record admission gate does not replay: invoked once without `--replay`, and it executes nothing. Workflow text has no direct replay invocation (a regression check). The CI token is read-only (top level, and no job grants write). This does not claim that nothing in CI replays: the test suite replays fixture transforms on purpose. | `test_C7_*` |
| C8 | Every report covers all seven dimensions. Execution safety, reproducibility, authenticity and governance never PASS in v1. Broken or missing records fail rather than pass. | `test_C8_*` |
| C9 | Canonical encoding and record IDs match the frozen, language-neutral vectors. These cover duplicate keys, floats and number forms, Unicode (NFC, surrogates, invalid UTF-8), escaping, key order, whitespace, BOM, depth, domain separation, and schema rejections. Each reject vector must fail for its stated reason, not merely fail. Independently of Python, CI re-serializes every record-ID fixture with `jq -cSj` and recomputes its record ID and plain SHA-256 with `sha256sum`. | `test_C9_*`, `conformance/record-v1-vectors.json`, `ci/verify_record_ids.sh` |

**Planted-defect sensitivity.** The harness [`tools/planted_defects.py`](tools/planted_defects.py)
checks that the tests detect specific defects. It is a manual maintenance command and is not run in
CI:

```bash
python tools/planted_defects.py                     # every catalogued defect, at HEAD
python tools/planted_defects.py --rev <commit> --json result.json
python tools/planted_defects.py --list              # the catalogue and each defect's expected tests
```

How it works:

- **Per defect.** It plants one defect into a fresh copy of a *committed* revision (exported with
  `git archive`), inside a temporary directory it owns. It never writes to the invoking working tree,
  and it checks the tree before and after the run.
- **Detection.** A defect counts as detected only if *every* test the catalogue names for it fails
  with an assertion failure whose text matches the catalogued reason. A failure for any other reason
  does not count.
- **Fail-closed.** The result is FAIL if:
  - a mutation does not apply exactly once
  - an expected test is absent from the passing baseline
  - `ledger` imports from anywhere other than the disposable copy
  - pytest errors, times out or is interrupted
  - the run is incomplete
- **Output.** It writes a JSON result (revision, Python version, per-defect expected and observed
  outcomes). It exits 0 only when the result is PASS.

The catalogue covers these defects:

- root or unrequested replay reported PASS
- execution safety reported NOT_APPLICABLE when nothing ran
- any runtime permitted, or the verifier's environment inherited
- no or a changed domain tag, or inputs or params excluded from `record_id()`
- governance, authenticity or execution safety reported PASS
- a satisfied profile hiding a failed dimension
- the schema admitting `runner` or a signature basis
- `--replay`, a write token or a job-level write grant in `ci.yml`, or the gate replaying by default
- canonicalization defects: floats accepted, NFC skipped, duplicate keys accepted, non-ASCII escaped,
  the round-trip check dropped
- cycles skipped
- unchecked ref targets or derive inputs
- the defects found in implementation review, re-planted in their original form:
  - a record writer that ignores the size limit its reader enforces
  - CAS publication that clobbers a concurrently created entry
  - the independent ID checker looping over a command substitution, which skips every comparison
    when `seq` is unavailable
  - a replay attempt counted as executed code
  - a run-directory failure escaping as an exception

The harness's own fail-closed behavior runs in CI (`tests/test_planted_defects_harness.py`, against a
synthetic repository). The full catalogue run does not.

**Trust boundary.** The disposable checkout isolates files, not execution. The tests run as the
invoking user, with that user's filesystem access, network and most environment variables. Run the
harness only on revisions you trust as much as your own code. Allowlisting the environment it
passes to tests is possible follow-up hardening.

A PASS shows that the suite detects *these particular* defects. It does not show exhaustive security
coverage, and it is not a substitute for adversarial review.

**What tests cannot establish:** that a sandbox exists, that repository settings are configured, or
that a given CI result came from an unmodified workflow. Those assurances stay NOT_CHECKED or FAIL
until real controls exist, and the tests guarantee that the reports say so.

## 9. Milestones

| Priority | Item | Acceptance condition | State |
| --- | --- | --- | --- |
| P0 | The CI admission gate does not replay submitted records | Newly submitted ledger records are verified, not replayed; CI jobs hold a read-only token | Done (C7). The test suite replays fixtures, and PR CI runs contributor code (section 7) |
| P1 | This contract and its conformance suite | Every assurance has semantics, failure states and adversary assumptions | Done: sections 2–5, C1–C8 |
| P1 | Artifact IDs separate from record IDs | Multiple derivations reference identical bytes without ambiguity | Done: `4gartha.record/1`, C3/C4/C9 |
| P1 | Accurate README/CONTRIBUTING/SECURITY | No documentation claims a guarantee the implementation does not provide | Done (this revision) |
| P2 | External governance anchoring | History independently checkable against an external commitment | Not started (5.7) |
| P2 | Branch protection and signing policy | Required checks and signing work with the actual contribution workflow | Branch protection done: ruleset `main-governance`, 2026-10-09 (5.7). Signing policy: owner action (section 7) |
| Later | Isolated replay; enforced environments; attested admission | 5.4, 5.5 and 5.6 may report PASS | Not started |

## 10. Changing this contract

A change to dimension semantics, the result vocabulary or profile definitions bumps
`4gartha.assurance/N`. A change to record identity bumps `4gartha.record/N` (new domain tag). Tests
for a new claim land with or before the claim. Records are never reinterpreted under a later
protocol.
