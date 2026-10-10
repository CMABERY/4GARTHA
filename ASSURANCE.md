# 4GARTHA Assurance Contract

Contract `4gartha.assurance/2` · Records `4gartha.record/1` and anchor log `4gartha.anchor/1`
([SPEC.md](SPEC.md)) · Conformance suite [`tests/test_conformance.py`](tests/test_conformance.py)

> **4GARTHA is a content-addressed evidence and provenance system whose assurance claims are
> explicitly scoped, independently testable, and limited to the guarantees its implementation can
> demonstrate.**

**Engineering rule:** no claim without a named adversary, a defined verification procedure, and a
reproducible acceptance condition.

## Controlling statement

> 4GARTHA establishes artifact and provenance-record integrity through independently checkable,
> cryptographically committed evidence. Given a trust policy that the verifier supplies, it can also
> establish that records were committed to checkpoints logged outside the repository's control, no
> later than a time bounded by witness cosignatures. It distinguishes verified facts from declared
> claims, unperformed checks, and external trust assumptions. No operation may report an assurance
> that its implementation has not actually established.

Everything below elaborates this statement. Where a section seems to promise more, the statement
governs.

This document is the engineering contract for what the verifier may report. Under
[LAW-0001](LAW-0001_Names_NonNormative_Tests_Normative.md) the conformance tests, not this prose,
are normative. A sentence here that no test backs is a defect in this document. It is not a
property of the system.

Contract version 2 differs from version 1 in one dimension only: governance can PASS, through the
external anchoring procedure in 5.7 and only under a policy the verifier supplies. Every other
dimension, status and profile means what it meant in version 1.

## 1. What version 2 can and cannot establish

| Dimension | v2 can report PASS? | Established by | Conformance |
| --- | --- | --- | --- |
| Artifact integrity | **Yes** | Hashing every referenced artifact | C8, `test_verifier.py`, `test_cas_existing_objects.py` |
| Provenance integrity | **Yes** | Canonical, schema-valid records bound to their IDs; lineage complete | C3, C4, `test_records.py` |
| Derivation verification | **Yes**, when replay is requested locally | Re-executing each derivation and comparing bytes | C1, C2, `test_verifier.py` |
| Execution safety | **No.** FAIL whenever a transform runs; NOT_CHECKED otherwise | Nothing: no isolation boundary exists | C1, C2, C8 |
| Reproducibility | **No.** NOT_CHECKED | Nothing: environments are declared, not enforced | C8 |
| Authenticity | **No.** NOT_CHECKED | Nothing: the only admission basis is `unattested` | C5, C8 |
| Governance | **Only with an anchor policy supplied by the verifier**, for anchored records | Recomputing the anchor log, then verifying the covering checkpoint's signature and its Sigsum proof under the policy's witness quorum | C6, C8, C10 |

Execution safety, reproducibility and authenticity are defined now so that their absence is visible
in every report and cannot be mistaken for success. Section 5 says, for each, what a later version
must build before it may report PASS. Governance PASS has the narrow meaning in 5.7: inclusion in an
externally logged checkpoint by a time bound, not freshness, completeness or the absence of forks.

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

An outcome may also carry `evidence`: machine-readable facts behind its status (in `--json`). A
governance PASS names its policy (SHA-256 of the policy file), checkpoint, Sigsum log and time bound.

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
| `isolated-replay` | `replay`, plus execution safety PASS (unsatisfiable in v2) |
| `reproducible` | `isolated-replay`, plus reproducibility PASS (unsatisfiable in v2) |
| `authenticated-admission` | integrity, plus authenticity PASS (unsatisfiable in v2) |
| `governed` | integrity, plus governance PASS. Satisfiable only with `--anchor-policy` (5.7) |

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
| Governance | NOT_CHECKED | no anchor policy was supplied, so no anchoring evidence was evaluated |

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

A4 also holds the anchor key (5.7): whoever can sign checkpoints can publish whatever they choose.
For governance, two outside parties are trusted, never individually: the Sigsum log operators the
policy lists, and its witnesses, as a quorum.

Assumed for every claim:

- SHA-256 is preimage-, second-preimage- and collision-resistant. Every statement in this document
  that two identifiers differ, that a change alters an ID, or that a structure (such as a cycle)
  cannot be built means *computationally infeasible under this assumption*, never mathematically
  impossible. If the assumption fails, these claims fail with it.
- The verifier's own code, its Python runtime and the host it runs on form the trusted base. A
  report from a modified verifier, or from a host controlled by A5, establishes nothing.
- No claim holds against A5. Against A4, only governance PASS says anything, and only what 5.7
  states. Every other claim in this document can be undone by A4 rewriting the repository.
- For governance only:
  - Ed25519 signatures cannot be forged.
  - The policy's keys are the real keys of the parties it names. The verifier, not the repository,
    is responsible for that, and the policy parser refuses small-order keys, under which anyone can
    forge signatures.
  - Dishonest witnesses cannot satisfy the policy's quorum on their own.
  - Honest witnesses' clocks are correct.

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
- **Current status.** No boundary exists. The verifier reports **FAIL** whenever a transform process
  actually started, because it knows the property does not hold. When nothing ran it reports
  NOT_CHECKED, never NOT_APPLICABLE, because no boundary was checked (C1, C2, C8).
  - "Ran" means a process was created. A replay attempt whose runtime could not start, or whose
    run directory or inputs could not be prepared, is an ERROR for derivation verification. It
    counts in `replay_attempts` but not in `transforms_executed`, and leaves execution safety
    NOT_CHECKED. A replay that matches still
  satisfies the `replay` profile, and the failed safety assurance is reported alongside it
  (`unrequired_failures`), never hidden.
- **What the verifier does provide (policy, not a boundary; pinned by C2):**
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
- **Current status.** NOT_CHECKED whenever the lineage contains a derivation; NOT_APPLICABLE for
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
- **Current status.** NOT_CHECKED always.
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

- **Claim.** With trust policy *P* supplied by the verifier, governance PASS for target record *R*
  means that every record in *R*'s lineage is a leaf of the repository's anchor log, at or below a
  checkpoint *C*, such that all of the following hold:
  1. The anchor files are well-formed and consistent:
     - batches are contiguous and no record appears twice
     - every checkpoint's root equals the root recomputed from the batches
     - every anchored record is present and valid
     - every stored Sigsum proof includes its checkpoint
  2. *C*'s note is signed by *P*'s anchor key under *P*'s anchor origin.
  3. *C*'s Sigsum proof shows that SHA-256 of *C*'s note text was signed by *P*'s anchor key and
     logged in a log that *P* lists. That log signed the tree head, and witnesses satisfying *P*'s
     quorum cosigned it.
  4. No signature by a key that *P* trusts, anywhere in the anchor log, fails to verify.

  The report gives the time bound *T* (`anchored_no_later_than`): the earliest time at which the
  cosignatures with timestamps up to *T* satisfy the quorum. For a group of threshold *k* that is
  the *k*-th smallest member time.
  - *T* is an integer: seconds since the Unix epoch, at most 2⁶³−1 as in Sigsum.
  - `anchored_no_later_than_utc` is the same instant in UTC. It is null when *T* is after
    9999-12-31T23:59:59Z, which a valid cosignature can carry, and the text then gives the integer.
  - *T* is never capped or changed to fit (C10).
- **What *T* means.** Suppose every set of witnesses that satisfies the quorum contains an honest
  witness with a correct clock. Then *C*'s note text, and so every record ID beneath it, existed and
  had been logged no later than *T*.
  - *T* is an upper bound. It does not say when a record was created, which may be much earlier.
  - It does not make a date or time stated inside a record or artifact true.
  - It is never the earliest cosignature: with threshold *k*, up to *k*−1 dishonest witnesses could
    backdate that.
  - Removing a cosignature from a proof can only make *T* later, or leave the quorum unmet (C10).
- **Adversaries, and what anchoring does about each.**
  - A2/A3 altering or corrupting anchor files: FAIL.
  - A4 deleting or altering an anchored record while keeping the anchor files: FAIL. An altered
    record has a new ID and so is a different, unanchored record (NOT_CHECKED). Anchoring it later
    gives a later *T*.
  - A4 claiming an earlier anchoring than happened: not possible without witnesses who can satisfy
    the quorum on their own, because *T* comes from witness cosignatures, not from the repository.
  - A4 rebuilding history: A4 holds the anchor key, so it can build a second anchor log (rewritten,
    or with records dropped), sign its checkpoints and log them in Sigsum. A repository carrying that
    second log verifies offline, and its surviving records PASS. Both logs are then public in Sigsum
    under the anchor key, so a monitor that follows the key can see both (Phase 2). Offline
    verification cannot.
  - Sigsum log operator: cannot forge leaves, which the anchor key signs. Showing different tree
    heads to different parties (a split view) needs dishonest witnesses, as below.
- **Does not establish:**
  - That the records' claims are true, or who made them (5.6).
  - That what was anchored is legitimate. A4 holds the anchor key, so anchoring proves publication,
    not legitimacy.
  - Freshness or completeness. Offline, the verifier sees only the checkpoints in this repository.
    It cannot tell whether later checkpoints exist or whether anything was dropped.
  - The absence of forks of the anchor log (A4 rebuilding history, above). Detecting forks needs
    monitoring, or a verifier that remembers checkpoints it has seen. Phase 1 has neither.
    Preventing them needs witnesses of the anchor log itself (Phase 3), with the conditions below.
  - Split-view resistance beyond the quorum's limits. Suppose *f* witnesses in a *k*-of-*n* group
    are dishonest. Dishonest witnesses alone satisfy the quorum, and so can backdate *T*, only if
    *f* ≥ *k*. The log can show different tree heads to different parties only if two
    quorum-satisfying sets can avoid sharing an honest witness, that is, if 2*k* − *n* ≤ *f*. Both
    defences also need honest witnesses to keep their state.
    - Example: Sigsum's production policy `sigsum-generic-2025-1` (2 of 3 witnesses) withstands one
      dishonest witness for *T*, but none for split views.
  - Governance for records not yet anchored: NOT_CHECKED.
- **Evidence.**
  - `ledger/anchors/<tree size>/{leaves.json, checkpoint, sigsum.proof}` (SPEC.md, "Anchor log").
  - The verifier's own policy file, `4gartha.anchor-policy/1` (SPEC.md). Only the file named by
    `--anchor-policy` is read. A policy stored in the repository is never used implicitly, because
    A4 could change it. If the named file is inside the repository, the CLI warns.
- **Procedure** (`ledger verify <id> --anchor-policy FILE`, `src/ledger/anchor.py`):
  1. Without a policy: governance is NOT_CHECKED, and nothing is read.
  2. If artifact or provenance integrity is not PASS, governance is NOT_CHECKED.
  3. Audit the whole anchor log, without any key:
     - layout (only `.keep` and `<12 digits>/` directories, each holding `leaves.json` and
       `checkpoint`, and optionally `sigsum.proof`; regular files only)
     - strict parsing of every file
     - contiguity and uniqueness of leaves
     - roots recomputed and compared, one origin throughout
     - every anchored record loaded and validated
     - every Sigsum inclusion path checked against its checkpoint
  4. With the policy, evaluate every checkpoint:
     - the origin
     - the note signature by the anchor key (signatures by unknown keys are ignored)
     - the Sigsum leaf: key hash, then signature
     - the log: in the policy, then its tree head signature
     - every cosignature by a policy witness
     - the quorum, and *T*
  5. Choose the smallest checkpoint covering the lineage whose evidence is PASS.
- **Results.**

| Status | When |
| --- | --- |
| PASS | A covering checkpoint's evidence is complete and verifies, and nothing anywhere in the anchor log FAILs. Detail and `evidence`: checkpoint size, origin, log key hash, *T*, the witnesses that met the quorum, the policy's SHA-256. |
| FAIL | Anywhere in the anchor log: a file is malformed or inconsistent; a root differs from its recomputation; an anchored record is missing or invalid; a proof does not include its checkpoint; a batch is not contiguous or repeats a record; or a signature by a key the policy trusts does not verify. That last case includes a single witness cosignature even when the quorum is met without it, so contradictory evidence is never skipped. Sigsum's own `sigsum-verify` would accept such a proof. |
| NOT_CHECKED | No policy; integrity not PASS; a lineage record not yet anchored; no covering checkpoint with complete evidence: origin not the policy's, signed only by unknown keys, no `sigsum.proof` yet, leaf by another key, log not in the policy, quorum not met; or Ed25519 not installed (the detail names `pip install 'epistemic-ledger[anchor]'`). |
| ERROR | An anchor file or anchored record could not be read, and nothing that was read FAILs. |

  Precedence is FAIL > ERROR > NOT_CHECKED > PASS. A FAIL anywhere in the anchor log fails every
  record's governance, not just the records in the affected batch. Without Ed25519, every check
  that needs only hashes still runs, so FAIL is still reported for such contradictions.

  If an anchor file or batch directory cannot be read:
  - Integrity is ERROR. The step 3 checks that follow parsing (contiguity, uniqueness, roots,
    anchored records, inclusion) do not run, because they take the whole log as their input.
  - Step 4 still runs on every checkpoint that was read. It is FAIL if the files that were read
    contradict it (a proof that does not include it, or a signature by a key the policy trusts
    that does not verify), and otherwise ERROR if any file in its batch could not be read.
    `ledger anchor verify --json` reports this per checkpoint.
  - The whole log's trust and each record's governance follow the same precedence, so such a
    FAIL outranks the read error (C10).
- **Permanent failure under add-only storage.** `ledger/anchors/**` is add-only. A malformed or
  contradictory file, once merged, makes governance FAIL for every record, and nothing in-band
  repairs it. So `ledger anchor verify --anchor-policy <policy>` must pass before a batch is
  committed, and `ledger anchor create` refuses to extend a log that fails integrity. The remedy for
  a bad file that reached `main`:
  - an explicit, reviewed removal of the file, which the append-only check rejects and so needs a
    deliberate exception
  - recorded in CHANGELOG.md

  Anyone holding the earlier history can see that it happened.
- **Repository controls that exist, and what they are** (guards against honest mistakes, and
  against A1 when maintainers review what they merge; not against A4):
  - **Append-only check** (`tools/check_append_only.py`, in CI and the opt-in pre-commit hook).
    Detects modification, deletion, rename or copy under `ledger/objects/`, `ledger/records/`,
    `ledger/anchors/` and `ledger/nodes/` within a PR or pushed range. On a PR it runs before
    merge, and branch protection (below) blocks the merge if it fails. On a push to `main` it runs
    after the push has landed and can only report.
  - **Record gate** (`tools/verify_new_records.py`, in CI). Applies the `integrity` profile to new
    records and their lineage. Rejects malformed record paths, anchor paths other than
    `ledger/anchors/<12 digits>/{leaves.json,checkpoint,sigsum.proof}`, and legacy v0 manifests.
  - **Anchor log integrity** (`ledger anchor verify`, in CI). Step 3 of the procedure above, with no
    network and no policy. CI cannot judge trust, because the repository, and so CI, is A4's.
  - **Independent anchor check** (`ci/verify_anchor_vectors.sh`, in CI). Checks the vectors and
    every stored checkpoint root with the Sigsum reference implementation (section 7). Stored
    Sigsum proofs fail this step until an anchor policy is configured for it (Phase 2).
  - **Branch protection** (repository ruleset `main-governance`, active since 2026-10-09, no bypass
    actors, so it binds admins too). Changes to `main` must be merged from a pull request whose
    `Ledger Integrity` and `Built-wheel tests` checks, reported by GitHub Actions, passed. Every
    control above runs in `Ledger Integrity`. Force-pushes to `main` and its deletion are blocked.
    Every commit added to `main` must carry a signature that GitHub verifies. No approving review
    is required, and a PR need not be up to date with `main`, so its checks may have run against an
    older `main`. A PR's checks run that PR's own workflow and tests, so A1 can make them pass by
    changing them (section 7). GitHub, not the ledger verifier, decides which signatures verify,
    and a verified signature identifies the GitHub account whose registered key signed a commit,
    not whether the change is sound (compare 5.6). A4 can edit or disable the ruleset.

  These produce CI results and repository settings, not evidence a verifier can check later.
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
  - Signed commits are required on `main` (`required_signatures` in `main-governance`, added
    2026-10-09). The maintainer signs command-line commits with an SSH key registered on GitHub as
    a signing key; web-UI commits and merges made on GitHub carry GitHub's signature. The rule
    applies only to new commits: earlier command-line commits such as `18e21d7` and `e8d2136`
    remain unsigned in history.
  - Nothing has been anchored yet: `ledger/anchors/` holds only `.keep`, so governance is
    NOT_CHECKED for every committed record under any policy.
- **Implemented (phase 1):** the format, the verifier procedure, `ledger anchor create|verify|body`,
  the conformance tests (C10), language-neutral vectors, and the independent Go check. All of it
  uses public test keys and a test-only Sigsum log.
- **Not implemented (phase 2, operational).** Until these exist, governance PASS is reachable only
  with test fixtures:
  - the production anchor key (dedicated, separate from commit signing, held by the maintainer)
  - signing through an SSH agent, so the key need not be a file
  - the production origin, and the domain whose `_sigsum_v1` TXT record carries Sigsum's
    rate-limit key (or a log operator's allowlisting)
  - the first real submission
  - the anchoring cadence
  - a published anchor policy
  - `ledger anchor monitor`, and a monitor operator other than the maintainer

  Phase 3 is witnessing of the anchor origin itself.
  [docs/design/external-anchoring.md](docs/design/external-anchoring.md) has the plan and its open
  decisions.

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
- **Anchor log integrity.** The `Ledger Integrity` job runs `ledger anchor verify`: the keyless,
  networkless audit in 5.7, step 3. It judges no trust and is given no policy (C10).
- **Independent anchor check.** The `Ledger Integrity` job runs `ci/verify_anchor_vectors.sh`.
  It builds `ci/anchor-go` against the Sigsum reference implementation, `sigsum.org/sigsum-go
  v0.14.1`, and `golang.org/x/mod`'s signed-note package, both pinned by hash in `go.sum`. It also
  builds sigsum-go's `sigsum-verify` command. It then checks:
  - every vector in `conformance/anchor-v1-vectors.json`, including the RFC 6962 known answers
  - every Sigsum proof vector a second time through `sigsum-verify`
  - every stored checkpoint root in `ledger/anchors/`

  Where the vectors record that the reference implementation is more lenient than 4GARTHA (for
  example, it accepts a proof with one invalid cosignature when the quorum is met anyway), the
  check confirms the reference still behaves as recorded. Every run also includes negative
  controls: copies of the example anchor log that the checker must reject, namely stored proofs
  without a policy, a changed record ID, a checkpoint for another origin, and a quorum the
  cosignatures do not meet. It fails closed on a missing tool, a module hash mismatch, a vector
  count below its minimum, a control that is not rejected, or any mismatch. Go setup downloads
  modules, so this step needs network access. It is a second implementation path, not a
  replacement for C10.
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
  - Done 2026-10-09: signed commits are required on `main` (5.7). Outside contributors must sign
    the commits in their PRs (CONTRIBUTING.md).
  - Open (phase 2): if the independent anchor check moves to its own job, add that job to the
    required checks of `main-governance`. It runs inside `Ledger Integrity` today, so it is
    already required.

## 8. Conformance index

| ID | Establishes | Tests (`tests/test_conformance.py`) |
| --- | --- | --- |
| C1 | Root-node replay never reports that an unperformed derivation succeeded; unrequested replay is NOT_CHECKED; acceptability depends on the profile. The reference case (unattested root, integrity-only) produces exactly the table in section 3. | `test_C1_*` |
| C2 | A record cannot select an arbitrary runner under the restricted policy, and the transform does not inherit the verifier's environment. Timeouts are ERROR. Execution is never reported as safe, and a satisfied `replay` profile still reports the failed safety assurance. Execution safety is FAIL only once a transform process actually started; an unstartable runtime is an ERROR with nothing executed. | `test_C2_*` |
| C3 | Different derivations (and admissions) of identical bytes have distinct record IDs; identical claims have the same ID. | `test_C3_*` |
| C4 | Changing any identity-bearing field changes the record ID, both as the hash of the stored bytes and through the public `record_id()`. The field list is derived from the schema, so a field added later without coverage fails. IDs are domain-separated. | `test_C4_*` |
| C5 | An unattested admission cannot satisfy `authenticated-admission`; records claiming unverifiable authenticity are rejected. | `test_C5_*` |
| C6 | Passing repository controls (append-only check, record gate) do not yield governance assurance without external evidence and a verifier policy. | `test_C6_*` |
| C7 | The CI record admission gate does not replay: invoked once without `--replay`, and it executes nothing. Workflow text has no direct replay invocation (a regression check). The CI token is read-only (top level, and no job grants write). This does not claim that nothing in CI replays: the test suite replays fixture transforms on purpose. | `test_C7_*` |
| C8 | Every report covers all seven dimensions. Execution safety, reproducibility and authenticity never PASS in v2, and governance never PASSes without an anchor policy. Broken or missing records fail rather than pass. | `test_C8_*` |
| C9 | Canonical encoding and record IDs match the frozen, language-neutral vectors. These cover duplicate keys, floats and number forms, Unicode (NFC, surrogates, invalid UTF-8), escaping, key order, whitespace, BOM, depth, domain separation, and schema rejections. Each reject vector must fail for its stated reason, not merely fail. Independently of Python, CI re-serializes every record-ID fixture with `jq -cSj` and recomputes its record ID and plain SHA-256 with `sha256sum`. | `test_C9_*`, `conformance/record-v1-vectors.json`, `ci/verify_record_ids.sh` |
| C10 | Governance PASSes only through external anchoring under the verifier's own policy (5.7). It is NOT_CHECKED in all of these cases: no policy, even with valid anchors; only a policy planted in the repository; unanchored records; signed only by unknown keys; unknown log; other origin; quorum not met; Ed25519 not installed (hash-only contradictions still FAIL). It is FAIL in all of these: a root mismatch, even under the trusted key; a missing anchored record; a gap or fork between batches; a duplicate leaf; a tampered checkpoint, signature, inclusion path, tree head or leaf; a single invalid or backdated cosignature even when the quorum is otherwise met; malformed files (unexpected file, CRLF, non-canonical JSON, symlink, proof format version 1); and a failure in any batch fails every record. Decimals too long for `int()` (a 5,000-digit tree size, proof version or cosignature timestamp) FAIL rather than crash. An unreadable checkpoint, `leaves.json`, proof or batch directory is ERROR, never a crash, and a forged signature under the trusted key's name and ID still FAILs when its own proof or another batch's checkpoint is unreadable, as does a proof that does not include its checkpoint. The time bound is the quorum time, not the earliest cosignature, and omitting a cosignature never lowers it. A time bound after 9999-12-31T23:59:59Z keeps its integer value, with a null UTC form. Policies refuse `quorum none` and small-order keys. Anchors are add-only, the record gate admits only batch paths, and CI audits the anchor log without a policy and runs the reference implementation. The vectors reproduce from their generator and match RFC 6962 known answers, the C2SP signed-note example, and (in CI) sigsum-go v0.14.1, `sigsum-verify` and x/mod's signed-note code. | `test_C10_*`, `tests/test_anchor.py`, `conformance/anchor-v1-vectors.json`, `ci/verify_anchor_vectors.sh` |

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
- anchoring defects, each planted where it is the only check between the defect and a wrong
  governance result:
  - governance PASS without a policy
  - the policy read from the repository
  - the root not compared with its recomputation
  - the witness quorum ignored
  - the time bound taken from the earliest cosignature
  - a missing anchored record not detected
  - a checkpoint signature not verified once its key name and ID match
  - an invalid witness cosignature skipped when the quorum is met anyway
  - a single-hash Sigsum checksum
  - the inclusion path not checked
  - batches not checked for contiguity
  - the RFC 6962 leaf prefix dropped
  - governance evaluated although integrity failed
  - `ledger/anchors` missing from the append-only check
  - the record gate admitting any anchor path
- the defects found in implementation review of anchoring, re-planted in their original form:
  - anchor decimals, and the policy's group threshold, converted with `int()` before their
    length is bounded
  - checkpoint trust assuming the checkpoint was read
  - UTC formatting limited to the platform's time range
  - whole-log trust reporting a read error before a known contradiction

The harness's own fail-closed behavior runs in CI (`tests/test_planted_defects_harness.py`, against a
synthetic repository). The full catalogue run does not.

**Trust boundary.** The disposable checkout isolates files, not execution. The tests run as the
invoking user, with that user's filesystem access, network and most environment variables. Run the
harness only on revisions you trust as much as your own code. Allowlisting the environment it
passes to tests is possible follow-up hardening.

A PASS shows that the suite detects *these particular* defects. It does not show exhaustive security
coverage, and it is not a substitute for adversarial review.

**What tests cannot establish:** that a sandbox exists, that repository settings are configured,
that a given CI result came from an unmodified workflow, or that a production anchor key, Sigsum
log or witness is honest. Those assurances stay NOT_CHECKED or FAIL
until real controls exist, and the tests guarantee that the reports say so.

## 9. Milestones

| Priority | Item | Acceptance condition | State |
| --- | --- | --- | --- |
| P0 | The CI admission gate does not replay submitted records | Newly submitted ledger records are verified, not replayed; CI jobs hold a read-only token | Done (C7). The test suite replays fixtures, and PR CI runs contributor code (section 7) |
| P1 | This contract and its conformance suite | Every assurance has semantics, failure states and adversary assumptions | Done: sections 2–5, C1–C8 |
| P1 | Artifact IDs separate from record IDs | Multiple derivations reference identical bytes without ambiguity | Done: `4gartha.record/1`, C3/C4/C9 |
| P1 | Accurate README/CONTRIBUTING/SECURITY | No documentation claims a guarantee the implementation does not provide | Done (this revision) |
| P2 | External governance anchoring | History independently checkable against an external commitment | Phase 1 done: format, verifier, CLI, C10, vectors and the reference-implementation check, all with test keys. Phase 2 (operational: production key, domain, first submission, published policy, monitor) not started (5.7) |
| P2 | Branch protection and signing policy | Required checks and signing work with the actual contribution workflow | Done 2026-10-09: ruleset `main-governance` requires both checks and signed commits (5.7) |
| Later | Isolated replay; enforced environments; attested admission | 5.4, 5.5 and 5.6 may report PASS | Not started |

## 10. Changing this contract

A change to dimension semantics, the result vocabulary or profile definitions bumps
`4gartha.assurance/N`. A change to record identity bumps `4gartha.record/N` (new domain tag). Tests
for a new claim land with or before the claim. Records are never reinterpreted under a later
protocol.
