# Changelog

## 0.3.0: assurance contract `4gartha.assurance/2`, anchor log `4gartha.anchor/1`

Records (`4gartha.record/1`) and record IDs are unchanged. The assurance contract moves to version
2 because one dimension changes meaning: governance can now PASS, but only through external
anchoring verified against a trust policy the verifier supplies ([ASSURANCE.md](ASSURANCE.md) 5.7,
[SPEC.md](SPEC.md) "Anchor log"). This is phase 1 of
[docs/design/external-anchoring.md](docs/design/external-anchoring.md): everything runs offline,
with public test keys and a test-only Sigsum log. Nothing has been anchored in production.

### Added

- **Anchor log.** An RFC 6962 Merkle tree over raw record IDs, stored as add-only batches
  `ledger/anchors/<tree size>/`:
  - `leaves.json`: canonical JSON
  - `checkpoint`: a C2SP signed note signed by the anchor key
  - `sigsum.proof`: optional; a Sigsum proof, format version 2
- **`ledger anchor create`.** Writes the next batch and signs its checkpoint with a local
  Ed25519 key file.
- **`ledger anchor verify`.** Audits the whole log, for integrity only, or with
  `--anchor-policy` for trust.
- **`ledger anchor body`.** Prints the bytes to submit to Sigsum.
- **`--anchor-policy FILE`** for `ledger verify` and `ledger replay`. The policy
  (`4gartha.anchor-policy/1`) is Sigsum policy syntax plus the anchor origin and key. It refuses
  `quorum none` and small-order keys, and it is never read from the repository.
- **Governance PASS** reports a time bound: the time at which a witness quorum had cosigned. It is
  never the earliest cosignature. PASS also carries machine-readable `evidence` in `--json`.
- **Conformance C10, and `conformance/anchor-v1-vectors.json`.** The vectors are reproducible with
  `tools/anchor_fixtures.py`, and include RFC 6962 known answers and the C2SP signed-note example.
- **The optional `anchor` extra** (`cryptography`). The base install stays `jsonschema`-only.

### Changed

- `contract` in JSON reports is `4gartha.assurance/2`, and every outcome has an `evidence` object
  (empty unless a procedure fills it).
- The `governed` profile is satisfiable, with an anchor policy.
- `ledger/anchors/**` is add-only, and the record gate admits only batch paths there.
- C8: execution safety, reproducibility and authenticity never PASS, and governance never PASSes
  without a policy.

### CI

- `Ledger Integrity` runs `ledger anchor verify` (integrity only, no policy).
- `Ledger Integrity` also runs `ci/verify_anchor_vectors.sh`, which checks every vector and every
  stored checkpoint root with the Sigsum reference implementation (sigsum-go v0.14.1, pinned in
  `ci/anchor-go/go.sum`), its `sigsum-verify` command, and `golang.org/x/mod`'s signed-note code.
- The wheel job checks that the base install does not require `cryptography`.

### Tooling

- Planted defects M33 to M46 cover the anchoring checks. M6 is now governance PASS without a
  policy.

## 0.2.0: records protocol `4gartha.record/1` (breaking)

The v0 node-manifest format is removed, not deprecated. No v0 node was ever committed to the
ledger, so there is nothing to migrate. See [ASSURANCE.md](ASSURANCE.md) for what v1 does and does
not establish, and [SPEC.md](SPEC.md) for the format.

### Removed

- `ledger ingest`. Use `ledger admit` for roots of evidence and `ledger derive` for derivations.
- `ledger verify-reachable`. `ledger verify` now always checks the whole lineage.
- The `--runner` option. Records name a runtime (`--runtime`, default `python3`); the verifier's
  replay policy decides what a runtime name executes.
- `--env-digest`. Use `--env-file` (the environment description is stored in the CAS).
- `--note` and the manifest `meta` field. Records have no non-semantic fields.
- Modules `ledger.manifest`, `ledger.verify` and `ledger.replay`, and the v0 schema
  `node.schema.json`.
- `tools/replay_new_nodes.py`. Replaced by `tools/verify_new_records.py`, which does not replay.
- The `ledger/nodes/<artifact ID>.json` format. `ledger/nodes/` must stay empty, and CI rejects
  additions there.

### Changed

- **Identity.** Records live at `ledger/records/<record ID>.json`, where record ID =
  `sha256("4gartha.record/1\0" || canonical bytes)`. Artifact IDs are unchanged (`sha256(bytes)`).
  Several records may reference the same artifact.
- **Derivation inputs** are record IDs, not artifact IDs, and must pass the `integrity` profile
  before `derive` writes anything.
- **Canonical JSON** rejects floats, non-NFC strings, non-ASCII keys, duplicate keys, out-of-range
  integers and non-canonical escapes. It never normalizes them. The rules are frozen and pinned by
  `conformance/record-v1-vectors.json`.
- **Verification output** is a typed report: seven dimensions, each PASS / FAIL / NOT_CHECKED /
  NOT_APPLICABLE / ERROR. Named profiles (`--profile`) decide acceptance, and `--json` gives the
  machine-readable form. Exit codes: 0 satisfied, 2 not satisfied, 3 inconclusive.
- **`ledger replay` of an admission** reports `derivation_verification NOT_APPLICABLE` and exits 2
  under the `replay` profile, where v0 printed `OK`.
- **Replay** runs with a minimal environment, empty stdin, a fresh directory and a timeout. It
  reports `execution_safety FAIL` whenever it executes code (there is no sandbox).
- **`ledger refs set`** requires a target record that exists and passes the `integrity` profile.
- **Record size** is part of validity. A record's canonical encoding must be at most 1 MiB. Writers
  refuse larger records, so they never publish one the reader rejects.
- **Publication** of CAS objects and records is no-clobber (hard link, with fallbacks), and is safe
  against concurrent writers that do not share the session lock.
- **Reports** count `replay_attempts` separately from `transforms_executed`, which counts started
  processes only. Run-directory, input and runtime-start failures are typed ERRORs.
- **Re-admitting an identical claim** returns the existing record ID once the stored copy has been
  checked, where v0 refused to ingest the same bytes again. A corrupt stored copy makes the write
  fail.

### CI

- Workflow token is read-only (`permissions: contents: read`).
- The CI admission gate does not replay submitted records. The test suite still replays its own
  fixture transforms.
- A new `Built-wheel tests` job runs the suite against the installed wheel.
- `ci/verify_record_ids.sh` (step in `Ledger Integrity`) recomputes the record-ID fixtures without
  Python (`jq -cSj` and `sha256sum`).

### Tooling

- `tools/planted_defects.py` is a manual, fail-closed planted-defect harness that measures test
  sensitivity (ASSURANCE.md section 8). CI runs only its self-tests, not the full catalogue.
