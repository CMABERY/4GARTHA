# Spec: ledger records, protocol `4gartha.record/1`

This is the normative byte-level format. What a verifier may conclude from these bytes, and against
whom, is defined in [ASSURANCE.md](ASSURANCE.md). Where this file and the conformance tests disagree,
the tests win ([LAW-0001](LAW-0001_Names_NonNormative_Tests_Normative.md)) and this file is the bug.

## Two identities

| Identity | Definition | Stored at |
| --- | --- | --- |
| Artifact ID | `SHA-256(artifact bytes)`, 64 lowercase hex | `ledger/objects/<first 2 hex>/<artifact ID>` |
| Record ID | `SHA-256(UTF-8("4gartha.record/1") ‖ 0x00 ‖ canonical bytes of the record)`, 64 lowercase hex | `ledger/records/<record ID>.json` |

An artifact ID names bytes. A record ID names a *claim about* artifacts. The two are never
interchangeable: every reference in a record is typed by its field name (`artifact` or `record`).

The domain tag gives record IDs their own namespace. A record ID is SHA-256 over a different preimage
than the plain SHA-256 of its stored file (which is what that file's artifact ID would be), and a
future protocol hashes under a different tag. Domain-separated preimages establish distinct identity
namespaces. Equality between independently generated identifiers from different namespaces remains
computationally infeasible under the assumed security of SHA-256, but is not mathematically
impossible. The same holds for every statement in this document that two identifiers differ: it
rests on SHA-256's collision and preimage resistance (ASSURANCE.md section 4), not on construction.

A record file contains exactly the record's canonical bytes: no trailing newline, no other content.

## Canonical encoding

Implemented in `src/ledger/canonical.py`.

- UTF-8, no byte-order mark, no whitespace outside strings, no trailing newline.
- Object keys sorted by code point (keys are ASCII, so this equals byte order and UTF-16 order).
  Separators are `,` and `:`.
- String escaping is exactly:
  - `"` → `\"` and `\` → `\\`
  - U+0008, U+0009, U+000A, U+000C and U+000D → `\b`, `\t`, `\n`, `\f`, `\r`
  - every other code point below U+0020 → `\u00XX`, with lowercase hex
  - everything else (`/`, U+007F, U+2028, all non-ASCII including astral characters) is written
    literally as UTF-8

  Any other escape (`\/`, `\u0041`, `\u00e9`, `\u001F`, `\u000a`, surrogate pairs) is
  non-canonical.
- Permitted values: objects, arrays, strings, integers within ±(2⁵³−1), `true`, `false`, `null`.
- **Rejected, never normalized:** floats (including `1.0`), NaN/Infinity, larger integers, strings
  that are not NFC-normalized, lone surrogates, non-ASCII object keys, duplicate keys, nesting
  deeper than 32.
- A decoder accepts a file only if re-encoding its parsed value reproduces the file byte for byte.
  That rules out every alternative spelling of the same value (escapes, `-0`, whitespace, key order).

**These rules are frozen for `4gartha.record/1`.** They are pinned by language-neutral vectors in
[`conformance/record-v1-vectors.json`](conformance/record-v1-vectors.json): bytes as hex, expected
accept/reject, and record IDs with their canonical text. The tests in `tests/test_conformance.py`
(C9) run every vector, and `ci/verify_record_ids.sh` recomputes the record-ID vectors without
Python (`jq` and `sha256sum`). An independent implementation must produce the same outcome for every
vector.
Changing any rule, even to accept something now rejected, is a new protocol with a new domain tag.

Rationale: every one of the rejected cases would need a normalization policy, and any normalization
lets two different inputs share an identity or one input acquire two.

## Record kinds

Schema: `ledger/schema/record.schema.json` (identical to the packaged
`src/ledger/record.schema.json`, which is what the verifier uses). Every field is required, no other
fields are permitted, and **every field is identity-bearing**. There is no non-semantic metadata.
Human-friendly names belong in refs.

### Admission: a root of evidence

```json
{
  "protocol": "4gartha.record/1",
  "kind": "admission",
  "output": {"artifact": "<artifact ID>"},
  "basis": {"kind": "unattested", "statement": "<1..4096 chars>"}
}
```

`basis` is the declared trust basis. In v1 the only kind is `unattested`: a statement of where the
artifact came from and why it is admitted. It is a claim, not evidence. Any other basis kind, and
any signature-like field, is rejected by the schema, so no v1 record can appear authenticated
(ASSURANCE.md, Authenticity).

### Derivation: an output claimed to result from a transform

```json
{
  "protocol": "4gartha.record/1",
  "kind": "derivation",
  "output": {"artifact": "<artifact ID>"},
  "inputs": [{"record": "<record ID>"}, ...],
  "transform": {
    "artifact": "<artifact ID of the transform definition>",
    "runtime": "<runtime name>",
    "params": { ... }
  },
  "environment": null | {"artifact": "<artifact ID of an environment description>"}
}
```

- `inputs`: 1 to 1024 entries, ordered, duplicates permitted. Each entry names an input **record**,
  not an input artifact; its bytes are that record's `output.artifact`. The derivation's ID
  therefore commits to the entire lineage beneath it.
  - A cycle of valid records would require a SHA-256 preimage. That is computationally infeasible,
    not logically impossible, so verifiers must still detect cycles and report them as failures.
  - `ledger derive` refuses input records that do not satisfy the `integrity` profile.
- `transform.runtime`: a name matching `[a-z0-9][a-z0-9._-]{0,63}`, never an argv. What a name
  means is decided by the verifier's replay policy, not by the record (ASSURANCE.md, Execution
  safety).
- `transform.params`: a JSON object under the canonical rules above.
- `environment`: an explicit `null` (none declared) or an environment description artifact. In v1
  it is integrity-checked but not enforced (ASSURANCE.md, Reproducibility).

Identical claims have identical bytes and so the same record ID; storing one again is a no-op. Any
difference, including a different input record for the same input bytes, gives different bytes and
therefore, under SHA-256 collision resistance, a different record ID. Multiple admissions and
derivations of the same artifact coexist.

## Transform interface `4gartha.transform-argv/1`

During replay the verifier materializes verified bytes in a fresh, empty run directory and executes:

```
<argv for the runtime name, from the verifier's policy> <run>/transform.py \
  --parents-manifest <run>/parents.json \
  --parents-dir <run>/parents \
  --params-path <run>/params.json \
  --out <run>/out.bin
```

- `parents.json`: ordered list of `{"index", "record", "artifact", "path"}`, where `path` is relative to
  `--parents-dir`.
- `params.json`: canonical encoding of `transform.params`, followed by a newline.
- Working directory: the run directory. Environment: `PATH`, `LC_ALL=C`, and `HOME`/`TMPDIR` set to
  the run directory, and nothing else from the verifier. stdin: empty.
- The derivation is verified iff the process exits 0 within the policy timeout, writes `out.bin`,
  and `SHA-256(out.bin)` equals `output.artifact`.

The default (`restricted`) policy defines one runtime, `python3`: the verifier's own interpreter in
isolated mode (`sys.executable -I`). See `transforms/concat_parents.py`.

## Storage rules

- `ledger/objects/**` and `ledger/records/**` are add-only. CI rejects modification, deletion,
  rename or copy within them (`tools/check_append_only.py`), and every added record path must be
  `ledger/records/<64 lowercase hex>.json` (`tools/verify_new_records.py`).
- Records are published via a temp file and a hard link, so a crash never leaves a partial record
  under a valid ID. On filesystems without hard links this falls back to exclusive create, which is
  not crash-atomic; a partial file then fails verification rather than passing. An existing entry is never replaced; an entry that is not a valid copy
  of the record it is named for is reported, not repaired.
- `ledger/refs/**` holds mutable names for record IDs. Refs are a convenience: they carry no
  assurance and are not historical evidence. `ledger refs set` only accepts a target record that
  satisfies the `integrity` profile.
- `ledger/nodes/` is the retired v0 manifest location (one manifest per *artifact*, which made a
  second derivation of the same bytes impossible). v0 was retired before any v0 node was committed.
  The directory stays empty and protected, and CI rejects additions to it.

## Versioning

A change to identity semantics, canonical encoding or record kinds is a new protocol: new
`protocol` string, new domain tag, new schema. Records of an earlier protocol are never
reinterpreted under a later one. Auditable annotations, if added, will be a new record kind that
references the record it annotates. Mutable refs are not a substitute.
