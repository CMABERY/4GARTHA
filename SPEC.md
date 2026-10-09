# Spec: ledger records (`4gartha.record/1`) and anchor log (`4gartha.anchor/1`)

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
`src/ledger/record.schema.json`, which is what the verifier uses). A record's canonical encoding must not
exceed **1,048,576 bytes**. Writers refuse larger records before publishing anything, and readers
reject them. Every field is required, no other
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
- If the run directory or its inputs cannot be prepared, or the runtime cannot be started, the
  replay is an operational error (`ERROR`), and no transform code ran.

The default (`restricted`) policy defines one runtime, `python3`: the verifier's own interpreter in
isolated mode (`sys.executable -I`). See `transforms/concat_parents.py`.

## Storage rules

- `ledger/objects/**` and `ledger/records/**` are add-only. CI rejects modification, deletion,
  rename or copy within them (`tools/check_append_only.py`), and every added record path must be
  `ledger/records/<64 lowercase hex>.json` (`tools/verify_new_records.py`).
- Objects and records are both published the same way. The bytes go to a fully written, synced temp
  file, which is then hard-linked into place. Publication never replaces an existing entry, even
  when a concurrent writer creates it after the writer's own existence check: the existing entry is
  reused only if it verifies, and otherwise the write fails. Where hard links are unavailable,
  Windows uses `os.rename`, which is likewise atomic and fails if the destination exists. Other
  systems use exclusive create, which never clobbers but is not crash-atomic; a partial file then
  fails verification rather than passing. An entry that is not a valid copy of what it is named for
  is reported, never repaired.
- `ledger/anchors/**` is add-only too. Every added path must be
  `ledger/anchors/<12 digits>/{leaves.json,checkpoint,sigsum.proof}` (or `.keep`), and the anchor
  log must pass `ledger anchor verify` (see "Anchor log" below).
- `ledger/refs/**` holds mutable names for record IDs. Refs are a convenience: they carry no
  assurance and are not historical evidence. `ledger refs set` only accepts a target record that
  satisfies the `integrity` profile.
- `ledger/nodes/` is the retired v0 manifest location (one manifest per *artifact*, which made a
  second derivation of the same bytes impossible). v0 was retired before any v0 node was committed.
  The directory stays empty and protected, and CI rejects additions to it.

## Anchor log, protocol `4gartha.anchor/1`

The anchor log commits to record IDs in a Merkle tree whose checkpoints can be logged outside the
repository. What a verifier may conclude from it, and its limits, are in ASSURANCE.md 5.7. It is
implemented in `src/ledger/anchor.py`. It is pinned by language-neutral vectors in
[`conformance/anchor-v1-vectors.json`](conformance/anchor-v1-vectors.json) (C10), which CI also
checks with the Sigsum reference implementation (`ci/verify_anchor_vectors.sh`).

External specifications, pinned:

| Specification | Version | Used for |
| --- | --- | --- |
| RFC 6962, section 2.1 | | tree hash and inclusion proofs |
| C2SP `signed-note` | v1.1.0 | checkpoint signature lines and key IDs |
| C2SP `tlog-checkpoint`, `tlog-cosignature` | v1.1.0 | checkpoint text; cosignature semantics |
| Sigsum log protocol | "Stable version v1" (`log.md` at `3d7234dd`) | leaf, tree head and cosignature messages |
| Sigsum proof format | version 2 (sigsum-go v0.14.1, `doc/sigsum-proof.md`) | `sigsum.proof` |
| Sigsum policy format | sigsum-go v0.14.1, `doc/policy.md` | policy syntax |

### Tree

- **Leaf.** The 32 raw bytes of a record ID. Leaf hash `SHA-256(0x00 ‖ leaf)`, interior node
  `SHA-256(0x01 ‖ left ‖ right)`. The tree hash is RFC 6962's MTH, which splits *n* leaves at the
  largest power of two below *n*. The empty tree hashes to `SHA-256("")`. Record IDs are already
  domain-separated (`4gartha.record/1\0`), and every leaf is exactly 32 bytes.
- **Order.** Batches are appended in the order they are created. Within a batch the record IDs are
  sorted ascending, which is the same order for hex and raw bytes. A record ID appears at most once
  in the log. Log order need not follow lineage order: a child can precede its parent within a
  batch. The verifier checks membership, never position.

### Batches

One directory per batch, `ledger/anchors/<tree size, 12 decimal digits>/`, so lexical order is
log order. It contains exactly the following, all regular files (no symlinks, no subdirectories).
`ledger/anchors/` holds only these directories and `.keep`.

- **`leaves.json`** (required). The canonical encoding (above) of exactly
  `{"previous_size": P, "protocol": "4gartha.anchor/1", "records": [...]}`.
  - *P* is the tree size before this batch: 0 for the first batch, and otherwise the preceding
    batch's size.
  - `records` holds 1 to 65,536 record IDs, strictly ascending.
  - The directory's size is *P* plus the number of records.
- **`checkpoint`** (required). A C2SP signed note, UTF-8, with no control characters other than
  newline.
  - **Text.** Exactly three lines, each ending in `\n`:
    - the origin: 1 to 255 bytes, with no spaces, `+` or control characters, and the same in
      every checkpoint of the log
    - the tree size in decimal, without leading zeros
    - the root at that size, in canonical, padded standard base64

    There are no extension lines.
  - **Signatures.** After a blank line come 1 to 16 lines of the form
    `— <key name> <base64(key ID ‖ signature)>`, in canonical base64.
    - The anchor key's line has key name = origin and key ID
      `SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ public key)[:4]`, and carries an Ed25519 signature over the
      text.
    - Lines with any other key name or key ID are ignored, so later phases can add cosignatures.
    - A second line with the same key name and key ID is malformed.
- **`sigsum.proof`** (optional). A Sigsum proof, format version 2 exactly.
  - **Message.** `SHA-256(checkpoint text)`: the note text, not the whole file, so signatures added
    later do not change what was logged. `ledger anchor body <size>` prints that text, and
    `sigsum-submit` hashes its input once to get the message.
  - **Leaf.**
    - checksum: `SHA-256(message)`
    - signature: by the anchor key, over `sigsum.org/v1/tree-leaf ‖ 0x00 ‖ checksum`
    - key hash: `SHA-256(anchor public key)`

    The leaf hash is `SHA-256(0x00 ‖ checksum ‖ signature ‖ key hash)`.
  - **Tree head.** The log signs `sigsum.org/v1/tree/<hex log key hash>\n<size>\n<base64 root>\n`.
    A witness signs `cosignature/v1\ntime <timestamp>\n` followed by those same three lines.
  - **Syntax, strict.**
    - every line ends in `\n` (no CR)
    - values are separated by single spaces
    - integers are decimal, without leading zeros, at most 2⁶³−1
    - hex may be either case, as on the Sigsum wire
    - cosignature key hashes are distinct
    - a tree of size 1 has no inclusion part

`ledger anchor create` writes `leaves.json` and the signed `checkpoint` together, into a directory it
creates exclusively. The operator adds `sigsum.proof` after submission. Once committed, nothing in a
batch changes.

### Trust policy `4gartha.anchor-policy/1`

The verifier holds this file and passes it with `--anchor-policy`. The repository never supplies it.

- **Syntax.** Sigsum policy syntax (sigsum-go v0.14.1, `doc/policy.md`):
  - `log <hex key> [url]`
  - `witness <name> <hex key> [url]`
  - `group <name> <k|all|any> <member>...`
  - `quorum <name>`
  - `#` comments at the start of a line

  It adds exactly one `anchor-origin <origin>` and exactly one `anchor-key <hex key>`. Keys are raw
  32-byte Ed25519 public keys in hex. Names are opaque bytes.
- **Stricter than Sigsum.**
  - at least one log is required
  - `quorum none` is refused, because a governance PASS always rests on witnesses
  - small-order keys are refused
  - CR is refused (sigsum-go strips it)
  - thresholds must be decimal
- **Use with Sigsum's tools.** Drop the two `anchor-` lines, and the rest is a Sigsum policy for
  `sigsum-submit` and `sigsum-verify`.

```
anchor-origin example.org/ledger/anchor/1
anchor-key    <64 hex>
log           <64 hex>  https://log.example
witness w1    <64 hex>
witness w2    <64 hex>
witness w3    <64 hex>
group quorum-rule 2 w1 w2 w3
quorum quorum-rule
```

**Time bound.** For a witness, its cosignature timestamp if the cosignature verifies. For a group of
threshold *k*, the *k*-th smallest of its members' bounds, or none if fewer than *k* have one. The
quorum's bound is *T*.

Any change to this section (leaf encoding, tree, file formats, pinned Sigsum proof version) is a new
anchor protocol: a new `protocol` value in `leaves.json` and, if the tree changes, a new origin.

## Versioning

A change to identity semantics, canonical encoding or record kinds is a new protocol: new
`protocol` string, new domain tag, new schema. Records of an earlier protocol are never
reinterpreted under a later one. Auditable annotations, if added, will be a new record kind that
references the record it annotates. Mutable refs are not a substitute.
