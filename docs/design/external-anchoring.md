# Design proposal: external anchoring for governance assurance

Status: **proposal, not implemented.** Nothing here is a claim about the system. Under
[LAW-0001](../../LAW-0001_Names_NonNormative_Tests_Normative.md) a guarantee exists only once a
conformance test establishes it. Date: 2026-10-09.

Scope: the last open governance item in [ASSURANCE.md](../../ASSURANCE.md) 5.7, "external
anchoring", and the verifier procedure that would let `governance` report PASS. Record format
`4gartha.record/1` is unchanged. The assurance contract moves to `4gartha.assurance/2`, because a
dimension that can never PASS in v1 (C8) becomes able to.

## 1. The claim, exactly

`governance` PASS for target record *R* will mean:

> Every record in *R*'s lineage is a leaf of the 4GARTHA anchor log, in a checkpoint that (a) is
> signed by an anchor key in the verifier's trust policy, and (b) was logged in an external
> transparency log whose signed tree head is cosigned by a quorum of witnesses in that policy, no
> later than time *T*. The repository's anchor files reproduce that checkpoint exactly, and every
> anchored record they list is still present.

It will **not** mean:

- that the records' claims are true or their admissions authentic. That is 5.6, and a signature
  identifies a key, not the truth of what it signed.
- that nothing bogus was anchored. A4 holds the anchor key, so anchoring proves *publication*, not
  legitimacy.
- that records added since the last checkpoint are preserved. They report NOT_CHECKED until
  anchored.
- in offline verification, that no later checkpoint was suppressed, or that no conflicting checkpoint
  exists in the external log. That needs monitoring (section 7). Phase 3 witnessing turns fork
  detection into fork prevention (section 5).

## 2. Adversaries (ASSURANCE.md section 4) and what anchoring does about each

| Adversary | Without anchoring | With phase 2 anchoring (Sigsum) |
| --- | --- | --- |
| A4 repository writer rewrites or deletes anchored records | undetectable after the fact | anchored record missing, or anchor files not reproducing a logged checkpoint: FAIL offline. Deleting the anchor files too: detected by a monitor (a logged checksum with no matching checkpoint) |
| A4 forks the anchor log (two checkpoints at one size) | n/a | both forks are publicly logged under the anchor key. A monitor detects it; offline verification of one fork alone does not |
| A4 backdates a record | undetectable | not possible for anchored records: *T* comes from witness cosignatures, not from the repository |
| Anchor key theft | n/a | the thief can log new checkpoints, which a monitor sees, but cannot alter what witnesses already cosigned |
| External log operator | n/a | cannot forge or alter inclusion without a witness quorum cosigning an inconsistent tree head |
| Witnesses | n/a | trusted as a quorum (k of n), never individually |

## 3. Overview

```
ledger/records/*.json ──► anchor log (Merkle tree over record IDs, RFC 6962 hashing)
                              │
                              ▼
                     checkpoint (C2SP tlog-checkpoint: origin, size, root)
                     signed note, anchor key K
                              │  message = SHA-256(checkpoint body)
                              ▼
                     Sigsum log (leaf signed by K) ── tree head cosigned by witnesses
                              │
                              ▼
     ledger/anchors/<size>/ { leaves.json, checkpoint, sigsum.proof }   (add-only, in Git)
                              │
                              ▼
     ledger verify --anchor-policy <verifier's own file> --profile governed
```

## 4. Ledger side: the anchor log, `4gartha.anchor/1`

**Leaves.** Each leaf is one record ID, as its 32 raw bytes. Hashing follows RFC 6962, the same as
C2SP logs: leaf hash `SHA-256(0x00 ‖ leaf)`, interior node `SHA-256(0x01 ‖ left ‖ right)`. Record
IDs are already domain-separated (`4gartha.record/1\0`), so a leaf cannot be confused with an
artifact ID. A change to leaf encoding means a new origin and protocol, never a reinterpretation.

**Order.** Leaves are appended in anchoring order. Within one batch, the record IDs not yet in the
log are sorted ascending, so anyone can recompute a batch from the repository. A record ID appears
at most once. Log order need not follow lineage order, and within a sorted batch a child can come
before its parent. The verifier checks membership, never position.

**Checkpoint.** A [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body: origin line, tree
size, base64 root hash. Proposed origin: `github.com/CMABERY/4GARTHA/anchor/1`. It is signed as a
[C2SP signed note](https://c2sp.org/signed-note) with an Ed25519 signature by the anchor key, whose
key name is the origin. The format is chosen so that phase 3 witnesses can cosign the same bytes.

**Storage.** One directory per checkpoint, named by its tree size zero-padded to 12 digits, so
lexical order is log order:

```
ledger/anchors/000000000042/
  leaves.json     canonical JSON (canonical.py rules): {"previous_size": 37, "records": [...5 IDs...]}
  checkpoint      the signed note, byte for byte
  sigsum.proof    the Sigsum proof (section 5), byte for byte
```

`ledger/anchors/**` joins the add-only paths enforced by `tools/check_append_only.py`. The CI record
gate gets a no-network anchor check: sizes contiguous, leaves are existing records, recomputed root
equals the checkpoint root. That check is integrity only. CI cannot judge trust, because the
repository, and so CI, is A4's.

**New CLI.**

- `ledger anchor create`: compute the next batch, write `leaves.json`, and produce the checkpoint
  body for signing.
- `ledger anchor verify [--anchor-policy FILE]`: audit the whole anchor log, not one record.
- `ledger anchor monitor`: section 7.

## 5. External side: where checkpoints are anchored

Researched 2026-10-09. Sources are listed in section 12. Items marked *unverified* could not be
confirmed.

| Option | Time *T* | Signed by our key | Forks of our log | Offline verifier needs | Our OpenSSH Ed25519 key | Published | State 2026-10 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Sigsum** | witness cosignature timestamps | yes | detected by monitoring | SHA-256 + Ed25519 | yes, natively (ssh-agent works) | checksum, signature, key hash | log spec "stable v1"; production policy `sigsum-generic-2025-1` (2 logs, 2 of 3 witnesses) |
| **Own C2SP log + public witnesses** | witness cosignature timestamps | yes | **prevented** (honest quorum refuses inconsistent checkpoints) | SHA-256 + Ed25519 (ML-DSA-44 likely later) | yes | checkpoints only | specs v1.1.0 (2026-10-07); witness network production tier "not available yet" |
| Sigstore Rekor v2 | separate RFC 3161 timestamp authority | Ed25519ph only | not handled | X.509, CMS, ECDSA | no (SSH dropped, pure Ed25519 rejected) | public key, signature, digest | GA 2025-10-10 |
| OpenTimestamps | Bitcoin block time | no | no | Bitcoin block headers | n/a | aggregated hash | stable; Python library last released 2023-01 |
| GitHub artifact attestations | via Sigstore | GitHub's workflow identity | no | X.509 | no | repo and workflow identity | GA, but GitHub hosts the repo, and a repo admin can attest any digest: no protection from A4 |

**Phase 2: Sigsum.** For each checkpoint, submit `message = SHA-256(checkpoint body)` (exactly 32
bytes, as Sigsum requires) with the anchor key. The log stores `checksum = SHA-256(message)`, our
Ed25519 signature over `"sigsum.org/v1/tree-leaf" ‖ 0x00 ‖ checksum`, and our key hash. The proof
contains the leaf, an inclusion path and a witness-cosigned tree head. It is stored as
`sigsum.proof`. Nothing about the ledger's contents leaves the repository. Requirements:

- a **domain we control** for Sigsum's rate-limit token: a DNS TXT record at `_sigsum_v1.<domain>`,
  holding a separate Ed25519 key. A `github.io` name cannot carry one. Whether operators allowlist a
  key without a domain is *unverified*.
- the Sigsum submission tool (Go, `sigsum-go`) on the signing machine. Verification does not need it
  (section 6).
- caveat: the Sigsum project still labels its proof and policy *file formats* as work in progress.
  We pin the proof format version (`version=2`) with vectors, and fail closed on anything else.

**Phase 3: witness our own log.** Ask the Witness Network (or Mullvad directly) to witness origin
`github.com/CMABERY/4GARTHA/anchor/1`. Witnesses cosign a checkpoint only if it is consistent with
the last one they cosigned, so with an honest quorum a fork or rewrite cannot be cosigned at all.
Keep Sigsum alongside for publication. Switch the policy's requirement to witness cosignatures once a
production witness list exists. Expect ML-DSA-44 witness keys: tlog-cosignature v1.1.0 recommends it
for new deployments.

**Optional: OpenTimestamps** as a Bitcoin-anchored time bound independent of every operator above.
It adds no fork detection and needs a Bitcoin header source to verify, so it is never required by
the policy.

**Not chosen:** Rekor v2, because it cannot take our key type and its time evidence needs X.509/CMS.
GitHub attestations, because GitHub and A4 control the signing identity.

## 6. Verifier procedure

Inputs: target record IDs, the repository, and a **trust policy supplied by the verifier**. Without
`--anchor-policy`, governance stays NOT_CHECKED. A policy found in the repository is never used
implicitly, because A4 could swap it.

1. **Lineage.** Walk it as today. If integrity does not PASS, governance is NOT_CHECKED.
2. **Locate.** Find the smallest checkpoint whose leaves include every lineage record. If a lineage
   record is not yet anchored: NOT_CHECKED ("N record(s) not yet anchored").
3. **Recompute.** For every batch up to that checkpoint, parse `leaves.json` strictly, check
   `previous_size` contiguity and leaf uniqueness, check each leaf names a record present in
   `ledger/records/`, and recompute the root. The root must equal the checkpoint's root.
4. **Checkpoint signature.** The origin must equal the policy's origin, and the note must carry a
   valid Ed25519 signature by the policy's anchor key. A note signed only by unknown keys is not
   evidence: NOT_CHECKED.
5. **External proof.** Verify the stored Sigsum proof following the Sigsum proof spec:
   - the leaf checksum equals `SHA-256(SHA-256(checkpoint body))`;
   - the leaf key hash equals the hash of the policy anchor key, by bitwise equality;
   - the leaf signature is valid;
   - the inclusion path leads to the tree head;
   - the tree head is signed by a log key in the policy;
   - valid cosignatures from policy witnesses meet the quorum. Report *T* from the cosignature
     timestamps.
6. **Outcome.**

| Status | When |
| --- | --- |
| PASS | steps 2–5 succeed for the whole lineage. Detail: checkpoint size, origin, log, *T* |
| FAIL | evidence contradicts itself or the repository: recomputed root differs from a checkpoint signed by a trusted key; an anchored record is missing; sizes not contiguous; duplicate leaf; malformed anchor files; a Sigsum leaf that does not match its checkpoint; an invalid signature by a key the policy trusts |
| NOT_CHECKED | no policy; a record not yet anchored; Ed25519 support not installed; only untrusted keys signed; cosignature quorum not met |
| ERROR | anchor files unreadable (I/O) |

The precedence FAIL > ERROR > NOT_CHECKED > PASS applies, as for every other dimension.

**Crypto dependency.** Python's standard library has SHA-256 but not Ed25519. Proposal: an optional
extra, `pip install epistemic-ledger[anchor]`, pulling in `cryptography`. That package also loads
OpenSSH keys and, from version 48, ML-DSA (needed for phase 3). The base install stays
`jsonschema`-only, and without the extra governance reports NOT_CHECKED with an install hint. The
alternative is vendoring the roughly 60-line RFC 8032 verification routine: verification touches only
public data. It is smaller, but it is hand-maintained cryptography in a project whose whole point is
not over-claiming.

## 7. Monitoring (what offline verification cannot see)

`ledger anchor monitor` (online) lists Sigsum leaves carrying the anchor key's hash and checks two
things:

- every logged checksum corresponds to a checkpoint in the repository;
- all logged checkpoints lie on one linear chain, each consistent with the previous.

It detects forks, suppressed checkpoints, and anchor files deleted together with their records. Its
value depends on who runs it. The maintainer running it guards against accidents and key theft. A
party A4 does not control guards against A4. The procedure will be documented so that anyone can run
it, and it needs only the public log and a clone.

## 8. Keys and signing

- **A dedicated anchor key**, separate from the commit-signing key. Both protocols domain-separate
  their signatures, so reuse would be cryptographically safe. Separation limits exposure and lets the
  anchor key rotate without touching commit signing. Rotation is a policy change, and old checkpoints
  stay verifiable under the old key, which the policy keeps listed for checkpoints up to a stated size.
- **Who signs.** Recommended for phase 2: the maintainer, locally, with the key in the GNOME Keyring
  agent. This keeps ASSURANCE.md section 7's "no repository secrets" mitigation true. Signing from CI
  would need the key as a GitHub secret available to `main` pushes only. That is more automatic, but
  A4 and anyone who compromises CI can then use the key, and section 7 must change.
- **Cadence.** After each merge that adds records, or daily. Sigsum's ginkgo log allows 288
  submissions a day per domain.

## 9. Contract, conformance and CI changes

- `4gartha.assurance/2`. C8 changes from "governance never PASSes" to "governance PASSes only through
  the anchoring procedure, with a verifier-supplied policy". The `governed` profile becomes
  satisfiable. ASSURANCE.md 5.7 gets the claim in section 1, and its limits, verbatim.
- **New conformance tests (C10)**, each against fixtures built in a temporary repository:
  - unanchored record → NOT_CHECKED;
  - no policy → NOT_CHECKED, even with valid anchors;
  - a policy file inside the repository is not read;
  - valid anchors under the policy → PASS, with *T* reported;
  - root mismatch, missing anchored record, non-contiguous sizes, duplicate leaf → FAIL;
  - checkpoint signed by an untrusted key → NOT_CHECKED;
  - tampered checkpoint body, wrong-key and wrong-content signatures, tampered inclusion path → FAIL;
  - cosignatures below quorum → NOT_CHECKED;
  - Ed25519 extra missing → NOT_CHECKED.
- **Language-neutral vectors** (`conformance/anchor-v1-vectors.json`), like C9: leaf and node hashes,
  roots, inclusion paths, signed-note verification (valid, wrong key, wrong content, key-ID
  collision), and Sigsum proofs (valid, tampered cosignature, below quorum).
- **An independent, non-Python check in CI**, in the spirit of `ci/verify_record_ids.sh`: run the Go
  `sigsum-verify` on every stored proof.
- **Planted defects** for the harness:
  - governance PASS without a policy;
  - the policy read from the repository;
  - the root not recomputed;
  - quorum ignored;
  - a missing anchored record not detected;
  - an untrusted key accepted.

## 10. Phases

| Phase | Delivers | Publishes anything? | Governance can PASS? |
| --- | --- | --- | --- |
| 1 | `4gartha.anchor/1` format, `ledger anchor create/verify`, verifier procedure, vectors, C10, contract v2 text. Fixtures use test keys and a recorded test proof | no | only in tests |
| 2 | Anchor key, domain and rate-limit token, first real checkpoint logged in Sigsum, `ledger anchor monitor`, published policy | yes: checkpoint hashes to Sigsum | yes, for anchored records, with a policy |
| 3 | Witness Network witnessing of our origin; policy requires witness cosignatures | yes: checkpoints to witnesses | yes, with fork prevention |

## 11. Decisions for the maintainer

1. **External log for phase 2: Sigsum (recommended),** with phase 3 witnessing.
2. **A domain for the Sigsum rate-limit token:** which domain, or ask a log operator about
   allowlisting.
3. **Who signs checkpoints: maintainer locally (recommended)** or CI with a secret.
4. **Ed25519 in the verifier: `cryptography` as an optional extra (recommended)** or a vendored RFC
   8032 routine.
5. **Cadence:** per merge that adds records, or daily.
6. **Who runs a monitor besides the maintainer.**

## 12. Sources (web research, 2026-10-09; not all independently re-verified)

- Sigsum log spec (leaf format, 32-byte messages, "stable v1"):
  <https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md>
- Sigsum proof format and verification steps:
  <https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/sigsum-proof.md>
- Sigsum tools (OpenSSH keys, ssh-agent): <https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/tools.md>
- Policy `sigsum-generic-2025-1`:
  <https://github.com/sigsum/sigsum-go/blob/main/pkg/policy/builtin/sigsum-generic-2025-1.builtin-policy>.
  Maintenance rules: <https://git.glasklar.is/sigsum/project/documentation/-/blob/main/policy-maintenance.md>
- ginkgo log terms (288/day per domain, one year's notice): <https://ginkgo.tlog.mullvad.net/about>.
  Glasklar's terms for seasalp: *unverified*.
- Rate limiting: <https://github.com/sigsum/log-go/blob/main/doc/rate-limit.md>
- C2SP: <https://c2sp.org/tlog-checkpoint>, <https://c2sp.org/signed-note>,
  <https://c2sp.org/tlog-cosignature>, <https://c2sp.org/tlog-witness>, <https://c2sp.org/tlog-proof>
  (untagged)
- Witness Network (production tier not yet available): <https://witness-network.org/>,
  <https://github.com/transparency-dev/witness-network/tree/main/lists>
- Rekor v2: <https://blog.sigstore.dev/rekor-v2-ga/>,
  <https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md>
- OpenTimestamps: <https://github.com/opentimestamps/opentimestamps-client>
- GitHub artifact attestations: <https://docs.github.com/en/actions/concepts/security/artifact-attestations>
- `cryptography` changelog (ML-DSA): <https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst>
