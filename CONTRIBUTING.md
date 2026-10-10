# Contributing

## The rule for claims

No claim without a named adversary, a defined verification procedure, and a reproducible
acceptance condition. Under [LAW-0001](LAW-0001_Names_NonNormative_Tests_Normative.md), tests are
normative. A change that adds or strengthens an assurance must therefore land with (or after) a
conformance test in `tests/test_conformance.py`, and must update [ASSURANCE.md](ASSURANCE.md). Docs
must not describe a guarantee the code does not test.

## Storage rules

- `ledger/objects/**` (artifacts), `ledger/records/**` (records) and `ledger/anchors/**` (the
  anchor log) are **add-only**.
- `ledger/nodes/` is the retired v0 location and must stay empty.
- `ledger/refs/**` is mutable (names for record IDs; no assurance).

CI rejects modifications, deletions, renames and copies under the add-only paths, any addition
under `ledger/nodes/`, and any added anchor path other than
`ledger/anchors/<12 digits>/{leaves.json,checkpoint,sigsum.proof}`. `main` is protected by a ruleset that accepts changes only through a pull
request with these checks passing, so a pull request that breaks these rules cannot be merged
unless it also changes the checks. Admins can change the ruleset, so this is not a governance
assurance (ASSURANCE.md 5.7).

## Local hardening

Install the provided pre-commit hook (recommended):

```bash
python tools/install_hooks.py
```

The hook blocks any staged modify/delete/rename/copy under `ledger/objects/**`, `ledger/records/**`,
`ledger/anchors/**` or `ledger/nodes/**`.

## Adding records

1. `ledger admit <file> --statement "..."` for roots of evidence. The statement is recorded as an
   *unattested* basis: say where the bytes came from. It is a claim, not evidence.
2. `ledger derive <output> --input <record ID> ... --transform-file <transform.py>` for
   derivations. Inputs are record IDs, in order, and each must already pass the `integrity`
   profile.
3. `ledger verify <record ID>`, and if you trust the transform code, `ledger replay <record ID>`.
   Replay runs that code as your user without a sandbox.
4. Optionally point a ref at the record (`ledger refs set <name> <record ID>`).
5. Open a PR. `main` rejects direct pushes, and a PR can be merged only once the `Ledger Integrity`
   and `Built-wheel tests` checks pass. Every commit in the PR must be signed, and GitHub must show
   it as "Verified" ([commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification)).
   CI will:
   - run the test suite, including the conformance suite
   - check the anchoring vectors and the anchor log with the Sigsum reference implementation (Go)
   - enforce the add-only rules
   - audit the anchor log (`ledger anchor verify`, integrity only)
   - check new records and their whole lineage against the `integrity` profile. The admission gate
     does not replay submitted records until replay is isolated. The test suite does replay its own
     fixture transforms.
   - run the suite again against the built wheel

   CI is not a sandbox: your PR's tests, tools and package build run in it, with a read-only token.

## Anchoring (maintainers)

Contributors never add anchor batches. The maintainer holding the anchor key does this on their own
machine, never in CI (ASSURANCE.md 5.7, SPEC.md "Anchor log"):

1. `ledger anchor create --key <anchor key> [--origin <origin>]` adds every stored record not yet
   anchored as a new batch: `leaves.json` and the signed `checkpoint`. It refuses if the existing
   anchor log fails integrity, or if a new record fails the `integrity` profile.
2. Log the checkpoint in Sigsum and store the proof as `sigsum.proof` in the batch directory
   (`ledger anchor body <size>` prints the bytes to submit).
3. `ledger anchor verify --anchor-policy <policy>` must pass before you commit. A bad file under
   `ledger/anchors/` is permanent under add-only storage, and it makes governance FAIL for every
   record.

The anchor key is dedicated to anchoring, separate from the commit-signing key, and never a
repository file or CI secret. Phase 2 provisions it.

Reviewers: a passing record gate establishes integrity only. Read new transform code yourself. CI
does not replay it, and a replay that matches would not show the transform is honest (ASSURANCE.md
5.3). Review changes under `.github/` and `tests/` with the same care: a PR can change the checks
that judge it. Branch protection does not require an approving review, so this review is the
merge decision.
