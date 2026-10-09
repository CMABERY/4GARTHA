# Contributing

## The rule for claims

No claim without a named adversary, a defined verification procedure, and a reproducible
acceptance condition. Under [LAW-0001](LAW-0001_Names_NonNormative_Tests_Normative.md), tests are
normative. A change that adds or strengthens an assurance must therefore land with (or after) a
conformance test in `tests/test_conformance.py`, and must update [ASSURANCE.md](ASSURANCE.md). Docs
must not describe a guarantee the code does not test.

## Storage rules

- `ledger/objects/**` (artifacts) and `ledger/records/**` (records) are **add-only**.
- `ledger/nodes/` is the retired v0 location and must stay empty.
- `ledger/refs/**` is mutable (names for record IDs; no assurance).

CI rejects modifications, deletions, renames and copies under the add-only paths, and any addition
under `ledger/nodes/`. These are detection checks that run after a push lands. Until `main` is
protected, they do not prevent a rewrite (ASSURANCE.md 5.7).

## Local hardening

Install the provided pre-commit hook (recommended):

```bash
python tools/install_hooks.py
```

The hook blocks any staged modify/delete/rename/copy under `ledger/objects/**`, `ledger/records/**`
or `ledger/nodes/**`.

## Adding records

1. `ledger admit <file> --statement "..."` for roots of evidence. The statement is recorded as an
   *unattested* basis: say where the bytes came from. It is a claim, not evidence.
2. `ledger derive <output> --input <record ID> ... --transform-file <transform.py>` for
   derivations. Inputs are record IDs, in order.
3. `ledger verify <record ID>`, and if you trust the transform code, `ledger replay <record ID>`.
   Replay runs that code as your user without a sandbox.
4. Optionally point a ref at the record (`ledger refs set <name> <record ID>`).
5. Open a PR. CI will:
   - run the test suite, including the conformance suite
   - enforce the add-only rules
   - check new records and their whole lineage against the `integrity` profile, **without executing
     any transform** (derivation replay is disabled in CI until replay is isolated)

Reviewers: a passing record gate establishes integrity only. Read new transform code yourself. CI
never runs it, and a replay that matches would not show the transform is honest (ASSURANCE.md 5.3).
