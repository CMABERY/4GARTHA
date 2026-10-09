# 4GARTHA: Epistemic Ledger (skeleton)

> 4GARTHA is a content-addressed evidence and provenance system whose assurance claims are
> explicitly scoped, independently testable, and limited to the guarantees its implementation can
> demonstrate.

**No claim without a named adversary, a defined verification procedure, and a reproducible
acceptance condition.** The claims, their limits and their conformance tests are in
[ASSURANCE.md](ASSURANCE.md), which opens with the controlling statement for v1. This README only
summarizes them.

This repo contains two pieces of infrastructure:

1) **Ledger kernel**: content-addressed artifacts plus content-addressed *records* (claims about
   artifacts: admissions and derivations), stored in Git. Format: [SPEC.md](SPEC.md),
   `4gartha.record/1`.
2) **Sprint-1 fencepost (Frozen)**: an executable verifier gate (`nre-verify-fixtures --all`).

## 1) Ledger kernel: what it does and does not establish

- **Artifacts** are named by `sha256(bytes)` and stored in `ledger/objects/`.
- **Records** are named by a domain-separated hash of their canonical bytes and stored in
  `ledger/records/`. Kinds:
  - An *admission* introduces an artifact with a declared, unattested basis.
  - A *derivation* claims an output came from a transform over ordered input records.

  Many claims can reference the same bytes.
- **Verification** reports seven assurances separately, each as PASS / FAIL / NOT_CHECKED /
  NOT_APPLICABLE / ERROR, and a named profile decides what is acceptable.

| Assurance | Today |
| --- | --- |
| Artifact integrity, provenance integrity | Verified |
| Derivation verification | Verified by local replay on request |
| Execution safety | **Not provided.** Replay runs transform code without a sandbox (FAIL when replay runs, NOT_CHECKED otherwise) |
| Reproducibility, authenticity, governance | **Not provided.** Always reported NOT_CHECKED |

Content addressing makes it infeasible to change a record or artifact without changing its ID, so
in-place modification is detected. It does not stop deletion or replacement, and it does not make
history immutable. Preservation depends on repository controls that are not yet enforced (see
"Governance" below).

## Directory layout

```
ledger/
  objects/            # artifacts, content-addressed (add-only)
  records/            # admission/derivation records, content-addressed (add-only)
  refs/               # mutable names for record IDs (no assurance)
  nodes/              # retired v0 location; must stay empty (CI rejects additions)
  schema/             # record JSON schema (copy of the packaged one)
transforms/           # transform code (your domain logic)
tools/                # governance + dev tooling
src/ledger/           # kernel library + verifier
schemas/              # Sprint-1 schema fencepost
canon/                # Sprint-1 canonicalization primitives
verify/               # Sprint-1 verifier
fixtures/             # Sprint-1 vectors + cases
cli/                  # Sprint-1 CLI entrypoints
ci/                   # CI scripts
.github/workflows/    # CI checks
tests/                # incl. tests/test_conformance.py (normative, see LAW-0001)
```

## Locked deps (Sprint-1 fencepost requirement)

Install pinned dependencies from the lockfile:

```bash
python -m pip install -r requirements.lock
```

## Sprint-1 acceptance gate (single command)

```bash
PATH="$(pwd)/cli:$PATH" nre-verify-fixtures --all
```

## Ledger quickstart

Create a Python venv and install editable:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock
pip install -e . --no-deps
```

Admit an artifact (a root of evidence). The statement is your declared basis, recorded as
*unattested*:

```bash
ledger admit path/to/source.bin --statement "exported from instrument X on 2026-10-01"
# prints the admission record ID
```

Record a derivation over input records:

```bash
ledger derive path/to/result.bin --input <record ID> --transform-file transforms/my_transform.py \
  --params-json '{"suffix": "!"}'
# prints the derivation record ID
```

Verify a record and its whole lineage (no code is executed):

```bash
ledger verify <record ID>                    # profile: integrity
ledger verify <record ID> --json             # machine-readable report
```

Replay derivations. This **executes transform code as your user, without a sandbox**; only replay
records whose transforms you would run yourself:

```bash
ledger replay <record ID>                    # profile: replay
ledger verify <record ID> --replay --profile replay-if-derived
```

Every report lists all seven assurances. Replaying an admission reports
`derivation_verification NOT_APPLICABLE` and does not satisfy the `replay` profile. A satisfied
profile still reports any failed dimension it does not require, for example
`note: execution_safety is FAIL`. Exit status: 0 satisfied, 2 not satisfied, 3 inconclusive.

Name a record (the target must exist and pass the `integrity` profile; refs are mutable and are not
evidence):

```bash
ledger refs set latest <record ID>
```

Upgrading from 0.1.x: the v0 `ingest` and `verify-reachable` commands and the `ledger/nodes/` format
are gone. See [CHANGELOG.md](CHANGELOG.md).

## Governance: what is checked, and what is not enforced

CI (`.github/workflows/ci.yml`, read-only token) on pull requests and pushes to `main`:

- **Append-only check:** rejects modification, deletion, rename or copy under `ledger/objects/**`,
  `ledger/records/**` and `ledger/nodes/**`.
- **Record gate:** applies the `integrity` profile to new records and their lineage, and rejects
  malformed record paths and v0 node manifests. **CI does not invoke ledger derivation replay.**
- **Built-wheel tests:** the suite runs again against the installed wheel.

CI is not a sandbox. Pull-request runs still execute contributor-controlled code (the package build,
the tests and the tools), subject to GitHub Actions' permissions, contributor trust policies and
execution-environment protections.

These checks *detect*. They do not *prevent*: they run after a push lands, and anyone with write
access controls both history and CI. `main` currently has no branch protection, and the one
ruleset is disabled. Governance is therefore reported NOT_CHECKED. Protecting `main` (required
checks, no force-push) and external anchoring are open items: ASSURANCE.md sections 5.7 and 7.

## Local hardening (pre-commit hook)

The hook prevents accidental self-inflicted rewrites on your clone. It is not a governance
control.

```bash
python tools/install_hooks.py
```

This installs `.git/hooks/pre-commit` which:

- rejects modify/delete/rename/copy under `ledger/objects/**`, `ledger/records/**` and `ledger/nodes/**`
- runs `nre-verify-fixtures --all` when Sprint-1-relevant files are staged

## Root Entropy Commit Fixtures

The repository includes infrastructure for verifying TPM-signed root entropy commit fixtures. This
pipeline is separate from the ledger kernel. No ledger record references it, and the ledger's
authenticity assurance does not use it (ASSURANCE.md 5.6 and 6.2). No fixture pair is committed
yet.

### Quick Verification

Verify a commit fixture with the comprehensive verification script:

```bash
bash ci/verify_commit_fixture.sh commit_noquote
```

This runs all 10 verification steps including:
- RSA signature verification against AK public key
- Canonical statement reconstruction and validation
- Node ID contract verification
- Raw entropy safety checks

### Manual Verification

For step-by-step verification or debugging:

```bash
# Ingest fixture and produce canonical node record
python3 ingest_root_entropy.py commit-fixtures/commit_noquote.json > ingest_out.json

# Verify node_id contract
python3 ci/assert_node_id.py ingest_out.json commit-fixtures/commit_noquote.node_id
```

See `commit-fixtures/README.md` for detailed documentation and troubleshooting.
