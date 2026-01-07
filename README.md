# Epistemic Ledger Repo (Skeleton)

This repo contains two pieces of infrastructure:

1) **AGARTHA accounting kernel**: an immutable, content-addressed DAG embedded in Git.
2) **Sprint-1 fencepost (Frozen)**: an executable verifier gate (`nre-verify-fixtures --all`).

## 1) AGARTHA kernel (append-only truth graph + mutable pointers)

- **Node registry**: `sha256 -> artifact`
- **Edge registry**: `child -> ordered parents`
- **Derivation contract**: `(parents, transform) -> child` (deterministic)
- **Verification**: recompute hash; check parent reachability
- **Preservation**: replicate; never rewrite

## Directory layout

```
ledger/
  objects/            # content-addressed blobs (add-only)
  nodes/              # node manifests (add-only)
  refs/               # moving pointers (mutable convenience)
  schema/             # JSON schema for node manifests
transforms/           # pure transform code (your domain logic)
tools/                # governance + dev tooling
src/ledger/           # kernel library
schemas/              # Sprint-1 schema fencepost
canon/                # Sprint-1 canonicalization primitives
verify/               # Sprint-1 verifier
fixtures/             # Sprint-1 vectors + cases
cli/                  # Sprint-1 CLI entrypoints
ci/                   # CI scripts
.github/workflows/    # CI enforcement
tests/
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

Ingest an artifact:

```bash
ledger ingest path/to/artifact.bin --parent <hash> --transform "my_transform:v1" --transform-file transforms/my_transform.py
```

Point a ref at the new node:

```bash
ledger refs set latest <hash>
```

Verify a node:

```bash
ledger verify <hash>
```

Replay derivation (strong verification):

```bash
ledger replay <hash>
```

Or gate verification on replay:

```bash
ledger verify <hash> --replay
ledger verify-reachable <hash> --replay
```

## Governance invariant (enforced in CI)

- `ledger/objects/**` **add-only**
- `ledger/nodes/**` **add-only**
- `ledger/refs/**` mutable (pointers)
- everything else normal

Branch protection should disable force-push on protected branches; CI rejects rewrites of `objects/` or `nodes/`.

## Local hardening (pre-commit hook)

CI is necessary but not sufficient; a local hook prevents accidental self-inflicted rewrites.

Install the provided hook:

```bash
python tools/install_hooks.py
```

This installs `.git/hooks/pre-commit` which:

- rejects modify/delete/rename/copy under `ledger/objects/**` and `ledger/nodes/**`
- runs `nre-verify-fixtures --all` when Sprint-1-relevant files are staged

## Root Entropy Commit Fixtures

The repository includes infrastructure for verifying TPM-signed root entropy commit fixtures.

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
