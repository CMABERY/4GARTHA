# Spec: Minimal Accounting Kernel

## Node manifest (canonical)

A node is identified by the **sha256 of the artifact bytes**.

The manifest lives at:

- `ledger/nodes/<sha256>.json`

The artifact bytes live at:

- `ledger/objects/<first2>/<sha256>` (or managed via Git LFS / external CAS; path stays stable)

### Fields

- `id` (string): sha256 hex of artifact bytes
- `parents` (array[string]): ordered parent ids (sha256)
- `transform` (object):
  - `name` (string): human label (not semantic)
  - `digest` (string): sha256 hex of transform definition (semantic)
  - `params` (object): canonical parameters (semantic)
- `meta` (object): non-semantic metadata (timestamps, notes, etc.)

## Truth boundary

Semantic validity (weak) requires only:

1. `id` matches artifact bytes
2. every `parents[i]` is reachable (its manifest exists) and is itself valid
3. `transform.digest` and `transform.params` are present (their interpretation is domain-defined)

Everything else is downstream projection.

## Strong verification: derivation replay

If you need the Derivation axiom ("child = deterministic transform(parents)") to be *machine-checked*,
you can require **replayable transforms**.

Minimal replay contract (v0):

- `transform.digest` must refer to a blob in the CAS (stored under `ledger/objects/`), containing an
  executable transform definition (by default, a Python script).
- Optional `transform.runner` pins the entrypoint as an argv prefix (e.g. `["python3", "-I"]`).
- Optional `transform.env_digest` pins an environment description (lockfile/Nix flake/container recipe).

Replay materializes ordered parents under a workdir and executes:

```
<runner...> <transform_script> \
  --parents-manifest <workdir>/parents.json \
  --parents-dir <workdir>/parents \
  --params-path <workdir>/params.json \
  --out <workdir>/out.bin
```

Replay succeeds iff `sha256(out.bin) == node.id`.

Notes:

- Root/admission nodes (no parents) have no derivation to replay.
- Replay executes code; run it only inside an appropriate sandbox for your threat model.
