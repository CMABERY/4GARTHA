# Transforms

Transforms are domain logic. A derivation record claims that a transform, run over its ordered input
records' artifacts with the given params, produced the output artifact. Replay checks that claim on the
verifying host. It does **not** establish that the transform does what its author says: a
transform that ignores its inputs and writes constant bytes replays perfectly. Reviewing transform
code is a human process (see [ASSURANCE.md](../ASSURANCE.md), Derivation verification).

Replay executes transform code **without an isolation boundary** (ASSURANCE.md, Execution safety).
Never replay records you would not run as your own user. The CI admission gate does not replay
submitted records.

## Interface `4gartha.transform-argv/1`

Record a derivation with `ledger derive out.bin --input <record ID> --transform-file path/to/transform.py`
(the transform is stored in the CAS by digest) and implement:

```
<runtime argv> transform.py \
  --parents-manifest <run>/parents.json \
  --parents-dir <run>/parents \
  --params-path <run>/params.json \
  --out <run>/out.bin
```

The record names a runtime (default `python3`), not a command. The verifier's policy decides what the name
runs. Full contract: [SPEC.md](../SPEC.md). Example: `concat_parents.py`.
