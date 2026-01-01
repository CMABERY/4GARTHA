# Transforms

Transforms are domain logic. The ledger only cares about one thing:

> given ordered parents and semantic params, the transform deterministically produces the child bytes.

## Replay contract (v0)

If you want **derivation replay** (`ledger replay ...`) to be possible, provide transform definitions
as blobs in the CAS (via `ledger ingest ... --transform-file path/to/transform.py`) and implement the
CLI contract:

```
<runner...> <transform_script> \
  --parents-manifest <workdir>/parents.json \
  --parents-dir <workdir>/parents \
  --params-path <workdir>/params.json \
  --out <workdir>/out.bin
```

See `concat_parents.py` for an example.
