# Contributing

## Non-negotiables

- `ledger/nodes/**` is **append-only**
- `ledger/objects/**` is **append-only**
- refs are mutable (`ledger/refs/**`)

CI rejects rewrites.

## Local hardening

Install the provided pre-commit hook (recommended):

```bash
python tools/install_hooks.py
```

The hook blocks any staged modify/delete/rename/copy under `ledger/nodes/**` or `ledger/objects/**`.

## Adding truth

1. Run `ledger ingest ...` to store the blob and write an immutable node manifest.
   - For replayable derivations, use `--transform-file` so the transform definition is stored in the CAS.
2. Update or create a ref under `ledger/refs/` if you want a moving pointer.
3. Open a PR. CI will:
   - lint + test
   - enforce append-only invariants
   - (optional) replay new derived nodes when configured for your threat model
