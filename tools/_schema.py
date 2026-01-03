from __future__ import annotations
import json
from pathlib import Path
from typing import Any

class SchemaError(Exception):
    pass

def _load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def validate_or_raise(obj: Any, *, which: str) -> None:
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except Exception as e:
        raise SchemaError("jsonschema/referencing dependency missing") from e

    tbs = _load("schemas/tbs-v1.schema.json")
    receipt = _load("schemas/receipt-v1.schema.json")

    reg = Registry().with_resources([
        ("nre:tbs-v1", Resource.from_contents(tbs)),
        ("nre:receipt-v1", Resource.from_contents(receipt)),
    ])

    schema = tbs if which == "tbs" else receipt
    v = Draft202012Validator(schema, registry=reg)

    errs = sorted(v.iter_errors(obj), key=lambda e: list(e.path))
    if errs:
        msg = "; ".join([f"{list(e.path)}: {e.message}" for e in errs[:5]])
        raise SchemaError(msg)
