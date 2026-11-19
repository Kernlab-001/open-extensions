from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_all_format_schemas_are_valid_json_schema():
    schema_paths = sorted((REPO_ROOT / "specs").glob("*/0.1.0/schema.json"))
    assert len(schema_paths) == 6
    for schema_path in schema_paths:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_memx_example_matches_payload_schema():
    schema = json.loads((REPO_ROOT / "specs/memx/0.1.0/schema.json").read_text(encoding="utf-8"))
    payload = json.loads((REPO_ROOT / "examples/memx/minimal.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = list(validator.iter_errors(payload))
    assert not errors, "; ".join(error.message for error in errors)
