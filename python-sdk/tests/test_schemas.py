from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPECS = REPO_ROOT / "specs"
PACKAGED = (
    REPO_ROOT
    / "python-sdk"
    / "packages"
    / "open-extensions-core"
    / "src"
    / "open_extensions"
    / "schemas"
)

FORMATS = ("memx", "stepx", "gridv", "podx", "wapp", "tlock")


@pytest.mark.parametrize("format_name", FORMATS)
def test_the_packaged_schema_matches_the_specification(format_name: str):
    """The schema shipped in the package must be the one in specs/.

    The specification directory is the normative home for the schemas. The
    packaged copy exists so that schema validation works for a plain
    ``pip install``, so the two must not drift.
    """
    spec_schema = SPECS / format_name / "0.1.0" / "schema.json"
    packaged_schema = PACKAGED / f"{format_name}.json"
    assert spec_schema.is_file(), f"missing specification schema for {format_name}"
    assert packaged_schema.is_file(), f"missing packaged schema for {format_name}"
    assert json.loads(packaged_schema.read_text(encoding="utf-8")) == json.loads(
        spec_schema.read_text(encoding="utf-8")
    ), f"the packaged schema for {format_name} has drifted from specs/"


@pytest.mark.parametrize("format_name", FORMATS)
def test_the_packaged_schema_is_valid_json_schema(format_name: str):
    from jsonschema import Draft202012Validator

    schema = json.loads((PACKAGED / f"{format_name}.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("format_name", FORMATS)
def test_the_loader_finds_the_packaged_schema(format_name: str):
    """The schema must be found without a checkout, so the loader prefers
    the packaged copy over the repository's specs directory."""
    from open_extensions._container import load_schema

    schema = load_schema(format_name)
    assert schema is not None, f"no schema found for {format_name}"
    assert schema.get("type") == "object"
