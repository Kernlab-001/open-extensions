from __future__ import annotations

import struct

import pytest

from open_extensions._container import FormatError, canonical_json
from open_extensions.stepx import (
    FORMAT_VERSION,
    MAGIC,
    MAX_BODY_LENGTH,
    StepxError,
    StepxFormatError,
    StepxValidationError,
    create_stepx,
    evaluate_condition,
    inspect_stepx,
    read_stepx,
    render_stepx,
    scale_stepx,
    validate_stepx,
    write_stepx,
)


def _document() -> dict:
    """Return a valid STEPX document."""
    return {
        "format": "stepx",
        "format_version": FORMAT_VERSION,
        "title": "Pancakes",
        "category": "recipe",
        "base_yield": "4",
        "yield_unit": "servings",
        "ingredients": [
            {"id": "flour", "name": "flour", "quantity": "250", "unit": "g"},
            {"id": "milk", "name": "milk", "quantity": "500", "unit": "ml"},
            {"id": "salt", "name": "salt", "quantity": "1", "unit": "pinch", "scale_mode": "fixed"},
        ],
        "steps": [
            {
                "id": "mix",
                "order": 1,
                "title": "Mix",
                "instruction": "Combine the flour and the milk.",
                "ingredient_refs": ["flour", "milk"],
                "timer": {"duration_seconds": 60, "label": "Rest", "start_policy": "manual"},
            },
            {
                "id": "cook",
                "order": 2,
                "title": "Cook",
                "instruction": "Fry until golden.",
                "requires": ["mix"],
                "substitutions": [
                    {
                        "replaces": "milk",
                        "replacement": {
                            "id": "oat-milk",
                            "name": "oat milk",
                            "quantity": "500",
                            "unit": "ml",
                        },
                        "reason": "dairy free",
                        "when": [{"variable": "diet", "operator": "eq", "value": "vegan"}],
                    }
                ],
            },
        ],
    }


def _container_bytes(document: dict) -> bytes:
    """Build a container without create-time validation, to test the validator."""
    body = canonical_json(document)
    return MAGIC + struct.pack(">I", len(body)) + body


# --- container framing -----------------------------------------------------

def test_round_trip_preserves_the_document():
    document = _document()
    container = create_stepx(document)
    assert container.startswith(MAGIC)
    assert read_stepx(container) == document


def test_body_length_prefix_is_exact():
    container = create_stepx(_document())
    declared = struct.unpack(">I", container[9:13])[0]
    assert declared == len(container) - 13
    assert validate_stepx(container) == []


def test_write_stepx_round_trip(tmp_path):
    path = tmp_path / "recipe.stepx"
    write_stepx(path, _document())
    assert read_stepx(path) == _document()
    assert path.read_bytes().startswith(MAGIC)


def test_valid_document_has_no_errors():
    assert validate_stepx(create_stepx(_document())) == []


def test_wrong_magic_is_rejected():
    container = b"NOTSTEPX" + b"\x00\x00\x00\x02{}"
    assert validate_stepx(container)
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_trailing_bytes_are_rejected():
    container = create_stepx(_document()) + b"extra"
    assert validate_stepx(container)
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_oversized_body_length_is_rejected():
    container = MAGIC + struct.pack(">I", MAX_BODY_LENGTH + 1) + b"{}"
    assert validate_stepx(container)
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_body_length_below_the_minimum_is_rejected():
    container = MAGIC + struct.pack(">I", 1) + b"x"
    assert validate_stepx(container)
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_truncated_body_is_rejected():
    container = create_stepx(_document())[:-4]
    assert validate_stepx(container)
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_non_canonical_body_is_rejected():
    raw = b'{"format": "stepx"}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    errors = validate_stepx(container)
    assert errors and "canonical" in errors[0].lower()
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_duplicate_json_keys_are_rejected():
    raw = b'{"format":"stepx","format":"stepx"}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    errors = validate_stepx(container)
    assert errors
    with pytest.raises(StepxFormatError):
        read_stepx(container)


def test_non_finite_json_numbers_are_rejected():
    raw = b'{"format":"stepx","base_yield":NaN}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    assert validate_stepx(container)


def test_body_must_be_a_json_object():
    raw = b"[1,2,3]"
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    assert validate_stepx(container)


def test_format_errors_share_the_container_error_hierarchy():
    assert issubclass(StepxFormatError, StepxError)
    assert issubclass(StepxFormatError, FormatError)


# --- validation rules ------------------------------------------------------

def test_unknown_ingredient_reference_is_detected():
    document = _document()
    document["steps"][0]["ingredient_refs"] = ["flour", "nonexistent"]
    errors = validate_stepx(_container_bytes(document))
    assert any("nonexistent" in error for error in errors)


def test_unknown_step_reference_is_detected():
    document = _document()
    document["steps"][1]["requires"] = ["nowhere"]
    errors = validate_stepx(_container_bytes(document))
    assert any("nowhere" in error for error in errors)


def test_self_referencing_step_is_detected():
    document = _document()
    document["steps"][0]["requires"] = ["mix"]
    errors = validate_stepx(_container_bytes(document))
    assert any("itself" in error for error in errors)


def test_duplicate_ingredient_id_is_detected():
    document = _document()
    document["ingredients"].append(dict(document["ingredients"][0]))
    errors = validate_stepx(_container_bytes(document))
    assert any("unique" in error for error in errors)


def test_duplicate_step_id_is_detected():
    document = _document()
    document["steps"].append(dict(document["steps"][0]))
    errors = validate_stepx(_container_bytes(document))
    assert any("unique" in error for error in errors)


def test_non_contiguous_step_order_is_detected():
    document = _document()
    document["steps"][1]["order"] = 5
    errors = validate_stepx(_container_bytes(document))
    assert any("order" in error for error in errors)


def test_duplicate_step_order_is_detected():
    document = _document()
    document["steps"][1]["order"] = 1
    errors = validate_stepx(_container_bytes(document))
    assert any("order" in error for error in errors)


def test_bad_decimal_syntax_is_detected():
    document = _document()
    document["ingredients"][0]["quantity"] = "250.0.0"
    errors = validate_stepx(_container_bytes(document))
    assert any("decimal" in error for error in errors)


def test_exponent_notation_is_not_a_valid_decimal():
    document = _document()
    document["ingredients"][0]["quantity"] = "2.5e2"
    errors = validate_stepx(_container_bytes(document))
    assert any("decimal" in error for error in errors)


def test_zero_base_yield_is_detected():
    document = _document()
    document["base_yield"] = "0"
    errors = validate_stepx(_container_bytes(document))
    assert any("base_yield" in error for error in errors)


def test_bad_condition_operator_is_detected():
    document = _document()
    document["steps"][1]["substitutions"][0]["when"][0]["operator"] = "matches"
    errors = validate_stepx(_container_bytes(document))
    assert any("operator" in error for error in errors)


def test_declared_condition_variables_are_accepted():
    document = _document()
    document["conditions"] = {"diet": "vegan"}
    errors = validate_stepx(_container_bytes(document))
    assert errors == []


def test_condition_variable_outside_the_declared_conditions_is_detected():
    document = _document()
    document["conditions"] = {"diet": "vegan"}
    document["steps"][1]["substitutions"][0]["when"][0]["variable"] = "region"
    errors = validate_stepx(_container_bytes(document))
    assert any("region" in error and "allowed" in error for error in errors)


def test_explicit_allowlist_accepts_a_declared_variable():
    container = _container_bytes(_document())
    assert validate_stepx(container, allowed_variables=["diet"]) == []


def test_explicit_allowlist_rejects_an_undeclared_variable():
    container = _container_bytes(_document())
    errors = validate_stepx(container, allowed_variables=["region"])
    assert any("diet" in error and "allowed" in error for error in errors)


def test_create_with_an_explicit_allowlist_rejects_an_undeclared_variable():
    with pytest.raises(StepxValidationError):
        create_stepx(_document(), allowed_variables=["region"])


def test_read_with_an_explicit_allowlist_rejects_an_undeclared_variable():
    container = _container_bytes(_document())
    with pytest.raises(StepxValidationError):
        read_stepx(container, allowed_variables=["region"])


def test_cyclic_prerequisites_are_detected():
    document = _document()
    document["steps"][0]["requires"] = ["cook"]
    errors = validate_stepx(_container_bytes(document))
    assert any("cycle" in error for error in errors)


def test_cyclic_substitutions_are_detected():
    document = _document()
    document["steps"][0]["substitutions"] = [
        {
            "replaces": "flour",
            "replacement": {"id": "gf-flour", "name": "gluten free flour", "quantity": "250", "unit": "g"},
            "reason": "gluten free",
        }
    ]
    document["steps"][1]["substitutions"] = [
        {
            "replaces": "gf-flour",
            "replacement": {"id": "flour", "name": "flour", "quantity": "250", "unit": "g"},
            "reason": "contains gluten",
        }
    ]
    errors = validate_stepx(_container_bytes(document))
    assert any("cycle" in error for error in errors)


def test_bad_scale_mode_is_detected():
    document = _document()
    document["ingredients"][0]["scale_mode"] = "exponential"
    errors = validate_stepx(_container_bytes(document))
    assert any("scale_mode" in error for error in errors)


def test_bad_timer_duration_is_detected():
    document = _document()
    document["steps"][0]["timer"]["duration_seconds"] = 0
    errors = validate_stepx(_container_bytes(document))
    assert any("duration_seconds" in error for error in errors)


def test_timer_duration_must_be_an_integer():
    document = _document()
    document["steps"][0]["timer"]["duration_seconds"] = 60.5
    errors = validate_stepx(_container_bytes(document))
    assert any("duration_seconds" in error for error in errors)


def test_timer_duration_is_bounded():
    document = _document()
    document["steps"][0]["timer"]["duration_seconds"] = 604801
    errors = validate_stepx(_container_bytes(document))
    assert any("duration_seconds" in error for error in errors)


def test_bad_start_policy_is_detected():
    document = _document()
    document["steps"][0]["timer"]["start_policy"] = "on_load"
    errors = validate_stepx(_container_bytes(document))
    assert any("start_policy" in error for error in errors)


def test_unknown_format_version_is_detected():
    document = _document()
    document["format_version"] = "9.9.9"
    errors = validate_stepx(_container_bytes(document))
    assert any("format_version" in error for error in errors)


def test_schema_errors_are_surfaced():
    pytest.importorskip("jsonschema")
    document = _document()
    document["unexpected_root_field"] = "value"
    errors = validate_stepx(_container_bytes(document))
    assert any(error.startswith("schema:") for error in errors)


def test_schema_rejects_a_script_field():
    pytest.importorskip("jsonschema")
    document = _document()
    document["script"] = "rm -rf /"
    errors = validate_stepx(_container_bytes(document))
    assert any(error.startswith("schema:") for error in errors)


def test_create_rejects_an_invalid_document():
    document = _document()
    document["steps"][0]["ingredient_refs"] = ["nope"]
    with pytest.raises(StepxValidationError) as failure:
        create_stepx(document)
    assert failure.value.errors
    assert isinstance(failure.value.errors, list)


def test_read_stepx_rejects_a_semantically_invalid_document():
    document = _document()
    document["steps"][0]["ingredient_refs"] = ["nope"]
    with pytest.raises(StepxValidationError):
        read_stepx(_container_bytes(document))


# --- scaling ---------------------------------------------------------------

def test_scaling_uses_exact_decimal_arithmetic():
    document = _document()
    document["base_yield"] = "4"
    document["ingredients"][0]["quantity"] = "1"
    document["ingredients"][1]["quantity"] = "0.5"
    document["ingredients"].append(
        {"id": "sugar", "name": "sugar", "quantity": "0.125", "unit": "tsp"}
    )
    scaled = scale_stepx(document, "10")
    quantities = {i["id"]: i["quantity"] for i in scaled["ingredients"]}
    assert quantities["flour"] == "2.5"
    assert quantities["milk"] == "1.25"
    assert quantities["sugar"] == "0.3125"
    assert scaled["base_yield"] == "10"


def test_scaling_multiplies_linear_ingredients():
    scaled = scale_stepx(_document(), "10")
    quantities = {i["id"]: i["quantity"] for i in scaled["ingredients"]}
    assert quantities["flour"] == "625"
    assert quantities["milk"] == "1250"


def test_scaling_leaves_fixed_ingredients_alone():
    scaled = scale_stepx(_document(), "10")
    quantities = {i["id"]: i["quantity"] for i in scaled["ingredients"]}
    assert quantities["salt"] == "1"


def test_scaling_scales_substitution_replacements():
    scaled = scale_stepx(_document(), "10")
    replacement = scaled["steps"][1]["substitutions"][0]["replacement"]
    assert replacement["quantity"] == "1250"


def test_scaling_by_the_base_yield_is_a_no_op():
    scaled = scale_stepx(_document(), "4")
    quantities = {i["id"]: i["quantity"] for i in scaled["ingredients"]}
    assert quantities["flour"] == "250"


def test_scaling_keeps_thirty_four_significant_digits():
    document = _document()
    document["base_yield"] = "3"
    document["ingredients"][0]["quantity"] = "1"
    scaled = scale_stepx(document, "1")
    quantities = {i["id"]: i["quantity"] for i in scaled["ingredients"]}
    assert quantities["flour"] == "0.3333333333333333333333333333333333"


def test_scaled_document_is_still_valid():
    scaled = scale_stepx(_document(), "10")
    assert validate_stepx(create_stepx(scaled)) == []


def test_scaling_does_not_mutate_the_source():
    document = _document()
    scale_stepx(document, "10")
    assert document["ingredients"][0]["quantity"] == "250"
    assert document["base_yield"] == "4"


def test_scaling_rejects_a_bad_target():
    with pytest.raises(StepxValidationError):
        scale_stepx(_document(), "ten")
    with pytest.raises(StepxValidationError):
        scale_stepx(_document(), "0")


# --- rendering -------------------------------------------------------------

def test_render_text_contains_the_title_and_steps():
    text = render_stepx(_document(), "text")
    assert text
    assert "Pancakes" in text
    assert "Mix" in text
    assert "250 g flour" in text


def test_render_text_is_the_default_format():
    assert render_stepx(_document()) == render_stepx(_document(), "text")


def test_render_markdown_contains_headings():
    markdown = render_stepx(_document(), "markdown")
    assert markdown
    assert "# Pancakes" in markdown
    assert "## Ingredients" in markdown
    assert "## Steps" in markdown


def test_render_rejects_an_unknown_format():
    with pytest.raises(StepxFormatError):
        render_stepx(_document(), "pdf")


def test_render_never_executes_instruction_text(tmp_path):
    marker = tmp_path / "pwned"
    document = _document()
    document["steps"][0]["instruction"] = f"touch {marker} && touch {marker}"
    text = render_stepx(document, "text")
    assert str(marker) in text
    assert not marker.exists()


# --- inspection ------------------------------------------------------------

def test_inspect_summarises_the_document():
    summary = inspect_stepx(create_stepx(_document()))
    assert summary["format"] == "stepx"
    assert summary["format_version"] == FORMAT_VERSION
    assert summary["title"] == "Pancakes"
    assert summary["category"] == "recipe"
    assert summary["base_yield"] == "4"
    assert summary["yield_unit"] == "servings"
    assert summary["ingredient_count"] == 3
    assert summary["step_count"] == 2
    assert summary["condition_variables"] == ["diet"]


def test_inspect_summary_carries_no_instruction_text():
    summary = inspect_stepx(create_stepx(_document()))
    assert "Combine the flour" not in str(summary)
    assert "script" not in summary


# --- conditions ------------------------------------------------------------

def test_evaluate_condition_known_variable():
    condition = [{"variable": "diet", "operator": "eq", "value": "vegan"}]
    assert evaluate_condition(condition, {"diet": "vegan"}) is True
    assert evaluate_condition(condition, {"diet": "vegan-ish"}) is False


def test_evaluate_condition_unknown_variable_is_not_true():
    condition = [{"variable": "diet", "operator": "eq", "value": "vegan"}]
    assert evaluate_condition(condition, {}) is None
    assert not evaluate_condition(condition, {})


def test_evaluate_condition_in_operator():
    condition = [{"variable": "region", "operator": "in", "value": ["eu", "uk"]}]
    assert evaluate_condition(condition, {"region": "eu"}) is True
    assert evaluate_condition(condition, {"region": "us"}) is False


def test_evaluate_condition_not_in_operator():
    condition = [{"variable": "region", "operator": "not_in", "value": ["eu"]}]
    assert evaluate_condition(condition, {"region": "us"}) is True
    assert evaluate_condition(condition, {"region": "eu"}) is False


def test_evaluate_condition_ands_all_clauses():
    condition = [
        {"variable": "diet", "operator": "eq", "value": "vegan"},
        {"variable": "region", "operator": "eq", "value": "eu"},
    ]
    assert evaluate_condition(condition, {"diet": "vegan", "region": "eu"}) is True
    assert evaluate_condition(condition, {"diet": "vegan", "region": "us"}) is False
    assert evaluate_condition(condition, {"diet": "vegan"}) is None


def test_evaluate_condition_rejects_an_unsafe_operator():
    condition = [{"variable": "diet", "operator": "eval", "value": "vegan"}]
    assert evaluate_condition(condition, {"diet": "vegan"}) is False
