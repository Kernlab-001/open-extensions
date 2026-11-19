"""STEPX v0.1 reference implementation.

``.stepx`` is a portable, structured instruction document for recipes, DIY
projects, repair procedures, and other step-driven guides. It models
quantities, yields, step timers, prerequisites, and conditional
substitutions as data.

Three boundaries are deliberate:

* **Nothing is executed.** A step instruction is text. The file has no
  script field and the reader must never execute instruction content.
* **Scaling is arithmetic, not judgment.** Ingredient scaling is not a
  substitute for culinary, chemical, structural, or safety judgment. Some
  quantities do not scale linearly, which is why ``scale_mode: "fixed"``
  exists.
* **Unit conversion never happens implicitly.** Grams, millilitres,
  teaspoons and item counts are not interchangeable. A consumer must not
  convert between them without a declared unit conversion profile, and
  v0.1 does not define one.

v0.1 carries no embedded media. Images may be referenced by an
application-level catalog in a later version; a reader never fetches them.
"""
from __future__ import annotations

import copy
import os
import re
from collections.abc import Iterable, Mapping
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from typing import Any

from ._container import (
    ContainerError,
    FormatError,
    atomic_write_bytes,
    canonical_json,
    format_decimal,
    parse_canonical_body,
    parse_decimal,
    read_length_prefixed,
    read_source,
    schema_errors,
)

MAGIC = b"STEPX\r\n\x1a\n"  # 9 bytes
FORMAT_VERSION = "0.1.0"

# The body length prefix is an unsigned 32-bit big-endian count of canonical
# JSON bytes, from 2 bytes up to 8 MiB.
MIN_BODY_LENGTH = 2
MAX_BODY_LENGTH = 8 * 1024 * 1024
MAX_CONTAINER_LENGTH = len(MAGIC) + 4 + MAX_BODY_LENGTH

# The schema's decimal pattern is stricter than a general decimal: no sign,
# no leading zero before the point, no bare zero. Quantities are positive.
_DECIMAL_RE = re.compile(r"^(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$")

CATEGORIES = {"recipe", "diy", "repair", "procedure", "other"}
SCALE_MODES = {"linear", "fixed"}
CONDITION_OPERATORS = {"eq", "neq", "in", "not_in"}
START_POLICIES = {"manual", "on_step_open"}

# Exact decimal arithmetic. 34 significant digits with round-half-even
# matches the precision convention used by the pinned spreadsheet formula
# profile, so a scaled quantity is reproducible across implementations.
DECIMAL_PRECISION = 34

MAX_TIMER_SECONDS = 604_800


class StepxError(ContainerError):
    """Base class for STEPX errors."""


class StepxFormatError(StepxError, FormatError):
    """The container framing or document is invalid or unsupported."""


class StepxValidationError(StepxError):
    """The document does not satisfy the v0.1 data model."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# --- helpers ---------------------------------------------------------------

def _is_decimal_string(value: Any) -> bool:
    """Return True for an exact positive decimal string."""
    return isinstance(value, str) and bool(_DECIMAL_RE.fullmatch(value))


def _decimal(value: Any, name: str) -> Decimal:
    """Parse a decimal string that already passed the decimal pattern."""
    try:
        return parse_decimal(value, name)
    except ContainerError as exc:
        raise StepxFormatError(str(exc)) from exc


def _validate_ingredient(ingredient: Any, prefix: str, errors: list[str]) -> str | None:
    """Validate one ingredient and return its id, or None when it has none."""
    if not isinstance(ingredient, dict):
        errors.append(f"{prefix} must be an object")
        return None
    required = {"id", "name", "quantity", "unit"}
    missing = required - ingredient.keys()
    if missing:
        errors.append(f"{prefix} is missing: {', '.join(sorted(missing))}")
    extra = ingredient.keys() - required - {"scale_mode", "preparation"}
    if extra:
        errors.append(f"{prefix} has unsupported field(s): {', '.join(sorted(extra))}")
    ingredient_id = ingredient.get("id")
    if not isinstance(ingredient_id, str) or not ingredient_id:
        errors.append(f"{prefix}.id must be a non-empty string")
        return None
    if not isinstance(ingredient.get("name"), str) or not ingredient.get("name"):
        errors.append(f"{prefix}.name must be a non-empty string")
    if not _is_decimal_string(ingredient.get("quantity")):
        errors.append(f"{prefix}.quantity must be a decimal string such as \"1\" or \"0.5\"")
    if not isinstance(ingredient.get("unit"), str) or not ingredient.get("unit"):
        errors.append(f"{prefix}.unit must be a non-empty string")
    scale_mode = ingredient.get("scale_mode", "linear")
    if not isinstance(scale_mode, str) or scale_mode not in SCALE_MODES:
        errors.append(f"{prefix}.scale_mode must be 'linear' or 'fixed'")
    if "preparation" in ingredient and not isinstance(ingredient["preparation"], str):
        errors.append(f"{prefix}.preparation must be a string")
    return ingredient_id


def _validate_condition(
    condition: Any,
    prefix: str,
    errors: list[str],
    allowed: set[str] | None = None,
) -> None:
    """Validate a condition clause list.

    The condition DSL is declarative only. A clause names a variable, one of
    the four safe operators, and a JSON scalar value; it can never hold an
    expression that a reader would evaluate as code. When ``allowed`` is not
    None, the clause variable must appear in that allowlist.
    """
    if not isinstance(condition, list):
        errors.append(f"{prefix} must be an array of clauses")
        return
    for index, clause in enumerate(condition):
        clause_prefix = f"{prefix}[{index}]"
        if not isinstance(clause, dict):
            errors.append(f"{clause_prefix} must be an object")
            continue
        if clause.keys() != {"variable", "operator", "value"}:
            errors.append(f"{clause_prefix} must contain exactly: variable, operator, value")
            continue
        if not isinstance(clause["variable"], str) or not clause["variable"]:
            errors.append(f"{clause_prefix}.variable must be a non-empty string")
        elif allowed is not None and clause["variable"] not in allowed:
            errors.append(
                f"{clause_prefix}.variable {clause['variable']!r} is not an allowed condition variable"
            )
        operator = clause["operator"]
        if not isinstance(operator, str) or operator not in CONDITION_OPERATORS:
            errors.append(f"{clause_prefix}.operator must be one of: {', '.join(sorted(CONDITION_OPERATORS))}")
        value = clause["value"]
        if not isinstance(value, (str, int, float, bool, list)) and value is not None:
            errors.append(f"{clause_prefix}.value must be a JSON scalar or array")


def _validate_step(
    step: Any,
    prefix: str,
    errors: list[str],
    allowed: set[str] | None = None,
) -> str | None:
    """Validate one step and return its id, or None when it has none."""
    if not isinstance(step, dict):
        errors.append(f"{prefix} must be an object")
        return None
    required = {"id", "order", "title", "instruction"}
    missing = required - step.keys()
    if missing:
        errors.append(f"{prefix} is missing: {', '.join(sorted(missing))}")
    extra = step.keys() - required - {"ingredient_refs", "requires", "timer", "substitutions"}
    if extra:
        errors.append(f"{prefix} has unsupported field(s): {', '.join(sorted(extra))}")
    step_id = step.get("id")
    if not isinstance(step_id, str) or not step_id:
        errors.append(f"{prefix}.id must be a non-empty string")
        return None
    order = step.get("order")
    if isinstance(order, bool) or not isinstance(order, int) or order < 1:
        errors.append(f"{prefix}.order must be an integer of at least 1")
    if not isinstance(step.get("title"), str):
        errors.append(f"{prefix}.title must be a string")
    if not isinstance(step.get("instruction"), str) or not step.get("instruction"):
        errors.append(f"{prefix}.instruction must be a non-empty string")
    if "ingredient_refs" in step:
        refs = step["ingredient_refs"]
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            errors.append(f"{prefix}.ingredient_refs must be an array of strings")
    if "requires" in step:
        requires = step["requires"]
        if not isinstance(requires, list) or any(not isinstance(ref, str) for ref in requires):
            errors.append(f"{prefix}.requires must be an array of strings")
    if "timer" in step:
        timer = step["timer"]
        if not isinstance(timer, dict):
            errors.append(f"{prefix}.timer must be an object")
        else:
            if timer.keys() != {"duration_seconds", "label", "start_policy"}:
                errors.append(f"{prefix}.timer must contain exactly: duration_seconds, label, start_policy")
            else:
                duration = timer["duration_seconds"]
                if isinstance(duration, bool) or not isinstance(duration, int) or not (1 <= duration <= MAX_TIMER_SECONDS):
                    errors.append(f"{prefix}.timer.duration_seconds must be an integer between 1 and {MAX_TIMER_SECONDS}")
                if not isinstance(timer["label"], str):
                    errors.append(f"{prefix}.timer.label must be a string")
                policy = timer["start_policy"]
                if not isinstance(policy, str) or policy not in START_POLICIES:
                    errors.append(f"{prefix}.timer.start_policy must be 'manual' or 'on_step_open'")
    if "substitutions" in step:
        substitutions = step["substitutions"]
        if not isinstance(substitutions, list):
            errors.append(f"{prefix}.substitutions must be an array")
        else:
            for index, substitution in enumerate(substitutions):
                sub_prefix = f"{prefix}.substitutions[{index}]"
                if not isinstance(substitution, dict):
                    errors.append(f"{sub_prefix} must be an object")
                    continue
                if not {"replaces", "replacement", "reason"} <= substitution.keys():
                    errors.append(f"{sub_prefix} is missing: replaces, replacement, reason")
                    continue
                extra_sub = substitution.keys() - {"replaces", "replacement", "reason", "when"}
                if extra_sub:
                    errors.append(f"{sub_prefix} has unsupported field(s): {', '.join(sorted(extra_sub))}")
                if not isinstance(substitution["replaces"], str) or not substitution["replaces"]:
                    errors.append(f"{sub_prefix}.replaces must be a non-empty string")
                _validate_ingredient(substitution["replacement"], f"{sub_prefix}.replacement", errors)
                if not isinstance(substitution["reason"], str) or not substitution["reason"]:
                    errors.append(f"{sub_prefix}.reason must be a non-empty string")
                if "when" in substitution:
                    _validate_condition(substitution["when"], f"{sub_prefix}.when", errors, allowed)
    return step_id


def _find_cycle(edges: dict[str, list[str]]) -> list[str] | None:
    """Return the first cycle in a directed graph as a node path, or None.

    The search is iterative, so a long dependency chain in a hostile file
    cannot exhaust the interpreter's call stack.
    """
    white, grey, black = 0, 1, 2
    state: dict[str, int] = {}
    for root in edges:
        if state.get(root, white) != white:
            continue
        stack: list[tuple[str, int]] = [(root, 0)]
        path: list[str] = []
        while stack:
            node, index = stack[-1]
            if index == 0:
                state[node] = grey
                path.append(node)
            neighbours = edges.get(node, [])
            if index < len(neighbours):
                stack[-1] = (node, index + 1)
                neighbour = neighbours[index]
                neighbour_state = state.get(neighbour, white)
                if neighbour_state == grey:
                    start = path.index(neighbour)
                    return path[start:] + [neighbour]
                if neighbour_state == white:
                    stack.append((neighbour, 0))
            else:
                state[node] = black
                stack.pop()
                path.pop()
    return None


def _detect_cycle(edges: dict[str, list[str]], label: str) -> list[str]:
    """Return a cycle description when the dependency graph is not acyclic."""
    cycle = _find_cycle(edges)
    if cycle is None:
        return []
    return [f"{label} cycle detected: {' -> '.join(cycle)}"]


def steps_by_id(steps: list[Any]) -> dict[str, list[str]]:
    """Map each step id to the step ids it requires."""
    graph: dict[str, list[str]] = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_id = step.get("id")
        if not isinstance(step_id, str):
            continue
        requires = step.get("requires")
        graph[step_id] = [r for r in requires if isinstance(r, str)] if isinstance(requires, list) else []
    return graph


def _substitution_graph(steps: list[Any]) -> dict[str, list[str]]:
    """Map each replaced ingredient id to the ids that replace it."""
    graph: dict[str, list[str]] = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        substitutions = step.get("substitutions")
        if not isinstance(substitutions, list):
            continue
        for substitution in substitutions:
            if not isinstance(substitution, dict):
                continue
            replaces = substitution.get("replaces")
            replacement = substitution.get("replacement")
            if not isinstance(replaces, str) or not isinstance(replacement, dict):
                continue
            replacement_id = replacement.get("id")
            if not isinstance(replacement_id, str):
                continue
            graph.setdefault(replaces, []).append(replacement_id)
            graph.setdefault(replacement_id, [])
    return graph


def _replacement_ids(steps: list[Any]) -> set[str]:
    """Return the ids introduced by substitution replacements."""
    ids: set[str] = set()
    for step in steps:
        if not isinstance(step, dict):
            continue
        substitutions = step.get("substitutions")
        if not isinstance(substitutions, list):
            continue
        for substitution in substitutions:
            if not isinstance(substitution, dict):
                continue
            replacement = substitution.get("replacement")
            if isinstance(replacement, dict) and isinstance(replacement.get("id"), str):
                ids.add(replacement["id"])
    return ids


def _allowed_variables(document: Any, allowed_variables: Iterable[str] | None) -> set[str] | None:
    """Return the condition variables a document may use, or None for no policy.

    An explicit allowlist supplied by the application wins. Otherwise a
    document that declares a root ``conditions`` object names its own
    variables there, and those names form the allowlist. A document that
    declares nothing carries no variable policy, because condition variables
    are application-defined and an unknown variable only ever evaluates as
    unknown.
    """
    if allowed_variables is not None:
        return {name for name in allowed_variables if isinstance(name, str)}
    conditions = document.get("conditions") if isinstance(document, dict) else None
    if isinstance(conditions, dict):
        return {name for name in conditions if isinstance(name, str)}
    return None


def _validate_document(document: Any, allowed_variables: Iterable[str] | None = None) -> list[str]:
    """Full semantic validation of a STEPX document.

    The checks follow section 4 of ``specs/stepx/0.1.0/spec.md``: schema
    conformance, unique identifiers, valid ingredient references, step order,
    timers, exact decimal syntax, safe condition operators, and cycles in
    prerequisites and substitutions. The validator build plan of section 5
    also asks for condition-variable allowlists, so a condition variable must
    appear in the allowed set when one is in force.
    """
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document root must be an object"]
    errors.extend(schema_errors("stepx", document))
    allowed = _allowed_variables(document, allowed_variables)

    if document.get("format") != "stepx":
        errors.append("format must equal 'stepx'")
    if document.get("format_version") != FORMAT_VERSION:
        errors.append(f"format_version must equal {FORMAT_VERSION}")
    title = document.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("title must be a non-empty string")
    category = document.get("category")
    if not isinstance(category, str) or category not in CATEGORIES:
        errors.append(f"category must be one of: {', '.join(sorted(CATEGORIES))}")
    if not _is_decimal_string(document.get("base_yield")):
        errors.append("base_yield must be a positive decimal string such as \"4\"")
    elif _decimal(document["base_yield"], "base_yield") <= 0:
        errors.append("base_yield must be greater than zero")
    if not isinstance(document.get("yield_unit"), str) or not document.get("yield_unit"):
        errors.append("yield_unit must be a non-empty string")

    if "conditions" in document:
        conditions = document["conditions"]
        if not isinstance(conditions, dict):
            errors.append("conditions must be an object")
        else:
            for name, value in conditions.items():
                if not isinstance(value, (str, int, float, bool, list)) and value is not None:
                    errors.append(f"conditions[{name!r}] must be a JSON scalar or array")

    ingredients = document.get("ingredients")
    ingredient_ids: list[str] = []
    if not isinstance(ingredients, list):
        errors.append("ingredients must be an array")
        ingredients = []
    for index, ingredient in enumerate(ingredients):
        ingredient_id = _validate_ingredient(ingredient, f"ingredients[{index}]", errors)
        if ingredient_id is not None:
            ingredient_ids.append(ingredient_id)
    duplicate_ingredients = {i for i in ingredient_ids if ingredient_ids.count(i) > 1}
    for duplicate in sorted(duplicate_ingredients):
        errors.append(f"ingredient id {duplicate!r} must be unique")

    steps = document.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("steps must be a non-empty array")
        steps = []
    step_ids: list[str] = []
    orders: list[int] = []
    for index, step in enumerate(steps):
        step_id = _validate_step(step, f"steps[{index}]", errors, allowed)
        if step_id is not None:
            step_ids.append(step_id)
        if isinstance(step, dict) and isinstance(step.get("order"), int) and not isinstance(step.get("order"), bool):
            orders.append(step["order"])
    duplicate_steps = {s for s in step_ids if step_ids.count(s) > 1}
    for duplicate in sorted(duplicate_steps):
        errors.append(f"step id {duplicate!r} must be unique")
    if orders:
        if len(set(orders)) != len(orders):
            errors.append("step order values must be unique")
        elif sorted(orders) != list(range(1, len(orders) + 1)):
            errors.append("step order values must be contiguous and start at 1")

    known_ingredients = set(ingredient_ids) | _replacement_ids(steps)
    known_steps = set(step_ids)
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        for ref in step.get("ingredient_refs", []) or []:
            if isinstance(ref, str) and ref not in known_ingredients:
                errors.append(f"steps[{index}].ingredient_refs references unknown ingredient {ref!r}")
        for ref in step.get("requires", []) or []:
            if isinstance(ref, str) and ref not in known_steps:
                errors.append(f"steps[{index}].requires references unknown step {ref!r}")
            elif isinstance(ref, str) and ref == step.get("id"):
                errors.append(f"steps[{index}].requires must not reference itself")
        for substitution in step.get("substitutions", []) or []:
            if not isinstance(substitution, dict):
                continue
            replaces = substitution.get("replaces")
            if isinstance(replaces, str) and replaces not in known_ingredients:
                errors.append(f"steps[{index}] substitution replaces unknown ingredient {replaces!r}")

    errors.extend(_detect_cycle(steps_by_id(steps), "step prerequisite"))
    errors.extend(_detect_cycle(_substitution_graph(steps), "substitution"))
    return errors


# --- container -------------------------------------------------------------

def _parse_container(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> dict[str, Any]:
    """Parse the STEPX container and return its document.

    Framing, canonical JSON, and duplicate-key rejection all happen here, and
    every failure is reported as a :class:`StepxFormatError`.
    """
    try:
        raw = read_source(source, MAX_CONTAINER_LENGTH, "STEPX file")
        body, offset = read_length_prefixed(
            raw,
            MAGIC,
            prefix_size=4,
            min_length=MIN_BODY_LENGTH,
            max_length=MAX_BODY_LENGTH,
            label="STEPX document",
        )
    except ContainerError as exc:
        raise StepxFormatError(str(exc)) from exc
    if offset != len(raw):
        raise StepxFormatError("Trailing bytes are not allowed after a STEPX document")
    try:
        return parse_canonical_body(body, "STEPX document")
    except ContainerError as exc:
        raise StepxFormatError(str(exc)) from exc


def create_stepx(
    document: Mapping[str, Any],
    allowed_variables: Iterable[str] | None = None,
) -> bytes:
    """Create a STEPX container and return its bytes.

    The document is validated first, so an invalid document raises
    :class:`StepxValidationError` instead of producing a broken file.
    ``allowed_variables`` is the optional condition-variable allowlist of the
    application; None means the document's own declarations apply.
    """
    if not isinstance(document, Mapping):
        raise TypeError("document must be a mapping")
    candidate = dict(document)
    errors = _validate_document(candidate, allowed_variables)
    if errors:
        raise StepxValidationError(errors)
    try:
        body = canonical_json(candidate)
    except ContainerError as exc:
        raise StepxFormatError(str(exc)) from exc
    if not (MIN_BODY_LENGTH <= len(body) <= MAX_BODY_LENGTH):
        raise StepxFormatError("Canonical document size exceeds the v0.1 limit")
    return MAGIC + len(body).to_bytes(4, "big") + body


def read_stepx(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    allowed_variables: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Read a STEPX file and return its validated document.

    ``allowed_variables`` is the optional condition-variable allowlist of the
    application; None means the document's own declarations apply.
    """
    document = _parse_container(source)
    errors = _validate_document(document, allowed_variables)
    if errors:
        raise StepxValidationError(errors)
    return document


def write_stepx(output: str | os.PathLike[str], document: Mapping[str, Any]) -> None:
    """Write a STEPX file with an atomic replacement."""
    atomic_write_bytes(output, create_stepx(document))


def validate_stepx(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    allowed_variables: Iterable[str] | None = None,
) -> list[str]:
    """Return validation errors for a STEPX container.

    An empty list means the container is valid. A framing problem is reported
    as a single error string rather than raised. ``allowed_variables`` is the
    optional condition-variable allowlist of the application; None means the
    document's own declarations apply.
    """
    try:
        document = _parse_container(source)
    except ContainerError as exc:
        return [str(exc)]
    return _validate_document(document, allowed_variables)


def inspect_stepx(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> dict[str, Any]:
    """Return a non-secret summary of a STEPX document.

    The summary holds the format identity, the title, the category, the base
    yield, the counts of ingredients and steps, and the condition variables the
    document refers to. v0.1 has no script or executable content to hide.
    """
    document = _parse_container(source)
    ingredients = document.get("ingredients") if isinstance(document.get("ingredients"), list) else []
    steps = document.get("steps") if isinstance(document.get("steps"), list) else []
    variables: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        for substitution in step.get("substitutions", []) or []:
            if not isinstance(substitution, dict):
                continue
            for clause in substitution.get("when", []) or []:
                if isinstance(clause, dict) and isinstance(clause.get("variable"), str):
                    if clause["variable"] not in variables:
                        variables.append(clause["variable"])
    return {
        "format": document.get("format"),
        "format_version": document.get("format_version"),
        "title": document.get("title"),
        "category": document.get("category"),
        "base_yield": document.get("base_yield"),
        "yield_unit": document.get("yield_unit"),
        "ingredient_count": len(ingredients),
        "step_count": len(steps),
        "condition_variables": sorted(variables),
    }


# --- scaling ---------------------------------------------------------------

def _iter_ingredients(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return every ingredient of a document, including substitution replacements."""
    ingredients: list[dict[str, Any]] = []
    root = document.get("ingredients")
    if isinstance(root, list):
        ingredients.extend(item for item in root if isinstance(item, dict))
    steps = document.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            substitutions = step.get("substitutions")
            if not isinstance(substitutions, list):
                continue
            for substitution in substitutions:
                if not isinstance(substitution, dict):
                    continue
                replacement = substitution.get("replacement")
                if isinstance(replacement, dict):
                    ingredients.append(replacement)
    return ingredients


def _scale_quantity(ingredient: Mapping[str, Any], factor: Decimal) -> str:
    """Return the scaled quantity of one ingredient as an exact decimal string."""
    if ingredient.get("scale_mode", "linear") != "linear":
        return str(ingredient.get("quantity"))
    quantity = _decimal(ingredient.get("quantity"), "ingredient quantity")
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        scaled = quantity * factor
    text = format_decimal(scaled)
    if not _is_decimal_string(text):
        raise StepxValidationError([f"scaled quantity {text!r} is not a valid decimal"])
    return text


def scale_stepx(document: Mapping[str, Any], target_yield: str) -> dict[str, Any]:
    """Return a copy of the document scaled to ``target_yield``.

    The factor is ``target_yield / base_yield`` computed with exact decimal
    arithmetic: 34 significant digits with round-half-even, matching the
    pinned spreadsheet formula profile. Only ingredients with ``scale_mode``
    ``"linear"`` (the default) are scaled; ingredients marked ``"fixed"`` keep
    their quantity, and unit conversion is never performed. The scaled
    document's ``base_yield`` becomes the target yield.
    """
    if not isinstance(document, Mapping):
        raise TypeError("document must be a mapping")
    candidate = dict(document)
    errors = _validate_document(candidate)
    if errors:
        raise StepxValidationError(errors)
    if not _is_decimal_string(target_yield):
        raise StepxValidationError(["target yield must be a positive decimal string such as \"10\""])
    target = _decimal(target_yield, "target yield")
    if target <= 0:
        raise StepxValidationError(["target yield must be greater than zero"])

    base = _decimal(candidate["base_yield"], "base_yield")
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        factor = target / base

    scaled = copy.deepcopy(candidate)
    scaled["base_yield"] = format_decimal(target)
    for ingredient in _iter_ingredients(scaled):
        ingredient["quantity"] = _scale_quantity(ingredient, factor)
    return scaled


# --- conditions ------------------------------------------------------------

def evaluate_condition(condition: Any, variables: Mapping[str, Any]) -> bool | None:
    """Evaluate a condition against ``variables``.

    Returns ``True`` when every clause holds, ``False`` when a clause fails,
    and ``None`` when the result is unknown because a variable was not
    supplied. Unknown is never true, so a substitution guarded by an unknown
    condition must not be applied.
    """
    if not isinstance(condition, list):
        return False
    for clause in condition:
        if not isinstance(clause, dict):
            return False
        variable = clause.get("variable")
        if not isinstance(variable, str) or variable not in variables:
            return None
        actual = variables[variable]
        expected = clause.get("value")
        operator = clause.get("operator")
        if operator == "eq":
            if actual != expected:
                return False
        elif operator == "neq":
            if actual == expected:
                return False
        elif operator == "in":
            if not isinstance(expected, list) or actual not in expected:
                return False
        elif operator == "not_in":
            if not isinstance(expected, list) or actual in expected:
                return False
        else:
            return False
    return True


# --- rendering -------------------------------------------------------------

def _ordered_steps(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the steps of a document ordered by their step order."""
    steps = [s for s in document.get("steps", []) if isinstance(s, dict)]
    return sorted(steps, key=lambda s: s.get("order", 0))


def _ingredient_map(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ingredient ids to their ingredient objects."""
    mapping: dict[str, dict[str, Any]] = {}
    for ingredient in document.get("ingredients", []):
        if isinstance(ingredient, dict) and isinstance(ingredient.get("id"), str):
            mapping[ingredient["id"]] = ingredient
    return mapping


def _condition_text(condition: Any) -> str:
    """Return a readable summary of a condition clause list."""
    if not isinstance(condition, list):
        return ""
    clauses = []
    for clause in condition:
        if not isinstance(clause, dict):
            continue
        value = clause.get("value")
        if isinstance(value, str):
            rendered = value
        elif isinstance(value, list):
            rendered = ", ".join(str(item) for item in value)
        else:
            rendered = str(value)
        clauses.append(f"{clause.get('variable')} {clause.get('operator')} {rendered}")
    return " and ".join(clauses)


def render_stepx(document: Mapping[str, Any], fmt: str = "text") -> str:
    """Render a STEPX document as plain text or Markdown.

    Only the data of the document is rendered. Instruction text is printed
    verbatim and is never executed, and no substitution is applied without
    the variables to evaluate it against.
    """
    if fmt not in ("text", "markdown"):
        raise StepxFormatError("format must be 'text' or 'markdown'")
    if not isinstance(document, Mapping):
        raise TypeError("document must be a mapping")
    candidate = dict(document)
    errors = _validate_document(candidate)
    if errors:
        raise StepxValidationError(errors)

    ingredients = _ingredient_map(candidate)
    steps = _ordered_steps(candidate)
    lines: list[str] = []
    title = candidate["title"]

    if fmt == "markdown":
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"*Category:* {candidate['category']}")
        lines.append(f"*Yield:* {candidate['base_yield']} {candidate['yield_unit']}")
        lines.append("")
        lines.append("## Ingredients")
        lines.append("")
        for ingredient in candidate.get("ingredients", []):
            if not isinstance(ingredient, dict):
                continue
            note = f" ({ingredient['preparation']})" if ingredient.get("preparation") else ""
            lines.append(f"- {ingredient['quantity']} {ingredient['unit']} {ingredient['name']}{note}")
        lines.append("")
        lines.append("## Steps")
        lines.append("")
        for step in steps:
            lines.append(f"### {step.get('order', '?')}. {step.get('title', '')}")
            lines.append("")
            lines.append(step.get("instruction", ""))
            timer = step.get("timer")
            if isinstance(timer, dict):
                lines.append("")
                lines.append(f"*{timer.get('label', 'Timer')}: {timer.get('duration_seconds', 0)} seconds "
                             f"({timer.get('start_policy', 'manual')}).*")
            for substitution in step.get("substitutions", []) or []:
                if not isinstance(substitution, dict):
                    continue
                replacement = substitution.get("replacement", {})
                condition = _condition_text(substitution.get("when"))
                suffix = f" when {condition}" if condition else ""
                lines.append(f"* Substitute {replacement.get('name', '')} for "
                             f"{substitution.get('replaces', '')}: {substitution.get('reason', '')}{suffix}.")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    lines.append(title)
    lines.append("=" * len(title))
    lines.append(f"Category: {candidate['category']}")
    lines.append(f"Yield: {candidate['base_yield']} {candidate['yield_unit']}")
    lines.append("")
    lines.append("Ingredients")
    lines.append("-----------")
    for ingredient in candidate.get("ingredients", []):
        if not isinstance(ingredient, dict):
            continue
        note = f" ({ingredient['preparation']})" if ingredient.get("preparation") else ""
        lines.append(f"  {ingredient['quantity']} {ingredient['unit']} {ingredient['name']}{note}")
    lines.append("")
    lines.append("Steps")
    lines.append("-----")
    for step in steps:
        lines.append(f"{step.get('order', '?')}. {step.get('title', '')}")
        lines.append(f"   {step.get('instruction', '')}")
        timer = step.get("timer")
        if isinstance(timer, dict):
            lines.append(f"   [Timer: {timer.get('label', 'Timer')} - {timer.get('duration_seconds', 0)} seconds, "
                         f"{timer.get('start_policy', 'manual')}]")
        refs = [ingredients[r] for r in step.get("ingredient_refs", []) or [] if r in ingredients]
        for ingredient in refs:
            lines.append(f"   Uses: {ingredient['quantity']} {ingredient['unit']} {ingredient['name']}")
        for substitution in step.get("substitutions", []) or []:
            if not isinstance(substitution, dict):
                continue
            replacement = substitution.get("replacement", {})
            condition = _condition_text(substitution.get("when"))
            suffix = f" when {condition}" if condition else ""
            lines.append(
                f"   Substitute {replacement.get('quantity', '')} {replacement.get('unit', '')} "
                f"{replacement.get('name', '')} for {substitution.get('replaces', '')} "
                f"({substitution.get('reason', '')}){suffix}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
