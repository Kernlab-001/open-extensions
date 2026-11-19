"""GRIDV v0.1 reference implementation.

The ``.gridv`` container is an append-only spreadsheet history. A canonical
JSON header is followed by hash-chained event frames; every frame stores the
canonical JSON bytes of one event plus ``SHA-256(previous hash || event
bytes)``. Deleting, reordering or editing a frame breaks the chain, so the
log is tamper-evident even though it is not authenticated.

This module implements the container, the validator, the replay helpers and
the CSV exporter described in ``specs/gridv/0.1.0/spec.md``. It deliberately
does **not** implement a formula engine. The workbook pins the
``nxf-formula-0.1`` profile in its header, and reconstructed formula cells
carry their source string, never a recalculated value.
"""
from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import struct
import uuid
from collections.abc import Mapping
from typing import Any

from ._container import (
    ContainerError,
    FormatError,
    atomic_write_bytes,
    canonical_json,
    parse_canonical_body,
    parse_decimal,
    read_length_prefixed,
    read_source,
    schema_errors,
    timestamp_is_valid,
    utc_now,
)

MAGIC = b"GRIDV\r\n\x1a\n"  # 9 bytes
FORMAT_VERSION = "0.1.0"
FORMULA_PROFILE = "nxf-formula-0.1"

MIN_HEADER_LENGTH = 2
MAX_HEADER_LENGTH = 64 * 1024
MIN_EVENT_LENGTH = 2
MAX_EVENT_LENGTH = 64 * 1024 * 1024
MAX_CONTAINER_LENGTH = 512 * 1024 * 1024
HASH_LENGTH = 32
MAX_FORMULA_LENGTH = 4096
MAX_STYLE_ATTRIBUTES = 32
MAX_STYLE_KEY_LENGTH = 64
MAX_STYLE_VALUE_LENGTH = 256
MAX_IDENTIFIER_LENGTH = 200

REQUIRED_OPS = (
    "workbook.create",
    "sheet.add",
    "sheet.remove",
    "sheet.rename",
    "row.insert",
    "row.delete",
    "column.insert",
    "column.delete",
    "cell.set",
    "formula.set",
    "style.set",
    "checkpoint",
)

PROFILE_FUNCTIONS = frozenset(
    {
        "SUM",
        "MIN",
        "MAX",
        "COUNT",
        "COUNTA",
        "AVERAGE",
        "IF",
        "AND",
        "OR",
        "NOT",
        "ABS",
        "ROUND",
        "LEFT",
        "RIGHT",
        "LEN",
        "CONCAT",
    }
)

CELL_TYPES = ("string", "decimal", "boolean", "date", "empty")

_HEADER_REQUIRED_FIELDS = (
    "format",
    "format_version",
    "workbook_id",
    "created_at",
    "formula_profile",
    "time_zone",
    "initial_state_hash",
)
_EVENT_FIELDS = ("seq", "event_id", "recorded_at", "actor_id", "op", "data")
_RECOVERED_EXTENSION = "open-extensions.gridv.recovered"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_DATE_RE = re.compile(r"^\d{4}-\d\d-\d\d$")
_FUNCTION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.]*)\s*\(")


class GridvError(ContainerError):
    """Base class for GRIDV errors."""


class GridvFormatError(GridvError, FormatError):
    """The container framing or header is invalid or unsupported."""


class GridvValidationError(GridvError):
    """The document does not satisfy the v0.1 data model."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# --- canonical JSON --------------------------------------------------------

def _canonical(value: Any, label: str) -> bytes:
    """Serialize a value to canonical JSON, reporting failures as format errors."""
    try:
        return canonical_json(value)
    except FormatError as exc:
        raise GridvFormatError(f"{label} cannot be represented as canonical JSON: {exc}") from exc


def _digest(data: bytes) -> str:
    """Return the lowercase SHA-256 hex digest of some bytes."""
    return hashlib.sha256(data).hexdigest()


def _state_digest(sheets: Any, settings: Any) -> str:
    """Return the digest of the canonical initial workbook state."""
    return _digest(canonical_json({"settings": settings, "sheets": sheets}))


def _new_event_id() -> str:
    """Return a fresh opaque event identifier."""
    return f"evt-{uuid.uuid4().hex}"


# --- structural validation --------------------------------------------------

def _cell_value_errors(value: Any, label: str) -> list[str]:
    """Return the errors of a typed cell value."""
    if not isinstance(value, dict):
        return [f"{label} must be an object"]
    kind = value.get("type")
    if kind not in CELL_TYPES:
        return [f"{label}.type must be one of: {', '.join(CELL_TYPES)}"]
    if kind == "empty":
        if "value" in value:
            return [f"{label} of type 'empty' must not carry a value"]
        return []
    if set(value) != {"type", "value"}:
        return [f"{label} must contain exactly 'type' and 'value'"]
    payload = value["value"]
    if kind == "string":
        if not isinstance(payload, str):
            return [f"{label}.value must be a string"]
        return []
    if kind == "decimal":
        if not isinstance(payload, str):
            return [f"{label}.value must be a decimal string"]
        try:
            parse_decimal(payload, f"{label}.value")
        except FormatError as exc:
            return [str(exc)]
        return []
    if kind == "boolean":
        if not isinstance(payload, bool):
            return [f"{label}.value must be a boolean"]
        return []
    if not isinstance(payload, str) or not _DATE_RE.fullmatch(payload):
        return [f"{label}.value must be an ISO calendar date (YYYY-MM-DD)"]
    return []


def _style_errors(style: Any, label: str) -> list[str]:
    """Return the errors of a bounded style attribute object."""
    if not isinstance(style, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    if len(style) > MAX_STYLE_ATTRIBUTES:
        errors.append(f"{label} must not hold more than {MAX_STYLE_ATTRIBUTES} attributes")
    for key, value in style.items():
        if not isinstance(key, str) or not key or len(key) > MAX_STYLE_KEY_LENGTH:
            errors.append(
                f"{label} attribute names must be non-empty strings of at most "
                f"{MAX_STYLE_KEY_LENGTH} characters"
            )
            continue
        if isinstance(value, str):
            if len(value) > MAX_STYLE_VALUE_LENGTH:
                errors.append(f"{label} attribute {key!r} exceeds {MAX_STYLE_VALUE_LENGTH} characters")
        elif value is not None and not isinstance(value, (bool, int, float)):
            errors.append(f"{label} attribute {key!r} must be a string, number, boolean or null")
    return errors


def _item_id(item: Any) -> str | None:
    """Return the identifier of a row or column definition."""
    if isinstance(item, str):
        return item or None
    if isinstance(item, dict):
        value = item.get("id")
        if isinstance(value, str) and value:
            return value
    return None


def _cell_errors(cell: Any, label: str) -> list[str]:
    """Return the errors of a cell definition."""
    if not isinstance(cell, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    allowed = {"row_id", "column_id", "value", "formula", "style"}
    missing = {"row_id", "column_id"} - cell.keys()
    extra = cell.keys() - allowed
    if missing:
        errors.append(f"{label} is missing: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(sorted(extra))}")
    if errors:
        return errors
    for key in ("row_id", "column_id"):
        if not isinstance(cell[key], str) or not cell[key]:
            errors.append(f"{label}.{key} must be a non-empty string")
    if cell.get("value") is not None:
        errors.extend(_cell_value_errors(cell["value"], f"{label}.value"))
    if cell.get("formula") is not None and not isinstance(cell["formula"], str):
        errors.append(f"{label}.formula must be a string")
    if cell.get("style") is not None:
        errors.extend(_style_errors(cell["style"], f"{label}.style"))
    return errors


def _sheet_errors(sheet: Any, label: str) -> list[str]:
    """Return the errors of a sheet definition."""
    if not isinstance(sheet, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    required = {"id", "name"}
    missing = required - sheet.keys()
    extra = sheet.keys() - required - {"rows", "columns", "cells"}
    if missing:
        errors.append(f"{label} is missing: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(sorted(extra))}")
    if errors:
        return errors
    sheet_id = sheet["id"]
    if not isinstance(sheet_id, str) or not sheet_id or len(sheet_id) > MAX_IDENTIFIER_LENGTH:
        errors.append(f"{label}.id must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters")
    name = sheet["name"]
    if not isinstance(name, str) or not name or len(name) > MAX_IDENTIFIER_LENGTH:
        errors.append(f"{label}.name must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters")
    for key in ("rows", "columns"):
        items = sheet.get(key, [])
        if not isinstance(items, list):
            errors.append(f"{label}.{key} must be an array")
            continue
        seen: set[str] = set()
        for index, item in enumerate(items):
            identifier = _item_id(item)
            if identifier is None:
                errors.append(f"{label}.{key}[{index}] must be an id or an object with an 'id'")
                continue
            if identifier in seen:
                errors.append(f"{label}.{key}[{index}] repeats the id {identifier!r}")
            seen.add(identifier)
    cells = sheet.get("cells", {})
    if not isinstance(cells, dict):
        errors.append(f"{label}.cells must be an object")
    else:
        for cell_id, cell in cells.items():
            errors.extend(_cell_errors(cell, f"{label}.cells[{cell_id!r}]"))
    return errors


def _initial_state_errors(state: Any) -> list[str]:
    """Return the errors of an initial workbook state."""
    if not isinstance(state, dict):
        return ["initial state must be an object"]
    errors: list[str] = []
    extra = state.keys() - {"sheets", "settings"}
    if extra:
        errors.append(f"initial state has unsupported fields: {', '.join(sorted(extra))}")
    if "sheets" not in state:
        errors.append("initial state is missing 'sheets'")
    else:
        sheets = state["sheets"]
        if not isinstance(sheets, list):
            errors.append("initial state sheets must be an array")
        else:
            for index, sheet in enumerate(sheets):
                errors.extend(_sheet_errors(sheet, f"initial state sheets[{index}]"))
    if "settings" in state and not isinstance(state["settings"], dict):
        errors.append("initial state settings must be an object")
    return errors


def _header_errors(header: Any) -> list[str]:
    """Return the errors of a container header."""
    if not isinstance(header, dict):
        return ["header must be a JSON object"]
    errors: list[str] = []
    missing = set(_HEADER_REQUIRED_FIELDS) - header.keys()
    extra = header.keys() - set(_HEADER_REQUIRED_FIELDS) - {"extensions"}
    if missing:
        errors.append(f"header is missing: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"header has unsupported fields: {', '.join(sorted(extra))}")
    if header.get("format") != "gridv":
        errors.append('header format must be "gridv"')
    if header.get("format_version") != FORMAT_VERSION:
        errors.append(f"header format_version must equal {FORMAT_VERSION}")
    if header.get("formula_profile") != FORMULA_PROFILE:
        errors.append(f"header formula_profile must equal {FORMULA_PROFILE}")
    if header.get("time_zone") != "UTC":
        errors.append('header time_zone must be "UTC"')
    workbook_id = header.get("workbook_id")
    if not isinstance(workbook_id, str) or not workbook_id or len(workbook_id) > MAX_IDENTIFIER_LENGTH:
        errors.append(
            f"header workbook_id must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters"
        )
    if not timestamp_is_valid(header.get("created_at")):
        errors.append("header created_at must be an RFC 3339 UTC timestamp ending in Z")
    if not _HEX_RE.fullmatch(str(header.get("initial_state_hash", ""))):
        errors.append("header initial_state_hash must be a lowercase SHA-256 hex digest")
    if "extensions" in header and not isinstance(header["extensions"], dict):
        errors.append("header extensions must be an object")
    return errors


def _formula_errors(formula: str, label: str) -> list[str]:
    """Return the errors of a formula source string against the pinned profile."""
    errors: list[str] = []
    if len(formula) > MAX_FORMULA_LENGTH:
        errors.append(f"{label} exceeds {MAX_FORMULA_LENGTH} characters")
    if not formula.startswith("="):
        errors.append(f"{label} must start with '='")
    if ";" in formula:
        errors.append(f"{label} must use ',' as the argument separator")
    if "[" in formula or "]" in formula:
        errors.append(f"{label} must not use structured references")
    if "@" in formula:
        errors.append(f"{label} must not use the '@' operator")
    for name in _FUNCTION_RE.findall(formula):
        if name.upper() not in PROFILE_FUNCTIONS:
            errors.append(f"{label} uses the unsupported function {name!r}")
    return errors


def _event_shape_errors(
    event: Any,
    label: str,
    expected_seq: int | None = None,
    seen_ids: set[str] | None = None,
) -> list[str]:
    """Return the errors of an event record's fixed fields."""
    if not isinstance(event, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    missing = set(_EVENT_FIELDS) - event.keys()
    extra = event.keys() - set(_EVENT_FIELDS)
    if missing:
        errors.append(f"{label} is missing: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(sorted(extra))}")
    seq = event.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        errors.append(f"{label} seq must be a positive integer")
    elif expected_seq is not None and seq != expected_seq:
        errors.append(f"{label} seq must be {expected_seq} to keep the sequence contiguous")
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id or len(event_id) > MAX_IDENTIFIER_LENGTH:
        errors.append(
            f"{label} event_id must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters"
        )
    elif seen_ids is not None and event_id in seen_ids:
        errors.append(f"{label} event_id {event_id!r} is already used")
    if not timestamp_is_valid(event.get("recorded_at")):
        errors.append(f"{label} recorded_at must be an RFC 3339 UTC timestamp ending in Z")
    actor_id = event.get("actor_id")
    if not isinstance(actor_id, str) or not actor_id or len(actor_id) > MAX_IDENTIFIER_LENGTH:
        errors.append(
            f"{label} actor_id must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters"
        )
    op = event.get("op")
    if not isinstance(op, str) or op not in REQUIRED_OPS:
        errors.append(f"{label} op must be one of: {', '.join(REQUIRED_OPS)}")
    if not isinstance(event.get("data"), dict):
        errors.append(f"{label} data must be an object")
    errors.extend(schema_errors("gridv", event))
    return errors


# --- replay -----------------------------------------------------------------

def _register_sheet(
    state: dict[str, Any],
    deleted: set[tuple[str, str]],
    sheet: Any,
    label: str,
    errors: list[str],
) -> None:
    """Add a validated sheet definition to the replay state."""
    sheet_errors = _sheet_errors(sheet, label)
    if sheet_errors:
        errors.extend(sheet_errors)
        return
    sheet_id = sheet["id"]
    if ("sheet", sheet_id) in deleted:
        errors.append(f"{label} reuses the deleted sheet id {sheet_id!r}")
        return
    if sheet_id in state["sheets_by_id"]:
        errors.append(f"{label} reuses the existing sheet id {sheet_id!r}")
        return
    rows = [_item_id(item) for item in sheet.get("rows", [])]
    columns = [_item_id(item) for item in sheet.get("columns", [])]
    for row_id in rows:
        if ("row", row_id) in deleted:
            errors.append(f"{label} reuses the deleted row id {row_id!r}")
            return
    for column_id in columns:
        if ("column", column_id) in deleted:
            errors.append(f"{label} reuses the deleted column id {column_id!r}")
            return
    cells: dict[str, dict[str, Any]] = {}
    for cell_id, cell in sheet.get("cells", {}).items():
        if ("cell", cell_id) in deleted:
            errors.append(f"{label} reuses the deleted cell id {cell_id!r}")
            return
        if cell["row_id"] not in rows:
            errors.append(f"{label} cell {cell_id!r} references the unknown row {cell['row_id']!r}")
            return
        if cell["column_id"] not in columns:
            errors.append(f"{label} cell {cell_id!r} references the unknown column {cell['column_id']!r}")
            return
        cells[cell_id] = {
            "column_id": cell["column_id"],
            "formula": cell.get("formula"),
            "row_id": cell["row_id"],
            "style": dict(cell.get("style") or {}),
            "value": cell.get("value"),
        }
    entry = {
        "cells": cells,
        "columns": columns,
        "id": sheet_id,
        "name": sheet["name"],
        "rows": rows,
    }
    state["sheets"].append(entry)
    state["sheets_by_id"][sheet_id] = entry


def _apply_formula_rewrites(sheet: dict[str, Any], data: dict[str, Any], label: str, errors: list[str]) -> None:
    """Apply the ordered formula-reference rewrites carried by a row/column event."""
    rewrites = data.get("formula_rewrites", [])
    if not isinstance(rewrites, list):
        errors.append(f"{label} data.formula_rewrites must be an array")
        return
    for index, item in enumerate(rewrites):
        item_label = f"{label} data.formula_rewrites[{index}]"
        if not isinstance(item, dict) or set(item) != {"cell_id", "old_formula", "new_formula"}:
            errors.append(f"{item_label} must contain exactly cell_id, old_formula and new_formula")
            continue
        if not all(isinstance(item[key], str) for key in ("cell_id", "old_formula", "new_formula")):
            errors.append(f"{item_label} must hold strings only")
            continue
        cell = sheet["cells"].get(item["cell_id"])
        if cell is None:
            errors.append(f"{item_label} references the unknown cell {item['cell_id']!r}")
            continue
        cell["formula"] = item["new_formula"]


def _op_workbook_create(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``workbook.create`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheets = data.get("sheets")
    settings = data.get("settings", {})
    if not isinstance(sheets, list):
        errors.append(f"{label} data.sheets must be an array")
        return
    if not isinstance(settings, dict):
        errors.append(f"{label} data.settings must be an object")
        return
    digest = data.get("initial_state_hash")
    if not isinstance(digest, str) or not _HEX_RE.fullmatch(digest):
        errors.append(f"{label} data.initial_state_hash must be a lowercase SHA-256 hex digest")
    elif digest != _state_digest(sheets, settings):
        errors.append(f"{label} data.initial_state_hash does not match the initial state")
    if state["sheets"]:
        errors.append(f"{label} must be the first event and cannot create a second workbook")
        return
    state["settings"] = dict(settings)
    for index, sheet in enumerate(sheets):
        _register_sheet(state, deleted, sheet, f"{label} data.sheets[{index}]", errors)


def _op_sheet_add(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``sheet.add`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet = data.get("sheet")
    if not isinstance(sheet, dict):
        errors.append(f"{label} data.sheet must be an object")
        return
    _register_sheet(state, deleted, sheet, f"{label} data.sheet", errors)


def _op_sheet_remove(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``sheet.remove`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    state["sheets"].remove(entry)
    del state["sheets_by_id"][sheet_id]
    deleted.add(("sheet", sheet_id))
    for row_id in entry["rows"]:
        deleted.add(("row", row_id))
    for column_id in entry["columns"]:
        deleted.add(("column", column_id))
    for cell_id in entry["cells"]:
        deleted.add(("cell", cell_id))


def _op_sheet_rename(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``sheet.rename`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    name = data.get("name")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if not isinstance(name, str) or not name or len(name) > MAX_IDENTIFIER_LENGTH:
        errors.append(f"{label} data.name must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    entry["name"] = name


def _op_row_insert(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``row.insert`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    index = data.get("index")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        errors.append(f"{label} data.index must be an integer of at least 0")
        return
    row_id = _item_id(data.get("row"))
    if row_id is None:
        errors.append(f"{label} data.row must be an id or an object with an 'id'")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    if ("row", row_id) in deleted:
        errors.append(f"{label} reuses the deleted row id {row_id!r}")
        return
    if row_id in entry["rows"]:
        errors.append(f"{label} reuses the existing row id {row_id!r}")
        return
    entry["rows"].insert(min(index, len(entry["rows"])), row_id)
    _apply_formula_rewrites(entry, data, label, errors)


def _op_row_delete(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``row.delete`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    row_id = data.get("row_id")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if not isinstance(row_id, str) or not row_id:
        errors.append(f"{label} data.row_id must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    if row_id not in entry["rows"]:
        errors.append(f"{label} references the unknown row {row_id!r}")
        return
    entry["rows"].remove(row_id)
    deleted.add(("row", row_id))
    for cell_id, cell in list(entry["cells"].items()):
        if cell["row_id"] == row_id:
            del entry["cells"][cell_id]
            deleted.add(("cell", cell_id))
    _apply_formula_rewrites(entry, data, label, errors)


def _op_column_insert(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``column.insert`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    index = data.get("index")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        errors.append(f"{label} data.index must be an integer of at least 0")
        return
    column_id = _item_id(data.get("column"))
    if column_id is None:
        errors.append(f"{label} data.column must be an id or an object with an 'id'")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    if ("column", column_id) in deleted:
        errors.append(f"{label} reuses the deleted column id {column_id!r}")
        return
    if column_id in entry["columns"]:
        errors.append(f"{label} reuses the existing column id {column_id!r}")
        return
    entry["columns"].insert(min(index, len(entry["columns"])), column_id)
    _apply_formula_rewrites(entry, data, label, errors)


def _op_column_delete(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``column.delete`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    column_id = data.get("column_id")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if not isinstance(column_id, str) or not column_id:
        errors.append(f"{label} data.column_id must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    if column_id not in entry["columns"]:
        errors.append(f"{label} references the unknown column {column_id!r}")
        return
    entry["columns"].remove(column_id)
    deleted.add(("column", column_id))
    for cell_id, cell in list(entry["cells"].items()):
        if cell["column_id"] == column_id:
            del entry["cells"][cell_id]
            deleted.add(("cell", cell_id))
    _apply_formula_rewrites(entry, data, label, errors)


def _op_cell_set(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``cell.set`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    cell_id = data.get("cell_id")
    row_id = data.get("row_id")
    column_id = data.get("column_id")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if not isinstance(cell_id, str) or not cell_id:
        errors.append(f"{label} data.cell_id must be a non-empty string")
        return
    if not isinstance(row_id, str) or not row_id:
        errors.append(f"{label} data.row_id must be a non-empty string")
        return
    if not isinstance(column_id, str) or not column_id:
        errors.append(f"{label} data.column_id must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    if row_id not in entry["rows"]:
        errors.append(f"{label} references the unknown row {row_id!r}")
        return
    if column_id not in entry["columns"]:
        errors.append(f"{label} references the unknown column {column_id!r}")
        return
    if ("cell", cell_id) in deleted:
        errors.append(f"{label} reuses the deleted cell id {cell_id!r}")
        return
    value_errors = _cell_value_errors(data.get("value"), f"{label} data.value")
    if value_errors:
        errors.extend(value_errors)
        return
    existing = entry["cells"].get(cell_id)
    entry["cells"][cell_id] = {
        "column_id": column_id,
        "formula": None,
        "row_id": row_id,
        "style": dict(existing["style"]) if existing else {},
        "value": data["value"],
    }


def _op_formula_set(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``formula.set`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    cell_id = data.get("cell_id")
    row_id = data.get("row_id")
    column_id = data.get("column_id")
    formula = data.get("formula")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    if not isinstance(cell_id, str) or not cell_id:
        errors.append(f"{label} data.cell_id must be a non-empty string")
        return
    if not isinstance(row_id, str) or not row_id:
        errors.append(f"{label} data.row_id must be a non-empty string")
        return
    if not isinstance(column_id, str) or not column_id:
        errors.append(f"{label} data.column_id must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    if row_id not in entry["rows"]:
        errors.append(f"{label} references the unknown row {row_id!r}")
        return
    if column_id not in entry["columns"]:
        errors.append(f"{label} references the unknown column {column_id!r}")
        return
    if ("cell", cell_id) in deleted:
        errors.append(f"{label} reuses the deleted cell id {cell_id!r}")
        return
    if data.get("formula_profile") != FORMULA_PROFILE:
        errors.append(f"{label} data.formula_profile must equal {FORMULA_PROFILE}")
    if not isinstance(formula, str) or not formula:
        errors.append(f"{label} data.formula must be a non-empty formula source string")
        return
    errors.extend(_formula_errors(formula, f"{label} data.formula"))
    existing = entry["cells"].get(cell_id)
    entry["cells"][cell_id] = {
        "column_id": column_id,
        "formula": formula,
        "row_id": row_id,
        "style": dict(existing["style"]) if existing else {},
        "value": None,
    }


def _op_style_set(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``style.set`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    sheet_id = data.get("sheet_id")
    cell_id = data.get("cell_id")
    cell_range = data.get("range")
    style = data.get("style")
    if not isinstance(sheet_id, str) or not sheet_id:
        errors.append(f"{label} data.sheet_id must be a non-empty string")
        return
    entry = state["sheets_by_id"].get(sheet_id)
    if entry is None:
        errors.append(f"{label} references the unknown sheet {sheet_id!r}")
        return
    errors.extend(_style_errors(style, f"{label} data.style"))
    if cell_id is None and cell_range is None:
        errors.append(f"{label} data must target a cell_id or a range")
        return
    if cell_id is not None:
        if not isinstance(cell_id, str) or not cell_id:
            errors.append(f"{label} data.cell_id must be a non-empty string")
            return
        cell = entry["cells"].get(cell_id)
        if cell is None:
            errors.append(f"{label} references the unknown cell {cell_id!r}")
        else:
            cell["style"] = dict(style)
    if cell_range is not None:
        if not isinstance(cell_range, dict):
            errors.append(f"{label} data.range must be an object")
            return
        keys = {"start_row_id", "start_column_id", "end_row_id", "end_column_id"}
        if set(cell_range) != keys:
            errors.append(f"{label} data.range must contain exactly {', '.join(sorted(keys))}")
            return
        if not all(isinstance(cell_range[key], str) and cell_range[key] for key in keys):
            errors.append(f"{label} data.range must hold non-empty strings")
            return
        rows = entry["rows"]
        columns = entry["columns"]
        if cell_range["start_row_id"] not in rows or cell_range["end_row_id"] not in rows:
            errors.append(f"{label} data.range references an unknown row")
            return
        if cell_range["start_column_id"] not in columns or cell_range["end_column_id"] not in columns:
            errors.append(f"{label} data.range references an unknown column")
            return
        row_span = rows[rows.index(cell_range["start_row_id"]): rows.index(cell_range["end_row_id"]) + 1]
        column_span = columns[
            columns.index(cell_range["start_column_id"]): columns.index(cell_range["end_column_id"]) + 1
        ]
        for row_id in row_span:
            for column_id in column_span:
                for cell in entry["cells"].values():
                    if cell["row_id"] == row_id and cell["column_id"] == column_id:
                        cell["style"] = dict(style)


def _op_checkpoint(state: dict[str, Any], deleted: set[tuple[str, str]], event: dict[str, Any], errors: list[str]) -> None:
    """Apply a ``checkpoint`` event."""
    data = event["data"]
    label = f"event {event['seq']}"
    seq = data.get("seq")
    snapshot = data.get("snapshot")
    digest = data.get("digest")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        errors.append(f"{label} data.seq must be a positive integer")
    elif seq > event["seq"]:
        errors.append(f"{label} data.seq must not be greater than the event sequence")
    if not isinstance(snapshot, dict):
        errors.append(f"{label} data.snapshot must be an object")
        return
    if not isinstance(digest, str) or not _HEX_RE.fullmatch(digest):
        errors.append(f"{label} data.digest must be a lowercase SHA-256 hex digest")
        return
    if digest != _digest(canonical_json(snapshot)):
        errors.append(f"{label} data.digest does not match the canonical snapshot digest")


_OP_HANDLERS = {
    "workbook.create": _op_workbook_create,
    "sheet.add": _op_sheet_add,
    "sheet.remove": _op_sheet_remove,
    "sheet.rename": _op_sheet_rename,
    "row.insert": _op_row_insert,
    "row.delete": _op_row_delete,
    "column.insert": _op_column_insert,
    "column.delete": _op_column_delete,
    "cell.set": _op_cell_set,
    "formula.set": _op_formula_set,
    "style.set": _op_style_set,
    "checkpoint": _op_checkpoint,
}


def _replay(events: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Replay events into a workbook state and collect reference errors."""
    state: dict[str, Any] = {"settings": {}, "sheets": [], "sheets_by_id": {}}
    deleted: set[tuple[str, str]] = set()
    errors: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        op = event.get("op")
        data = event.get("data")
        seq = event.get("seq")
        if not isinstance(op, str) or not isinstance(data, dict) or not isinstance(seq, int):
            continue
        handler = _OP_HANDLERS.get(op)
        if handler is None:
            continue
        handler(state, deleted, event, errors)
    state["deleted"] = deleted
    return state, errors


def _public_state(header: dict[str, Any], state: dict[str, Any], seq: int) -> dict[str, Any]:
    """Return the public reconstructed workbook state."""
    sheets: list[dict[str, Any]] = []
    for entry in state["sheets"]:
        cells: dict[str, Any] = {}
        for cell_id, cell in entry["cells"].items():
            cells[cell_id] = {
                "column_id": cell["column_id"],
                "formula": cell["formula"],
                "row_id": cell["row_id"],
                "style": dict(cell["style"]),
                "value": cell["value"],
            }
        sheets.append(
            {
                "cells": cells,
                "columns": [{"id": column_id, "index": index} for index, column_id in enumerate(entry["columns"])],
                "id": entry["id"],
                "name": entry["name"],
                "rows": [{"id": row_id, "index": index} for index, row_id in enumerate(entry["rows"])],
            }
        )
    return {
        "formula_profile": header["formula_profile"],
        "seq": seq,
        "settings": dict(state["settings"]),
        "sheets": sheets,
        "workbook_id": header["workbook_id"],
    }


# --- framing ----------------------------------------------------------------

def _scan_frames(raw: bytes, start: int) -> tuple[list[tuple[bytes, bytes]], list[str]]:
    """Scan event frames, returning the raw frames and the framing errors."""
    frames: list[tuple[bytes, bytes]] = []
    errors: list[str] = []
    offset = start
    while offset < len(raw):
        remaining = len(raw) - offset
        if remaining < 4:
            errors.append(f"trailing bytes after the last event frame: {remaining}")
            break
        length = struct.unpack(">I", raw[offset:offset + 4])[0]
        if not (MIN_EVENT_LENGTH <= length <= MAX_EVENT_LENGTH):
            errors.append(f"event frame length {length} is outside the v0.1 bounds")
            break
        body_start = offset + 4
        body_end = body_start + length
        frame_end = body_end + HASH_LENGTH
        if frame_end > len(raw):
            errors.append("truncated final event frame")
            break
        frames.append((raw[body_start:body_end], raw[body_end:frame_end]))
        offset = frame_end
    return frames, errors


def _parse_header(raw: bytes) -> tuple[dict[str, Any], int]:
    """Parse the container header and return it with the frame offset."""
    try:
        body, offset = read_length_prefixed(
            raw,
            MAGIC,
            prefix_size=4,
            min_length=MIN_HEADER_LENGTH,
            max_length=MAX_HEADER_LENGTH,
            label="GRIDV header",
        )
        header = parse_canonical_body(body, "GRIDV header")
    except FormatError as exc:
        raise GridvFormatError(str(exc)) from exc
    return header, offset


def _parse_container(raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], list[tuple[bytes, bytes]]]:
    """Parse a container into its header, its events and its raw frames."""
    header, offset = _parse_header(raw)
    frames, framing_errors = _scan_frames(raw, offset)
    if framing_errors:
        raise GridvFormatError(framing_errors[0])
    events: list[dict[str, Any]] = []
    for index, (event_raw, _stored_hash) in enumerate(frames):
        try:
            events.append(parse_canonical_body(event_raw, f"GRIDV event {index + 1}"))
        except FormatError as exc:
            raise GridvFormatError(str(exc)) from exc
    return header, events, frames


def _serialize_bytes(header: Mapping[str, Any], event_payloads: list[bytes]) -> bytes:
    """Serialize a header and pre-encoded event payloads into a container."""
    header_raw = _canonical(dict(header), "GRIDV header")
    if not (MIN_HEADER_LENGTH <= len(header_raw) <= MAX_HEADER_LENGTH):
        raise GridvFormatError("Header length is outside the v0.1 bounds")
    body = bytearray(MAGIC + struct.pack(">I", len(header_raw)) + header_raw)
    chain = b"\x00" * HASH_LENGTH
    for event_raw in event_payloads:
        if not (MIN_EVENT_LENGTH <= len(event_raw) <= MAX_EVENT_LENGTH):
            raise GridvFormatError("Event length is outside the v0.1 bounds")
        chain = hashlib.sha256(chain + event_raw).digest()
        body += struct.pack(">I", len(event_raw)) + event_raw + chain
    return bytes(body)


def _serialize_container(header: Mapping[str, Any], events: list[Mapping[str, Any]]) -> bytes:
    """Serialize a header and its events into a container."""
    payloads = [_canonical(dict(event), "GRIDV event") for event in events]
    return _serialize_bytes(header, payloads)


# --- public API -------------------------------------------------------------

def create_gridv(
    workbook_id: str,
    initial_state: Mapping[str, Any],
    *,
    actor_id: str = "local",
) -> bytes:
    """Create a GRIDV container holding a single ``workbook.create`` event.

    ``initial_state`` is a mapping with a ``sheets`` array and an optional
    ``settings`` object. Every sheet holds a stable ``id``, a ``name`` and
    optionally ``rows``, ``columns`` and ``cells`` arrays of stable
    identifiers; a cell holds a ``row_id``, a ``column_id`` and an optional
    typed ``value``, ``formula`` and ``style``.
    """
    if not isinstance(workbook_id, str) or not workbook_id or len(workbook_id) > MAX_IDENTIFIER_LENGTH:
        raise GridvValidationError(
            [f"workbook_id must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters"]
        )
    if not isinstance(actor_id, str) or not actor_id or len(actor_id) > MAX_IDENTIFIER_LENGTH:
        raise GridvValidationError(
            [f"actor_id must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters"]
        )
    if not isinstance(initial_state, Mapping):
        raise TypeError("initial_state must be a mapping")
    state = dict(initial_state)
    errors = _initial_state_errors(state)
    if errors:
        raise GridvValidationError(errors)
    sheets = state.get("sheets", [])
    settings = state.get("settings", {})
    initial_state_hash = _state_digest(sheets, settings)
    header = {
        "created_at": utc_now(),
        "format": "gridv",
        "format_version": FORMAT_VERSION,
        "formula_profile": FORMULA_PROFILE,
        "initial_state_hash": initial_state_hash,
        "time_zone": "UTC",
        "workbook_id": workbook_id,
    }
    event = {
        "actor_id": actor_id,
        "data": {
            "initial_state_hash": initial_state_hash,
            "settings": settings,
            "sheets": sheets,
        },
        "event_id": _new_event_id(),
        "op": "workbook.create",
        "recorded_at": utc_now(),
        "seq": 1,
    }
    return _serialize_container(header, [event])


def append_gridv_event(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    event: Mapping[str, Any],
) -> bytes:
    """Append one event to an existing container and return the new bytes.

    The source container is never modified. The new event must carry the next
    contiguous sequence number and an unused event id.
    """
    raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    errors = validate_gridv(raw)
    if errors:
        raise GridvValidationError(errors)
    header, events, _frames = _parse_container(raw)
    if not isinstance(event, Mapping):
        raise TypeError("event must be a mapping")
    candidate = dict(event)
    seen_ids = {existing["event_id"] for existing in events if isinstance(existing.get("event_id"), str)}
    shape_errors = _event_shape_errors(candidate, "event", len(events) + 1, seen_ids)
    if shape_errors:
        raise GridvValidationError(shape_errors)
    state, replay_errors = _replay(events)
    if replay_errors:
        raise GridvValidationError(replay_errors)
    apply_errors: list[str] = []
    _OP_HANDLERS[candidate["op"]](state, state["deleted"], candidate, apply_errors)
    if apply_errors:
        raise GridvValidationError(apply_errors)
    return _serialize_container(header, events + [candidate])


def read_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read a container and return its header and its verified events.

    The hash chain is verified while reading; a broken chain raises
    :class:`GridvFormatError`.
    """
    raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    header, events, frames = _parse_container(raw)
    chain = b"\x00" * HASH_LENGTH
    for index, (event_raw, stored_hash) in enumerate(frames):
        expected = hashlib.sha256(chain + event_raw).digest()
        if expected != stored_hash:
            raise GridvFormatError(f"Hash chain mismatch at event {index + 1}")
        chain = expected
    return header, events


def write_gridv(
    output: str | os.PathLike[str],
    header: Mapping[str, Any],
    events: list[Mapping[str, Any]],
) -> None:
    """Write a container with an atomic replacement and a private temp file."""
    if not isinstance(header, Mapping):
        raise TypeError("header must be a mapping")
    header_object = dict(header)
    errors = _header_errors(header_object)
    if errors:
        raise GridvValidationError(errors)
    event_objects = [dict(event) for event in events]
    seen_ids: set[str] = set()
    for index, event in enumerate(event_objects):
        errors.extend(_event_shape_errors(event, f"event {index + 1}", index + 1, seen_ids))
        if isinstance(event.get("event_id"), str):
            seen_ids.add(event["event_id"])
    if errors:
        raise GridvValidationError(errors)
    container = _serialize_container(header_object, event_objects)
    errors = validate_gridv(container)
    if errors:
        raise GridvValidationError(errors)
    atomic_write_bytes(output, container)


def validate_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> list[str]:
    """Return the validation errors of a container; an empty list means valid.

    The validator checks framing, canonical JSON, contiguous sequence numbers,
    unique event ids, the event schema, stable-reference integrity, the hash
    chain, checkpoint digests, the formula profile and the header fields.
    """
    try:
        raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    except ContainerError as exc:
        return [str(exc)]
    try:
        header, offset = _parse_header(raw)
    except GridvFormatError as exc:
        return [str(exc)]
    errors = _header_errors(header)
    frames, framing_errors = _scan_frames(raw, offset)
    errors.extend(framing_errors)
    if framing_errors:
        return errors
    if not frames:
        errors.append("container must hold the workbook.create event")
        return errors
    events: list[dict[str, Any]] = []
    chain = b"\x00" * HASH_LENGTH
    for index, (event_raw, stored_hash) in enumerate(frames):
        try:
            event = parse_canonical_body(event_raw, f"GRIDV event {index + 1}")
        except FormatError as exc:
            errors.append(str(exc))
            event = None
        expected = hashlib.sha256(chain + event_raw).digest()
        if expected != stored_hash:
            errors.append(f"Hash chain mismatch at event {index + 1}")
        chain = expected
        if event is not None:
            events.append(event)
    if len(events) != len(frames):
        return errors
    errors.extend(_validate_events(header, events))
    return errors


def _validate_events(header: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    """Return the semantic validation errors of a parsed event log."""
    errors: list[str] = []
    seen_ids: set[str] = set()
    for index, event in enumerate(events):
        errors.extend(_event_shape_errors(event, f"event {index + 1}", index + 1, seen_ids))
        if isinstance(event.get("event_id"), str):
            seen_ids.add(event["event_id"])
    first = events[0]
    if first.get("op") != "workbook.create":
        errors.append("the first event must be workbook.create")
    elif isinstance(first.get("data"), dict):
        data = first["data"]
        sheets = data.get("sheets")
        settings = data.get("settings", {})
        if isinstance(sheets, list) and isinstance(settings, dict):
            computed = _state_digest(sheets, settings)
            if data.get("initial_state_hash") != computed:
                errors.append("event 1 data.initial_state_hash does not match the initial state")
            if header.get("initial_state_hash") != computed:
                errors.append("header initial_state_hash does not match the workbook.create initial state")
    _state, replay_errors = _replay(events)
    errors.extend(replay_errors)
    return errors


def inspect_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> dict[str, Any]:
    """Return the container header plus a short summary of the log."""
    raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    header, events, frames = _parse_container(raw)
    chain = b"\x00" * HASH_LENGTH
    for event_raw, _stored_hash in frames:
        chain = hashlib.sha256(chain + event_raw).digest()
    extensions = header.get("extensions") or {}
    summary: dict[str, Any] = dict(header)
    summary.update(
        {
            "chain_tip": chain.hex(),
            "event_count": len(events),
            "last_seq": events[-1]["seq"] if events else None,
            "recovered": _RECOVERED_EXTENSION in extensions,
        }
    )
    return summary


def log_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> list[dict[str, Any]]:
    """Return the event log in sequence order."""
    _header, events = read_gridv(source)
    return [dict(event) for event in events]


def diff_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    from_seq: int,
    to_seq: int,
) -> list[dict[str, Any]]:
    """Return the events with ``from_seq < seq <= to_seq``."""
    if isinstance(from_seq, bool) or not isinstance(from_seq, int) or from_seq < 0:
        raise GridvValidationError(["from_seq must be an integer of at least 0"])
    if isinstance(to_seq, bool) or not isinstance(to_seq, int) or to_seq < from_seq:
        raise GridvValidationError(["to_seq must be an integer of at least from_seq"])
    _header, events = read_gridv(source)
    return [dict(event) for event in events if from_seq < event["seq"] <= to_seq]


def checkout_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    seq: int,
) -> dict[str, Any]:
    """Reconstruct the workbook state as of ``seq``.

    The returned mapping is ``{"workbook_id", "formula_profile", "seq",
    "settings", "sheets"}``. Every sheet is ``{"id", "name", "rows",
    "columns", "cells"}``; ``rows`` and ``columns`` are ordered lists of
    ``{"id", "index"}`` and ``cells`` is keyed by the stable cell id with
    ``{"row_id", "column_id", "value", "formula", "style"}`` entries. A
    ``cell.set`` value is the typed object as recorded, a ``formula.set`` cell
    holds the formula source string and no value, and no formula is ever
    recalculated.
    """
    raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    errors = validate_gridv(raw)
    if errors:
        raise GridvValidationError(errors)
    header, events, _frames = _parse_container(raw)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise GridvValidationError(["seq must be a positive integer"])
    if seq > len(events):
        raise GridvValidationError([f"seq {seq} is beyond the end of the log ({len(events)} events)"])
    state, _errors = _replay(events[:seq])
    return _public_state(header, state, seq)


def _render_cell(cell: dict[str, Any] | None) -> str:
    """Render one reconstructed cell as a CSV field."""
    if cell is None:
        return ""
    formula = cell.get("formula")
    if formula:
        return formula
    value = cell.get("value")
    if not isinstance(value, dict):
        return ""
    kind = value.get("type")
    if kind in ("string", "decimal", "date"):
        payload = value.get("value")
        return payload if isinstance(payload, str) else ""
    if kind == "boolean":
        return "TRUE" if value.get("value") else "FALSE"
    return ""


def _state_to_csv(state: dict[str, Any]) -> str:
    """Render a reconstructed workbook state as CSV text."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for index, sheet in enumerate(state["sheets"]):
        if index:
            writer.writerow([])
        column_ids = [column["id"] for column in sheet["columns"]]
        writer.writerow(column_ids)
        cells = {(cell["row_id"], cell["column_id"]): cell for cell in sheet["cells"].values()}
        for row in sheet["rows"]:
            writer.writerow([_render_cell(cells.get((row["id"], column_id))) for column_id in column_ids])
    return buffer.getvalue()


def export_gridv_csv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    seq: int | None = None,
) -> str:
    """Export the reconstructed workbook state at ``seq`` as CSV text.

    Every sheet becomes one section: a header row of the stable column ids,
    then one row per stable row id in order, then a blank line before the
    next sheet. Cell values are rendered by type, an empty cell becomes an
    empty field, and a formula cell shows its source string. The sheet names
    are not part of the CSV body.
    """
    raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    _header, events, _frames = _parse_container(raw)
    target = len(events) if seq is None else seq
    state = checkout_gridv(raw, target)
    return _state_to_csv(state)


def recover_gridv(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> bytes:
    """Return a new container holding the longest verified prefix of a log.

    The source is never modified. The recovered container carries the
    ``open-extensions.gridv.recovered`` extension entry with the recovery
    time and the original length.
    """
    raw = read_source(source, MAX_CONTAINER_LENGTH, "GRIDV file")
    header, offset = _parse_header(raw)
    frames, _framing_errors = _scan_frames(raw, offset)
    verified: list[bytes] = []
    chain = b"\x00" * HASH_LENGTH
    for event_raw, stored_hash in frames:
        expected = hashlib.sha256(chain + event_raw).digest()
        if expected != stored_hash:
            break
        try:
            parse_canonical_body(event_raw, "GRIDV event")
        except FormatError:
            break
        chain = expected
        verified.append(event_raw)
    recovered_header = dict(header)
    extensions = dict(recovered_header.get("extensions") or {})
    extensions[_RECOVERED_EXTENSION] = {
        "original_length": len(raw),
        "recovered_at": utc_now(),
    }
    recovered_header["extensions"] = extensions
    return _serialize_bytes(recovered_header, verified)
