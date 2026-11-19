"""Tests for the GRIDV v0.1 reference implementation."""
from __future__ import annotations

import hashlib
import json
import struct

import pytest

from open_extensions.gridv import (
    FORMAT_VERSION,
    FORMULA_PROFILE,
    MAGIC,
    GridvFormatError,
    GridvValidationError,
    append_gridv_event,
    checkout_gridv,
    create_gridv,
    diff_gridv,
    export_gridv_csv,
    inspect_gridv,
    log_gridv,
    read_gridv,
    recover_gridv,
    validate_gridv,
    write_gridv,
)

HASH_LENGTH = 32

INITIAL_STATE = {
    "sheets": [
        {
            "id": "sheet-1",
            "name": "Sheet1",
            "rows": [{"id": "row-1"}, {"id": "row-2"}],
            "columns": [{"id": "col-1"}, {"id": "col-2"}],
            "cells": {
                "cell-11": {
                    "row_id": "row-1",
                    "column_id": "col-1",
                    "value": {"type": "string", "value": "hello"},
                }
            },
        }
    ],
    "settings": {"locale": "en-US"},
}


def _canonical(value: object) -> bytes:
    """Serialize a value the way the format requires, independently of the SDK."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _event(seq: int, op: str, data: dict, **overrides: object) -> dict:
    """Build one event record."""
    event = {
        "seq": seq,
        "event_id": f"evt-{seq:012d}",
        "recorded_at": "2026-01-01T00:00:00Z",
        "actor_id": "tester",
        "op": op,
        "data": data,
    }
    event.update(overrides)
    return event


def _rebuild(header: dict, events: list[dict]) -> bytes:
    """Rebuild a container from a header and events, recomputing the chain."""
    header_raw = _canonical(header)
    out = bytearray(MAGIC + struct.pack(">I", len(header_raw)) + header_raw)
    chain = b"\x00" * HASH_LENGTH
    for event in events:
        raw = _canonical(event)
        chain = hashlib.sha256(chain + raw).digest()
        out += struct.pack(">I", len(raw)) + raw + chain
    return bytes(out)


def _frames(container: bytes) -> list[tuple[int, int]]:
    """Return the (offset, total length) of every event frame."""
    header_length = struct.unpack(">I", container[len(MAGIC): len(MAGIC) + 4])[0]
    offset = len(MAGIC) + 4 + header_length
    frames: list[tuple[int, int]] = []
    while offset < len(container):
        event_length = struct.unpack(">I", container[offset: offset + 4])[0]
        total = 4 + event_length + HASH_LENGTH
        frames.append((offset, total))
        offset += total
    return frames


def _workbook() -> bytes:
    """Return a workbook with a create, two edits and a checkpoint."""
    container = create_gridv("workbook-1", INITIAL_STATE)
    container = append_gridv_event(
        container,
        _event(
            2,
            "cell.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-12",
                "row_id": "row-1",
                "column_id": "col-2",
                "value": {"type": "decimal", "value": "12.50"},
            },
        ),
    )
    container = append_gridv_event(
        container,
        _event(
            3,
            "formula.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-13",
                "row_id": "row-2",
                "column_id": "col-1",
                "formula": "=SUM(A1:A2)",
                "formula_profile": FORMULA_PROFILE,
            },
        ),
    )
    snapshot = {"sheets": [{"id": "sheet-1"}]}
    container = append_gridv_event(
        container,
        _event(
            4,
            "checkpoint",
            {
                "seq": 3,
                "snapshot": snapshot,
                "digest": hashlib.sha256(_canonical(snapshot)).hexdigest(),
            },
        ),
    )
    return container


# --- creation and reading ---------------------------------------------------

def test_create_and_read_round_trip():
    container = create_gridv("workbook-1", INITIAL_STATE)
    header, events = read_gridv(container)
    assert header["format"] == "gridv"
    assert header["format_version"] == FORMAT_VERSION
    assert header["workbook_id"] == "workbook-1"
    assert header["formula_profile"] == FORMULA_PROFILE
    assert header["time_zone"] == "UTC"
    assert len(events) == 1
    assert events[0]["op"] == "workbook.create"
    assert events[0]["seq"] == 1
    assert events[0]["data"]["sheets"] == INITIAL_STATE["sheets"]
    assert events[0]["data"]["settings"] == INITIAL_STATE["settings"]


def test_header_initial_state_hash_matches_the_canonical_initial_state():
    container = create_gridv("workbook-1", INITIAL_STATE)
    header, events = read_gridv(container)
    expected = hashlib.sha256(
        _canonical({"settings": INITIAL_STATE["settings"], "sheets": INITIAL_STATE["sheets"]})
    ).hexdigest()
    assert header["initial_state_hash"] == expected
    assert events[0]["data"]["initial_state_hash"] == expected


def test_create_rejects_an_invalid_initial_state():
    with pytest.raises(GridvValidationError):
        create_gridv("workbook-1", {"sheets": [{"name": "no id"}]})


def test_hash_chain_matches_the_specified_rule():
    container = _workbook()
    chain = b"\x00" * HASH_LENGTH
    for start, total in _frames(container):
        body = container[start + 4: start + total - HASH_LENGTH]
        chain = hashlib.sha256(chain + body).digest()
        assert container[start + total - HASH_LENGTH: start + total] == chain


def test_a_good_workbook_has_no_validation_errors():
    assert validate_gridv(_workbook()) == []


def test_read_reports_the_log_in_order():
    _header, events = read_gridv(_workbook())
    assert [event["seq"] for event in events] == [1, 2, 3, 4]
    assert [event["op"] for event in events] == [
        "workbook.create",
        "cell.set",
        "formula.set",
        "checkpoint",
    ]


def test_write_gridv_round_trips_through_a_file(tmp_path):
    header, events = read_gridv(_workbook())
    target = tmp_path / "book.gridv"
    write_gridv(target, header, events)
    assert validate_gridv(target) == []
    written_header, written_events = read_gridv(target)
    assert written_header == header
    assert written_events == events


def test_append_keeps_the_source_container_unchanged():
    container = _workbook()
    before = bytes(container)
    append_gridv_event(
        container,
        _event(
            5,
            "cell.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-14",
                "row_id": "row-2",
                "column_id": "col-2",
                "value": {"type": "empty"},
            },
        ),
    )
    assert container == before


def test_append_rejects_a_non_contiguous_sequence_number():
    with pytest.raises(GridvValidationError):
        append_gridv_event(_workbook(), _event(9, "cell.set", {}))


# --- framing and canonical JSON ---------------------------------------------

def test_tampering_with_an_event_byte_is_detected():
    container = _workbook()
    tampered = container.replace(b'"tester"', b'"Tester"', 1)
    assert tampered != container
    errors = validate_gridv(tampered)
    assert errors
    assert any("chain" in error.lower() for error in errors)
    with pytest.raises(GridvFormatError):
        read_gridv(tampered)


def test_deleting_an_event_frame_is_detected():
    container = _workbook()
    start, total = _frames(container)[1]
    spliced = container[:start] + container[start + total:]
    errors = validate_gridv(spliced)
    assert errors
    assert any("chain" in error.lower() or "contiguous" in error.lower() for error in errors)


def test_a_truncated_final_frame_is_detected():
    errors = validate_gridv(_workbook()[:-10])
    assert errors
    assert any("truncated" in error.lower() for error in errors)


def test_a_wrong_magic_is_rejected():
    container = bytearray(_workbook())
    container[0:1] = b"X"
    errors = validate_gridv(bytes(container))
    assert errors
    assert any("magic" in error.lower() for error in errors)


def test_an_oversized_header_length_is_rejected():
    container = MAGIC + struct.pack(">I", 999 * 1024) + b"{}"
    errors = validate_gridv(container)
    assert errors
    assert any("header" in error.lower() for error in errors)


def test_an_undersized_header_length_is_rejected():
    container = MAGIC + struct.pack(">I", 1) + b"{}"
    assert validate_gridv(container)


def test_an_oversized_event_length_is_rejected():
    container = bytearray(_workbook())
    start, _total = _frames(bytes(container))[0]
    container[start: start + 4] = struct.pack(">I", 100 * 1024 * 1024)
    errors = validate_gridv(bytes(container))
    assert errors
    assert any("event frame length" in error.lower() for error in errors)


def test_trailing_bytes_are_rejected():
    errors = validate_gridv(_workbook() + b"\x00")
    assert errors
    assert any("trailing" in error.lower() for error in errors)


def test_arbitrary_trailing_garbage_is_rejected():
    errors = validate_gridv(_workbook() + b"trailing")
    assert errors


def test_duplicate_json_keys_are_rejected():
    raw = b'{"format":"gridv","format":"gridv"}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    errors = validate_gridv(container)
    assert errors
    assert any("duplicate" in error.lower() for error in errors)


def test_non_canonical_json_is_rejected():
    raw = b'{"format": "gridv"}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    assert validate_gridv(container)


# --- log semantics ----------------------------------------------------------

def test_a_non_contiguous_sequence_is_rejected():
    header, events = read_gridv(_workbook())
    events[1]["seq"] = 5
    errors = validate_gridv(_rebuild(header, events))
    assert any("contiguous" in error for error in errors)


def test_a_duplicate_event_id_is_rejected():
    header, events = read_gridv(_workbook())
    events[2]["event_id"] = events[1]["event_id"]
    errors = validate_gridv(_rebuild(header, events))
    assert any("already used" in error for error in errors)


def test_an_unknown_op_is_rejected():
    header, events = read_gridv(_workbook())
    events[1]["op"] = "cell.teleport"
    errors = validate_gridv(_rebuild(header, events))
    assert any("op must be one of" in error for error in errors)


def test_the_first_event_must_be_workbook_create():
    header, events = read_gridv(_workbook())
    events[0]["op"] = "cell.set"
    errors = validate_gridv(_rebuild(header, events))
    assert any("first event must be workbook.create" in error for error in errors)


def test_a_checkpoint_digest_mismatch_is_detected():
    header, events = read_gridv(_workbook())
    events[3]["data"]["digest"] = "0" * 64
    errors = validate_gridv(_rebuild(header, events))
    assert any("digest does not match" in error for error in errors)


def test_a_valid_checkpoint_is_accepted():
    assert validate_gridv(_workbook()) == []


# --- header rules -----------------------------------------------------------

def test_an_unsupported_formula_profile_is_rejected():
    header, events = read_gridv(_workbook())
    header["formula_profile"] = "other-profile-9.9"
    errors = validate_gridv(_rebuild(header, events))
    assert any("formula_profile" in error for error in errors)


def test_a_non_utc_time_zone_is_rejected():
    header, events = read_gridv(_workbook())
    header["time_zone"] = "Europe/Berlin"
    errors = validate_gridv(_rebuild(header, events))
    assert any("time_zone" in error for error in errors)


def test_a_header_initial_state_hash_mismatch_is_rejected():
    header, events = read_gridv(_workbook())
    header["initial_state_hash"] = "0" * 64
    errors = validate_gridv(_rebuild(header, events))
    assert any("initial_state_hash" in error for error in errors)


def test_a_workbook_create_initial_state_hash_mismatch_is_rejected():
    header, events = read_gridv(_workbook())
    events[0]["data"]["initial_state_hash"] = "0" * 64
    errors = validate_gridv(_rebuild(header, events))
    assert any("initial_state_hash" in error for error in errors)


def test_an_unknown_header_field_is_rejected():
    header, events = read_gridv(_workbook())
    header["surprise"] = 1
    errors = validate_gridv(_rebuild(header, events))
    assert any("unsupported fields" in error for error in errors)


# --- stable references ------------------------------------------------------

def test_a_style_set_on_an_unknown_cell_is_rejected():
    header, events = read_gridv(_workbook())
    events.append(
        _event(
            5,
            "style.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-does-not-exist",
                "style": {"bold": True},
            },
        )
    )
    errors = validate_gridv(_rebuild(header, events))
    assert any("unknown cell" in error for error in errors)


def test_a_cell_set_may_introduce_a_new_cell_id():
    header, events = read_gridv(_workbook())
    events.append(
        _event(
            5,
            "cell.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-99",
                "row_id": "row-1",
                "column_id": "col-2",
                "value": {"type": "date", "value": "2026-01-01"},
            },
        )
    )
    assert validate_gridv(_rebuild(header, events)) == []


def test_a_reference_to_an_unknown_sheet_is_rejected():
    header, events = read_gridv(_workbook())
    events[1]["data"]["sheet_id"] = "sheet-404"
    errors = validate_gridv(_rebuild(header, events))
    assert any("unknown sheet" in error for error in errors)


def test_a_deleted_row_id_may_not_be_reused():
    header, events = read_gridv(_workbook())
    events.append(
        _event(5, "row.delete", {"sheet_id": "sheet-1", "row_id": "row-2"})
    )
    events.append(
        _event(6, "row.insert", {"sheet_id": "sheet-1", "row": "row-2", "index": 0})
    )
    errors = validate_gridv(_rebuild(header, events))
    assert any("deleted row id" in error for error in errors)


def test_a_deleted_column_id_may_not_be_reused():
    header, events = read_gridv(_workbook())
    events.append(
        _event(5, "column.delete", {"sheet_id": "sheet-1", "column_id": "col-2"})
    )
    events.append(
        _event(6, "column.insert", {"sheet_id": "sheet-1", "column": "col-2", "index": 0})
    )
    errors = validate_gridv(_rebuild(header, events))
    assert any("deleted column id" in error for error in errors)


def test_a_deleted_cell_id_may_not_be_reused():
    header, events = read_gridv(_workbook())
    events.append(
        _event(5, "row.delete", {"sheet_id": "sheet-1", "row_id": "row-1"})
    )
    events.append(
        _event(
            6,
            "cell.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-11",
                "row_id": "row-2",
                "column_id": "col-1",
                "value": {"type": "string", "value": "again"},
            },
        )
    )
    errors = validate_gridv(_rebuild(header, events))
    assert any("deleted cell id" in error for error in errors)


def test_an_unsupported_formula_function_is_rejected():
    header, events = read_gridv(_workbook())
    events[2]["data"]["formula"] = "=VLOOKUP(A1,B1:C2,3)"
    errors = validate_gridv(_rebuild(header, events))
    assert any("unsupported function" in error for error in errors)


def test_a_formula_must_start_with_an_equals_sign():
    header, events = read_gridv(_workbook())
    events[2]["data"]["formula"] = "SUM(A1:A2)"
    errors = validate_gridv(_rebuild(header, events))
    assert any("must start with '='" in error for error in errors)


# --- reconstruction ---------------------------------------------------------

def test_checkout_reconstructs_the_expected_state():
    state = checkout_gridv(_workbook(), 3)
    assert state["workbook_id"] == "workbook-1"
    assert state["formula_profile"] == FORMULA_PROFILE
    assert state["seq"] == 3
    assert state["settings"] == {"locale": "en-US"}
    sheet = state["sheets"][0]
    assert sheet["id"] == "sheet-1"
    assert sheet["name"] == "Sheet1"
    assert [row["id"] for row in sheet["rows"]] == ["row-1", "row-2"]
    assert [row["index"] for row in sheet["rows"]] == [0, 1]
    assert [column["id"] for column in sheet["columns"]] == ["col-1", "col-2"]
    assert sheet["cells"]["cell-11"] == {
        "column_id": "col-1",
        "formula": None,
        "row_id": "row-1",
        "style": {},
        "value": {"type": "string", "value": "hello"},
    }
    assert sheet["cells"]["cell-12"]["value"] == {"type": "decimal", "value": "12.50"}
    assert sheet["cells"]["cell-13"] == {
        "column_id": "col-1",
        "formula": "=SUM(A1:A2)",
        "row_id": "row-2",
        "style": {},
        "value": None,
    }


def test_checkout_at_an_earlier_sequence_excludes_later_edits():
    state = checkout_gridv(_workbook(), 1)
    sheet = state["sheets"][0]
    assert list(sheet["cells"]) == ["cell-11"]
    assert state["seq"] == 1


def test_checkout_rejects_an_out_of_range_sequence():
    with pytest.raises(GridvValidationError):
        checkout_gridv(_workbook(), 99)


def test_checkout_does_not_evaluate_formulas():
    state = checkout_gridv(_workbook(), 3)
    formula_cell = state["sheets"][0]["cells"]["cell-13"]
    assert formula_cell["formula"] == "=SUM(A1:A2)"
    assert formula_cell["value"] is None


def test_diff_returns_the_expected_slice():
    events = diff_gridv(_workbook(), 1, 3)
    assert [event["seq"] for event in events] == [2, 3]
    assert diff_gridv(_workbook(), 0, 0) == []
    assert [event["seq"] for event in diff_gridv(_workbook(), 2, 4)] == [3, 4]


def test_log_lists_every_event():
    events = log_gridv(_workbook())
    assert [event["seq"] for event in events] == [1, 2, 3, 4]


def test_inspect_summarises_the_workbook():
    summary = inspect_gridv(_workbook())
    assert summary["workbook_id"] == "workbook-1"
    assert summary["event_count"] == 4
    assert summary["last_seq"] == 4
    assert summary["recovered"] is False
    assert len(summary["chain_tip"]) == 64


# --- export -----------------------------------------------------------------

def test_export_csv_has_the_documented_layout():
    assert export_gridv_csv(_workbook(), 3) == (
        "col-1,col-2\n"
        "hello,12.50\n"
        "=SUM(A1:A2),\n"
    )


def test_export_csv_at_an_earlier_sequence():
    assert export_gridv_csv(_workbook(), 1) == (
        "col-1,col-2\n"
        "hello,\n"
        ",\n"
    )


def test_export_csv_separates_sheets_with_a_blank_line():
    container = create_gridv("workbook-1", INITIAL_STATE)
    container = append_gridv_event(
        container,
        _event(
            2,
            "sheet.add",
            {
                "sheet": {
                    "id": "sheet-2",
                    "name": "Sheet2",
                    "rows": ["row-3"],
                    "columns": ["col-3"],
                    "cells": {
                        "cell-31": {
                            "row_id": "row-3",
                            "column_id": "col-3",
                            "value": {"type": "boolean", "value": True},
                        }
                    },
                }
            },
        ),
    )
    assert export_gridv_csv(container) == (
        "col-1,col-2\n"
        "hello,\n"
        ",\n"
        "\n"
        "col-3\n"
        "TRUE\n"
    )


def test_export_csv_quotes_values_that_need_it():
    container = create_gridv("workbook-1", INITIAL_STATE)
    container = append_gridv_event(
        container,
        _event(
            2,
            "cell.set",
            {
                "sheet_id": "sheet-1",
                "cell_id": "cell-12",
                "row_id": "row-1",
                "column_id": "col-2",
                "value": {"type": "string", "value": "a,b"},
            },
        ),
    )
    assert export_gridv_csv(container, 2) == (
        "col-1,col-2\n"
        "hello,\"a,b\"\n"
        ",\n"
    )


# --- recovery ---------------------------------------------------------------

def test_recover_returns_a_valid_prefix_container():
    container = bytearray(_workbook())
    container[-1] ^= 0xFF
    source = bytes(container)
    errors = validate_gridv(source)
    assert errors
    recovered = recover_gridv(source)
    assert validate_gridv(recovered) == []
    _header, events = read_gridv(recovered)
    assert [event["seq"] for event in events] == [1, 2, 3]


def test_recover_does_not_modify_the_source():
    container = _workbook()
    before = bytes(container)
    recover_gridv(container)
    assert container == before


def test_recover_marks_the_result_as_recovered():
    recovered = recover_gridv(_workbook())
    header, _events = read_gridv(recovered)
    marker = header["extensions"]["open-extensions.gridv.recovered"]
    assert "recovered_at" in marker
    assert marker["original_length"] > 0
    assert inspect_gridv(recovered)["recovered"] is True


# --- contract guards --------------------------------------------------------
#
# These two tests guard the module itself rather than its behaviour. A second
# writer touching these paths must not silently narrow the public contract or
# pull in a dependency the SDK does not declare.


def test_the_public_api_surface_is_complete():
    """Guard the names the CLI layer depends on."""
    import open_extensions.gridv as gridv

    constants = {"MAGIC": bytes, "FORMAT_VERSION": str, "FORMULA_PROFILE": str}
    classes = ("GridvError", "GridvFormatError", "GridvValidationError")
    functions = (
        "create_gridv",
        "append_gridv_event",
        "read_gridv",
        "write_gridv",
        "validate_gridv",
        "inspect_gridv",
        "log_gridv",
        "diff_gridv",
        "checkout_gridv",
        "export_gridv_csv",
        "recover_gridv",
    )
    for name, kind in constants.items():
        assert isinstance(getattr(gridv, name, None), kind), name
    for name in classes:
        assert isinstance(getattr(gridv, name, None), type), name
    for name in functions:
        assert callable(getattr(gridv, name, None)), name
    assert gridv.MAGIC == b"GRIDV\r\n\x1a\n"
    assert gridv.FORMAT_VERSION == "0.1.0"
    assert gridv.FORMULA_PROFILE == "nxf-formula-0.1"
    assert issubclass(gridv.GridvFormatError, gridv.GridvError)
    assert issubclass(gridv.GridvValidationError, gridv.GridvError)
    assert gridv.GridvValidationError(["boom"]).errors == ["boom"]


def test_the_module_only_uses_the_standard_library_and_the_shared_helpers():
    """Guard the rule that the module adds no undeclared dependency."""
    import ast
    from pathlib import Path

    import open_extensions.gridv as gridv

    allowed = {
        "__future__",
        "collections",
        "csv",
        "datetime",
        "decimal",
        "hashlib",
        "io",
        "json",
        "os",
        "pathlib",
        "re",
        "struct",
        "typing",
        "uuid",
    }
    tree = ast.parse(Path(gridv.__file__).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= allowed, sorted(roots - allowed)
