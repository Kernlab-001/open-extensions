"""Command-line interface for the Open Extensions Python SDK."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from .memx import (
    MAX_PAYLOAD_LENGTH,
    MemxError,
    inspect_memx,
    read_memx,
    validate_memx,
    write_memx,
)


def _password(confirm: bool = False) -> str:
    first = getpass.getpass("MEMX password: ")
    if confirm:
        second = getpass.getpass("Confirm password: ")
        if first != second:
            raise MemxError("Passwords do not match")
    return first


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON value is not allowed: {value}")


def _load_json(path: Path) -> object:
    try:
        if path.stat().st_size > MAX_PAYLOAD_LENGTH:
            raise MemxError(f"Input JSON exceeds {MAX_PAYLOAD_LENGTH} bytes")
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_nonfinite)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, MemxError):
            raise
        raise MemxError(f"Cannot load input JSON: {exc}") from exc


def _write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise MemxError(f"Cannot write JSON output: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="open-extensions",
        description="Create, inspect, read, and validate Open Extensions files.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("memx-create", help="Encrypt JSON into a .memx file")
    create.add_argument("input", type=Path, help="Input MEMX payload JSON")
    create.add_argument("output", type=Path, help="Output .memx path")

    read = subparsers.add_parser("memx-read", help="Decrypt a .memx file into JSON")
    read.add_argument("input", type=Path, help="Input .memx path")
    read.add_argument("-o", "--output", type=Path, help="Output JSON path (default: stdout)")

    validate = subparsers.add_parser("memx-validate", help="Validate the .memx container")
    validate.add_argument("input", type=Path, help="Input .memx path")
    validate.add_argument("--verify", action="store_true", help="Also prompt for password and verify authentication and payload schema")

    inspect = subparsers.add_parser("memx-inspect", help="Print the non-secret .memx header")
    inspect.add_argument("input", type=Path, help="Input .memx path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "memx-create":
            payload = _load_json(args.input)
            if not isinstance(payload, dict):
                raise MemxError("Input JSON root must be an object")
            password = _password(confirm=True)
            write_memx(args.output, payload, password)
            print(f"Created {args.output}")
            return 0

        if args.command == "memx-read":
            payload = read_memx(args.input, _password())
            if args.output:
                _write_json(args.output, payload)
                print(f"Decrypted JSON written to {args.output}")
            else:
                sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            return 0

        if args.command == "memx-validate":
            password = _password() if args.verify else None
            errors = validate_memx(args.input, password=password)
            if errors:
                for error in errors:
                    print(f"INVALID: {error}", file=sys.stderr)
                return 1
            if args.verify:
                print("VALID: container, authentication, decrypted payload, and schema")
            else:
                print("STRUCTURALLY VALID: authentication and encrypted payload were not checked; use --verify")
            return 0

        if args.command == "memx-inspect":
            print(json.dumps(inspect_memx(args.input), ensure_ascii=False, indent=2, sort_keys=True))
            return 0

        parser.error("unknown command")
    except (MemxError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
