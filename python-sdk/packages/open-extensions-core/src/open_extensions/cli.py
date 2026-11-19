"""Command-line interface for the Open Extensions Python SDK.

Commands are namespaced by format::

    open-extensions memx create payload.json memory.memx
    open-extensions stepx validate recipe.stepx
    open-extensions gridv checkout book.gridv --seq 12

The v0.1 flat verbs (``memx-create``, ``memx-read``, ``memx-validate``,
``memx-inspect``) remain available as aliases so existing scripts keep
working.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from ._container import (
    ContainerError,
    FormatError,
    ValidationError,
    atomic_write_bytes,
    loads_json_file,
)

# The v0.1 flat verbs, kept as aliases for backwards compatibility.
LEGACY_ALIASES = {
    "memx-create": ("memx", "create"),
    "memx-read": ("memx", "read"),
    "memx-validate": ("memx", "validate"),
    "memx-inspect": ("memx", "inspect"),
}

FORMATS = ("memx", "stepx", "gridv", "podx", "wapp", "tlock")


def _is_available(format_name: str) -> bool:
    """Return True when the distribution for this format is installed.

    The six format distributions are independent, so a user may install only
    one of them. The command line must work with whatever is present.
    """
    try:
        importlib.import_module(f"open_extensions.{format_name}")
    except ImportError:
        return False
    return True


def _available_formats() -> list[str]:
    return [name for name in FORMATS if _is_available(name)]


MAX_JSON_BYTES = 16 * 1024 * 1024


class CliError(ContainerError):
    """A command-line input or usage error."""


def _password(confirm: bool = False) -> str:
    first = getpass.getpass("MEMX password: ")
    if confirm:
        second = getpass.getpass("Confirm password: ")
        if first != second:
            raise CliError("Passwords do not match")
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
        if path.stat().st_size > MAX_JSON_BYTES:
            raise CliError(f"Input JSON exceeds {MAX_JSON_BYTES} bytes")
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_nonfinite)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, CliError):
            raise
        raise CliError(f"Cannot load input JSON: {exc}") from exc


def _write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(path, encoded)
    except OSError as exc:
        raise CliError(f"Cannot write JSON output: {exc}") from exc


def _print_json(value: object) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _emit(value: object, output: Path | None) -> None:
    """Write a text or JSON result to a file, or to stdout."""
    if output is None:
        if isinstance(value, str):
            sys.stdout.write(value)
        else:
            _print_json(value)
        return
    if isinstance(value, str):
        atomic_write_bytes(output, value.encode("utf-8"))
    else:
        _write_json(output, value)


def _report(errors: list[str], *, valid_message: str) -> int:
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print(valid_message)
    return 0


def _read_secret(args: argparse.Namespace) -> bytes:
    """Read a PRF output from a file, an environment variable, or an argument."""
    if getattr(args, "prf_output_file", None):
        raw = Path(args.prf_output_file).read_bytes().strip()
        return _decode_b64url(raw, "PRF output file")
    if getattr(args, "prf_output_env", None):
        value = os.environ.get(args.prf_output_env)
        if not value:
            raise _tlock.TlockFormatError(f"Environment variable {args.prf_output_env!r} is not set")
        return _decode_b64url(value.encode("utf-8"), args.prf_output_env)
    if getattr(args, "prf_output", None):
        print(
            "WARNING: passing a PRF output on the command line exposes it to the shell "
            "history and the process list. Prefer --prf-output-file or --prf-output-env.",
            file=sys.stderr,
        )
        return _decode_b64url(args.prf_output.encode("utf-8"), "PRF output")
    raise _tlock.TlockFormatError(
        "A WebAuthn PRF output is required. Supply --prf-output-file, --prf-output-env or --prf-output."
    )


def _decode_b64url(value: bytes, name: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4))
    except Exception as exc:  # noqa: BLE001
        raise _tlock.TlockFormatError(f"{name} is not valid base64url: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="open-extensions",
        description="Create, inspect, read, and validate Open Extensions files.",
    )
    available = _available_formats()
    if not available:
        parser.error(
            "no Open Extensions format distributions are installed. "
            "Install 'open-extensions' for all six, or 'open-extensions-<format>' for one."
        )
    formats = parser.add_subparsers(dest="format", required=True, metavar="format")

    builders = {
        "memx": _add_memx,
        "stepx": _add_stepx,
        "gridv": _add_gridv,
        "podx": _add_podx,
        "wapp": _add_wapp,
        "tlock": _add_tlock,
    }
    for name in available:
        builders[name](formats)
    return parser


def _add_memx(formats: Any) -> None:
    parser = formats.add_parser("memx", help="Portable AI memory containers (.memx)")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Encrypt JSON into a .memx file")
    create.add_argument("input", type=Path, help="Input MEMX payload JSON")
    create.add_argument("output", type=Path, help="Output .memx path")

    read = commands.add_parser("read", help="Decrypt a .memx file into JSON")
    read.add_argument("input", type=Path, help="Input .memx path")
    read.add_argument("-o", "--output", type=Path, help="Output JSON path (default: stdout)")

    validate = commands.add_parser("validate", help="Validate the .memx container")
    validate.add_argument("input", type=Path, help="Input .memx path")
    validate.add_argument(
        "--verify",
        action="store_true",
        help="Also prompt for password and verify authentication and payload schema",
    )

    inspect = commands.add_parser("inspect", help="Print the non-secret .memx header")
    inspect.add_argument("input", type=Path, help="Input .memx path")


def _add_stepx(formats: Any) -> None:
    parser = formats.add_parser("stepx", help="Structured instruction documents (.stepx)")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Create a .stepx file from a JSON document")
    create.add_argument("input", type=Path, help="Input STEPX document JSON")
    create.add_argument("output", type=Path, help="Output .stepx path")

    validate = commands.add_parser("validate", help="Validate a .stepx document")
    validate.add_argument("input", type=Path, help="Input .stepx path")

    inspect = commands.add_parser("inspect", help="Summarise a .stepx document")
    inspect.add_argument("input", type=Path, help="Input .stepx path")

    scale = commands.add_parser("scale", help="Scale ingredients to a target yield")
    scale.add_argument("input", type=Path, help="Input .stepx path")
    scale.add_argument("--yield", dest="target_yield", required=True, help="Target yield as a decimal string")
    scale.add_argument("-o", "--output", type=Path, help="Output path (default: stdout JSON)")

    render = commands.add_parser("render", help="Render a .stepx document as text or Markdown")
    render.add_argument("input", type=Path, help="Input .stepx path")
    # The dest must not be "format": that name belongs to the top-level
    # format subparser and would be overwritten by this option.
    render.add_argument(
        "--format",
        dest="output_format",
        default="text",
        choices=["text", "markdown"],
        help="Output format",
    )
    render.add_argument("-o", "--output", type=Path, help="Output path (default: stdout)")


def _add_gridv(formats: Any) -> None:
    parser = formats.add_parser("gridv", help="Append-only spreadsheet history (.gridv)")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a new .gridv workbook")
    init.add_argument("workbook_id", help="Workbook identifier")
    init.add_argument("--state", type=Path, help="Initial state JSON (sheets and settings)")
    init.add_argument("-o", "--output", type=Path, required=True, help="Output .gridv path")

    append = commands.add_parser("append", help="Append an event to a .gridv workbook")
    append.add_argument("input", type=Path, help="Input .gridv path")
    append.add_argument("--event", type=Path, required=True, help="Event JSON to append")
    append.add_argument("-o", "--output", type=Path, help="Output path (default: in place)")

    validate = commands.add_parser("validate", help="Validate a .gridv workbook")
    validate.add_argument("input", type=Path, help="Input .gridv path")

    inspect = commands.add_parser("inspect", help="Summarise a .gridv workbook")
    inspect.add_argument("input", type=Path, help="Input .gridv path")

    log = commands.add_parser("log", help="List every event in the log")
    log.add_argument("input", type=Path, help="Input .gridv path")

    diff = commands.add_parser("diff", help="List the events between two sequence numbers")
    diff.add_argument("input", type=Path, help="Input .gridv path")
    diff.add_argument("--from", dest="from_seq", type=int, required=True, help="Exclusive lower bound")
    diff.add_argument("--to", dest="to_seq", type=int, required=True, help="Inclusive upper bound")

    checkout = commands.add_parser("checkout", help="Reconstruct the state at a sequence number")
    checkout.add_argument("input", type=Path, help="Input .gridv path")
    checkout.add_argument("--seq", type=int, required=True, help="Sequence number to reconstruct")

    export = commands.add_parser("export", help="Export the reconstructed state as CSV")
    export.add_argument("input", type=Path, help="Input .gridv path")
    export.add_argument("--seq", type=int, help="Sequence number (default: latest)")
    export.add_argument("-o", "--output", type=Path, help="Output path (default: stdout)")

    recover = commands.add_parser("recover", help="Write the longest verified prefix to a new file")
    recover.add_argument("input", type=Path, help="Input .gridv path")
    recover.add_argument("-o", "--output", type=Path, required=True, help="Output .gridv path")


def _add_podx(formats: Any) -> None:
    parser = formats.add_parser("podx", help="Multi-track audio packages (.podx)")
    commands = parser.add_subparsers(dest="command", required=True)

    pack = commands.add_parser("pack", help="Pack audio stems into a .podx package")
    pack.add_argument("source", type=Path, help="Directory holding the assets")
    pack.add_argument("--manifest", type=Path, required=True, help="Manifest JSON")
    pack.add_argument("-o", "--output", type=Path, required=True, help="Output .podx path")

    validate = commands.add_parser("validate", help="Validate a .podx package")
    validate.add_argument("input", type=Path, help="Input .podx path")

    inspect = commands.add_parser("inspect", help="Summarise a .podx package")
    inspect.add_argument("input", type=Path, help="Input .podx path")

    list_tracks = commands.add_parser("list-tracks", help="List the tracks in a .podx package")
    list_tracks.add_argument("input", type=Path, help="Input .podx path")

    extract = commands.add_parser("extract", help="Extract the assets of a .podx package")
    extract.add_argument("input", type=Path, help="Input .podx path")
    extract.add_argument("destination", type=Path, help="Output directory")


def _add_wapp(formats: Any) -> None:
    parser = formats.add_parser("wapp", help="Offline web-app packages (.wapp)")
    commands = parser.add_subparsers(dest="command", required=True)

    pack = commands.add_parser("pack", help="Pack a web project into a .wapp package")
    pack.add_argument("source", type=Path, help="Directory holding the app files")
    pack.add_argument("--manifest", type=Path, required=True, help="Manifest JSON")
    pack.add_argument("-o", "--output", type=Path, required=True, help="Output .wapp path")

    validate = commands.add_parser("validate", help="Validate a .wapp package")
    validate.add_argument("input", type=Path, help="Input .wapp path")

    inspect = commands.add_parser("inspect", help="Summarise a .wapp package")
    inspect.add_argument("input", type=Path, help="Input .wapp path")

    list_files = commands.add_parser("list", help="List the files in a .wapp package")
    list_files.add_argument("input", type=Path, help="Input .wapp path")

    extract = commands.add_parser("extract", help="Extract the contents of a .wapp package")
    extract.add_argument("input", type=Path, help="Input .wapp path")
    extract.add_argument("destination", type=Path, help="Output directory")

    run = commands.add_parser(
        "run",
        help="Serve the package locally (development inspection server only)",
    )
    run.add_argument("input", type=Path, help="Input .wapp path")
    run.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    run.add_argument("--port", type=int, default=0, help="Port to bind (default: an unused port)")


def _add_tlock(formats: Any) -> None:
    parser = formats.add_parser("tlock", help="Policy-bearing encrypted containers (.tlock)")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Encrypt a payload into a .tlock file")
    create.add_argument("input", type=Path, help="Input payload file")
    create.add_argument("output", type=Path, help="Output .tlock path")
    create.add_argument("--policy", type=Path, required=True, help="Policy JSON")
    create.add_argument("--mode", choices=["passkey-local", "server"], required=True, help="Key access profile")
    create.add_argument("--recipient", help="Recipient identifier (passkey-local)")
    create.add_argument("--credential-id-hash", help="Base64url credential id hash (passkey-local)")
    create.add_argument("--prf-output-file", help="File holding the base64url WebAuthn PRF output")
    create.add_argument("--prf-output-env", help="Environment variable holding the base64url PRF output")
    create.add_argument("--prf-output", help="Base64url WebAuthn PRF output (discouraged)")
    create.add_argument("--service-origin", help="Key service origin (server)")
    create.add_argument("--key-id", help="Key service key identifier (server)")
    create.add_argument("--media-type", default="application/octet-stream", help="Payload media type")

    open_cmd = commands.add_parser("open", help="Decrypt a .tlock file")
    open_cmd.add_argument("input", type=Path, help="Input .tlock path")
    open_cmd.add_argument("--mode", choices=["passkey-local", "server"], required=True, help="Key access profile")
    open_cmd.add_argument("--recipient", help="Recipient identifier (passkey-local)")
    open_cmd.add_argument("--prf-output-file", help="File holding the base64url WebAuthn PRF output")
    open_cmd.add_argument("--prf-output-env", help="Environment variable holding the base64url PRF output")
    open_cmd.add_argument("--prf-output", help="Base64url WebAuthn PRF output (discouraged)")
    open_cmd.add_argument("-o", "--output", type=Path, help="Output path (default: stdout)")

    validate = commands.add_parser("validate", help="Validate a .tlock container")
    validate.add_argument("input", type=Path, help="Input .tlock path")

    inspect = commands.add_parser("inspect", help="Print the non-secret .tlock header")
    inspect.add_argument("input", type=Path, help="Input .tlock path")

    policy = commands.add_parser("policy", help="Check the advisory access policy")
    policy.add_argument("input", type=Path, help="Input .tlock path")


# --- command implementations ----------------------------------------------

def _run_memx(args: argparse.Namespace) -> int:
    from .memx import inspect_memx, read_memx, validate_memx, write_memx

    if args.command == "create":
        payload = _load_json(args.input)
        if not isinstance(payload, dict):
            raise CliError("Input JSON root must be an object")
        password = _password(confirm=True)
        write_memx(args.output, payload, password)
        print(f"Created {args.output}")
        return 0

    if args.command == "read":
        payload = read_memx(args.input, _password())
        if args.output:
            _write_json(args.output, payload)
            print(f"Decrypted JSON written to {args.output}")
        else:
            _print_json(payload)
        return 0

    if args.command == "validate":
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

    if args.command == "inspect":
        _print_json(inspect_memx(args.input))
        return 0
    return 2


def _run_stepx(args: argparse.Namespace) -> int:
    from . import stepx as _stepx

    if args.command == "create":
        document = loads_json_file(args.input, 8 * 1024 * 1024)
        if not isinstance(document, dict):
            raise _stepx.StepxFormatError("Input JSON root must be an object")
        atomic_write_bytes(args.output, _stepx.create_stepx(document))
        print(f"Created {args.output}")
        return 0

    if args.command == "validate":
        return _report(_stepx.validate_stepx(args.input), valid_message="VALID: STEPX document")

    if args.command == "inspect":
        _print_json(_stepx.inspect_stepx(args.input))
        return 0

    if args.command == "scale":
        document = _stepx.read_stepx(args.input)
        _emit(_stepx.scale_stepx(document, args.target_yield), args.output)
        return 0

    if args.command == "render":
        document = _stepx.read_stepx(args.input)
        _emit(_stepx.render_stepx(document, args.output_format), args.output)
        return 0
    return 2


def _run_gridv(args: argparse.Namespace) -> int:
    from . import gridv as _gridv

    if args.command == "init":
        initial_state: dict[str, Any] = {"sheets": [], "settings": {}}
        if args.state:
            loaded = loads_json_file(args.state, 8 * 1024 * 1024)
            if not isinstance(loaded, dict):
                raise _gridv.GridvFormatError("Initial state JSON root must be an object")
            initial_state = loaded
        atomic_write_bytes(args.output, _gridv.create_gridv(args.workbook_id, initial_state))
        print(f"Created {args.output}")
        return 0

    if args.command == "append":
        event = loads_json_file(args.event, 64 * 1024 * 1024)
        if not isinstance(event, dict):
            raise _gridv.GridvFormatError("Event JSON root must be an object")
        container = _gridv.append_gridv_event(args.input, event)
        if args.output:
            atomic_write_bytes(args.output, container)
            print(f"Wrote {args.output}")
        else:
            atomic_write_bytes(args.input, container)
            print(f"Appended to {args.input}")
        return 0

    if args.command == "validate":
        return _report(_gridv.validate_gridv(args.input), valid_message="VALID: GRIDV workbook")

    if args.command == "inspect":
        _print_json(_gridv.inspect_gridv(args.input))
        return 0

    if args.command == "log":
        _print_json(_gridv.log_gridv(args.input))
        return 0

    if args.command == "diff":
        _print_json(_gridv.diff_gridv(args.input, args.from_seq, args.to_seq))
        return 0

    if args.command == "checkout":
        _print_json(_gridv.checkout_gridv(args.input, args.seq))
        return 0

    if args.command == "export":
        _emit(_gridv.export_gridv_csv(args.input, args.seq), args.output)
        return 0

    if args.command == "recover":
        atomic_write_bytes(args.output, _gridv.recover_gridv(args.input))
        print(f"Recovered prefix written to {args.output}")
        return 0
    return 2


def _run_podx(args: argparse.Namespace) -> int:
    from . import podx as _podx

    if args.command == "pack":
        manifest = loads_json_file(args.manifest, 4 * 1024 * 1024)
        if not isinstance(manifest, dict):
            raise _podx.PodxFormatError("Manifest JSON root must be an object")
        atomic_write_bytes(args.output, _podx.pack_podx(args.source, manifest))
        print(f"Created {args.output}")
        return 0

    if args.command == "validate":
        return _report(_podx.validate_podx(args.input), valid_message="VALID: PODX package")

    if args.command == "inspect":
        _print_json(_podx.inspect_podx(args.input))
        return 0

    if args.command == "list-tracks":
        _print_json(_podx.list_tracks_podx(args.input))
        return 0

    if args.command == "extract":
        extracted = _podx.extract_podx(args.input, args.destination)
        print(f"Extracted {len(extracted)} file(s) to {args.destination}")
        return 0
    return 2


def _run_wapp(args: argparse.Namespace) -> int:
    from . import wapp as _wapp

    if args.command == "pack":
        manifest = loads_json_file(args.manifest, 4 * 1024 * 1024)
        if not isinstance(manifest, dict):
            raise _wapp.WappFormatError("Manifest JSON root must be an object")
        atomic_write_bytes(args.output, _wapp.pack_wapp(args.source, manifest))
        print(f"Created {args.output}")
        return 0

    if args.command == "validate":
        return _report(_wapp.validate_wapp(args.input), valid_message="VALID: WAPP package")

    if args.command == "inspect":
        _print_json(_wapp.inspect_wapp(args.input))
        return 0

    if args.command == "list":
        _print_json(_wapp.list_wapp(args.input))
        return 0

    if args.command == "extract":
        extracted = _wapp.extract_wapp(args.input, args.destination)
        print(f"Extracted {len(extracted)} file(s) to {args.destination}")
        return 0

    if args.command == "run":
        _wapp.serve_wapp(args.input, host=args.host, port=args.port)
        return 0
    return 2


def _run_tlock(args: argparse.Namespace) -> int:
    from . import tlock as _tlock

    if args.command == "create":
        payload = args.input.read_bytes()
        policy = loads_json_file(args.policy, 1024 * 1024)
        if not isinstance(policy, dict):
            raise _tlock.TlockFormatError("Policy JSON root must be an object")
        if args.mode == "passkey-local":
            if not args.recipient or not args.credential_id_hash:
                raise _tlock.TlockFormatError(
                    "passkey-local requires --recipient and --credential-id-hash"
                )
            key_access = {
                "mode": "passkey-local",
                "recipients": [
                    {
                        "recipient_id": args.recipient,
                        "credential_id_hash": args.credential_id_hash,
                        "prf_output": _read_secret(args),
                    }
                ],
            }
        else:
            if not args.service_origin or not args.key_id:
                raise _tlock.TlockFormatError("server mode requires --service-origin and --key-id")
            key_access = {
                "mode": "server",
                "service_origin": args.service_origin,
                "key_id": args.key_id,
            }
        container = _tlock.create_tlock(
            payload,
            policy=policy,
            key_access=key_access,
            payload_media_type=args.media_type,
        )
        atomic_write_bytes(args.output, container)
        print(f"Created {args.output}")
        if args.mode == "server":
            print(
                "NOTE: the content key must be registered with the key service before this "
                "file can be opened. This repository does not ship a key service."
            )
        return 0

    if args.command == "open":
        if args.mode == "passkey-local":
            if not args.recipient:
                raise _tlock.TlockFormatError("passkey-local requires --recipient")
            payload = _tlock.open_tlock_passkey(
                args.input,
                prf_output=_read_secret(args),
                recipient_id=args.recipient,
            )
        else:
            raise _tlock.TlockFormatError(
                "server mode requires a key-service grant; this command does not implement the "
                "network protocol. Use the server-mode client API in the Python SDK."
            )
        if args.output:
            atomic_write_bytes(args.output, payload)
            print(f"Payload written to {args.output}")
        else:
            sys.stdout.buffer.write(payload)
        return 0

    if args.command == "validate":
        return _report(_tlock.validate_tlock(args.input), valid_message="VALID: TLOCK container")

    if args.command == "inspect":
        _print_json(_tlock.inspect_tlock(args.input))
        return 0

    if args.command == "policy":
        problems = _tlock.check_policy(_tlock.inspect_tlock(args.input))
        if problems:
            for problem in problems:
                print(f"POLICY: {problem}", file=sys.stderr)
            return 1
        print("POLICY: no advisory policy problem detected")
        return 0
    return 2


_RUNNERS = {
    "memx": _run_memx,
    "stepx": _run_stepx,
    "gridv": _run_gridv,
    "podx": _run_podx,
    "wapp": _run_wapp,
    "tlock": _run_tlock,
}


def _format_main(format_name: str) -> int:
    """Entry point for a single-format console script."""
    arguments = list(sys.argv[1:])
    return main([format_name, *arguments])


def main_memx() -> int:
    """Console script for the `open-extensions-memx` distribution."""
    return _format_main("memx")


def main_stepx() -> int:
    """Console script for the `open-extensions-stepx` distribution."""
    return _format_main("stepx")


def main_gridv() -> int:
    """Console script for the `open-extensions-gridv` distribution."""
    return _format_main("gridv")


def main_podx() -> int:
    """Console script for the `open-extensions-podx` distribution."""
    return _format_main("podx")


def main_wapp() -> int:
    """Console script for the `open-extensions-wapp` distribution."""
    return _format_main("wapp")


def main_tlock() -> int:
    """Console script for the `open-extensions-tlock` distribution."""
    return _format_main("tlock")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else sys.argv[1:]
    if arguments and arguments[0] in LEGACY_ALIASES:
        format_name, command = LEGACY_ALIASES[arguments[0]]
        arguments = [format_name, command, *arguments[1:]]

    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        return _RUNNERS[args.format](args)
    except (
        CliError,
        ContainerError,
        FormatError,
        ValidationError,
        OSError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
