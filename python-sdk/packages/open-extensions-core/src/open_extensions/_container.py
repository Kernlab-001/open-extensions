"""Shared container helpers for the Open Extensions format family.

Every v0.1 format in this family follows the same envelope discipline:
canonical JSON, bounded lengths, no trailing bytes, and defensive parsing.
This module holds the parts that must behave identically across formats, so
each format module only has to describe what is specific to it.

The rules implemented here come from ``specs/common/container-principles.md``.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

# Canonical JSON: UTF-8 without BOM, keys sorted lexicographically, no
# insignificant whitespace, no non-finite numbers.
def canonical_json(value: Any) -> bytes:
    """Serialize a value to canonical UTF-8 JSON bytes."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FormatError(f"Value cannot be represented as canonical JSON: {exc}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def loads_strict(raw: bytes, description: str) -> Any:
    """Parse JSON bytes, rejecting duplicate keys and non-finite numbers."""
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except UnicodeDecodeError as exc:
        raise FormatError(f"{description} is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FormatError(f"Invalid {description} JSON: {exc}") from exc
    except ValueError as exc:
        raise FormatError(f"Invalid {description} JSON: {exc}") from exc


def loads_json_file(path: str | os.PathLike[str], max_bytes: int) -> Any:
    """Read and parse a JSON document from disk with a size bound."""
    source = Path(path)
    try:
        size = source.stat().st_size
    except OSError as exc:
        raise FormatError(f"Cannot read input JSON: {exc}") from exc
    if size > max_bytes:
        raise FormatError(f"Input JSON exceeds {max_bytes} bytes")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise FormatError(f"Cannot read input JSON: {exc}") from exc
    return loads_strict(raw, "input")


# --- base64url -------------------------------------------------------------

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_encode(value: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: Any, name: str, expected_length: int | None = None) -> bytes:
    """Decode canonical unpadded base64url, rejecting sloppy encodings."""
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise FormatError(f"Field {name!r} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise FormatError(f"Field {name!r} is invalid base64url") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise FormatError(f"Field {name!r} has an invalid length")
    if b64url_encode(decoded) != value:
        raise FormatError(f"Field {name!r} is not canonically encoded")
    return decoded


# --- timestamps ------------------------------------------------------------

_TIMESTAMP_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$")


def timestamp_is_valid(value: Any) -> bool:
    """Return True for an RFC 3339 UTC timestamp ending in Z."""
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def utc_now() -> str:
    """Return the current UTC time as an RFC 3339 Z timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --- file IO ---------------------------------------------------------------

def read_source(source: bytes | bytearray | memoryview | str | os.PathLike[str], max_length: int, label: str) -> bytes:
    """Read a container from bytes or a path, enforcing a maximum size."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
    else:
        path = Path(source)
        try:
            if path.stat().st_size > max_length:
                raise FormatError(f"{label} exceeds the v0.1 maximum file size")
            raw = path.read_bytes()
        except FormatError:
            raise
        except OSError as exc:
            raise FormatError(f"Cannot read {label}: {exc}") from exc
    if len(raw) > max_length:
        raise FormatError(f"{label} exceeds the v0.1 maximum file size")
    return raw


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """Write bytes with an atomic replace and a restrictive temp file."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, destination)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def atomic_write_json(path: str | os.PathLike[str], value: Any, *, canonical: bool = False) -> None:
    """Write a JSON document, either canonical or human readable."""
    if canonical:
        data = canonical_json(value) + b"\n"
    else:
        data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(path, data)


# --- framing ---------------------------------------------------------------

def read_length_prefixed(
    raw: bytes,
    magic: bytes,
    *,
    prefix_size: int,
    min_length: int,
    max_length: int,
    label: str,
) -> tuple[bytes, int]:
    """Return the length-prefixed body and the offset just after it.

    The body is expected to hold canonical UTF-8 JSON. The returned offset is
    where any remaining payload (ciphertext, ZIP archive, frames) begins.
    """
    if len(raw) < len(magic) + prefix_size:
        raise FormatError(f"Invalid {label} magic bytes")
    if raw[: len(magic)] != magic:
        raise FormatError(f"Invalid {label} magic bytes")
    start = len(magic)
    if prefix_size == 4:
        length = struct.unpack(">I", raw[start : start + 4])[0]
    elif prefix_size == 8:
        length = struct.unpack(">Q", raw[start : start + 8])[0]
    else:  # pragma: no cover - programming error
        raise FormatError("Unsupported length prefix size")
    if not (min_length <= length <= max_length):
        raise FormatError(f"{label} length is outside the v0.1 bounds")
    body_start = start + prefix_size
    body_end = body_start + length
    if body_end > len(raw):
        raise FormatError(f"Truncated {label} body")
    return raw[body_start:body_end], body_end


def parse_canonical_body(body: bytes, label: str) -> dict[str, Any]:
    """Parse a canonical JSON object body, rejecting non-canonical encodings."""
    value = loads_strict(body, label)
    if not isinstance(value, dict):
        raise FormatError(f"{label} must be a JSON object")
    if canonical_json(value) != body:
        raise FormatError(f"{label} JSON is not in canonical v0.1 encoding")
    return value


# --- decimals --------------------------------------------------------------

_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")


def parse_decimal(value: Any, name: str) -> Decimal:
    """Parse an exact decimal string, rejecting exponent and float notation."""
    if not isinstance(value, str) or not _DECIMAL_RE.fullmatch(value):
        raise FormatError(f"{name} must be a decimal string such as \"1\" or \"0.5\"")
    try:
        return Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - regex already guards
        raise FormatError(f"{name} is not a valid decimal") from exc


def format_decimal(value: Decimal) -> str:
    """Render a Decimal without exponent notation."""
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


# --- ZIP safety ------------------------------------------------------------

class ZipLimits:
    """Bounds applied to embedded ZIP archives."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        max_total_bytes: int = 512 * 1024 * 1024,
        max_entry_bytes: int = 256 * 1024 * 1024,
        max_ratio: int = 200,
    ) -> None:
        self.max_entries = max_entries
        self.max_total_bytes = max_total_bytes
        self.max_entry_bytes = max_entry_bytes
        self.max_ratio = max_ratio


def _member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def zip_safety_errors(archive: zipfile.ZipFile, limits: ZipLimits) -> list[str]:
    """Return the archive-safety violations for a ZIP member list.

    Implements the archive rules from ``container-principles.md`` section 5:
    relative normalized paths, no symlinks or special files, no encrypted
    entries, and bounded entry count, sizes and compression ratio.
    """
    errors: list[str] = []
    entries = archive.infolist()
    if len(entries) > limits.max_entries:
        errors.append(f"archive has {len(entries)} entries, exceeding the limit of {limits.max_entries}")
    total = 0
    for info in entries:
        name = info.filename
        if name.startswith("/") or name.startswith("\\"):
            errors.append(f"archive entry {name!r} uses an absolute path")
        if ".." in Path(name).parts:
            errors.append(f"archive entry {name!r} escapes the archive root")
        if "\x00" in name:
            errors.append(f"archive entry {name!r} contains a NUL byte")
        if len(name) > 1 and name[1] == ":":
            errors.append(f"archive entry {name!r} uses a drive prefix")
        if name.startswith("\\\\"):
            errors.append(f"archive entry {name!r} uses a UNC root")
        if info.flag_bits & 0x1:
            errors.append(f"archive entry {name!r} is encrypted")
        if _member_is_symlink(info):
            errors.append(f"archive entry {name!r} is a symlink")
        if (info.external_attr >> 16) & 0o170000 not in (0, stat.S_IFREG):
            if not info.is_dir():
                errors.append(f"archive entry {name!r} is not a regular file")
        if info.file_size > limits.max_entry_bytes:
            errors.append(f"archive entry {name!r} exceeds the per-entry size limit")
        if info.compress_size > 0 and info.file_size / info.compress_size > limits.max_ratio:
            errors.append(f"archive entry {name!r} exceeds the compression ratio limit")
        total += info.file_size
    if total > limits.max_total_bytes:
        errors.append(f"archive expands to {total} bytes, exceeding the limit of {limits.max_total_bytes}")
    return errors


def extract_zip_safely(archive: zipfile.ZipFile, destination: str | os.PathLike[str]) -> list[str]:
    """Extract archive members into an isolated directory, refusing overwrites.

    Returns the list of extracted member names.
    """
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        target = (root / info.filename).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            raise FormatError(f"archive entry {info.filename!r} escapes the extraction root")
        if target.exists():
            raise FormatError(f"refusing to overwrite existing file {info.filename!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, target.open("wb") as sink:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                sink.write(chunk)
        extracted.append(info.filename)
    return extracted


def read_zip_member(archive: zipfile.ZipFile, name: str, max_bytes: int) -> bytes:
    """Read one archive member with a size bound."""
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise FormatError(f"archive is missing required member {name!r}") from exc
    if info.file_size > max_bytes:
        raise FormatError(f"archive member {name!r} exceeds its size limit")
    with archive.open(info) as stream:
        return stream.read(max_bytes + 1)


# --- JSON Schema -----------------------------------------------------------

def find_specs_dir() -> Path | None:
    """Locate the repository's ``specs`` directory when running from a checkout.

    Returns ``None`` when the specs are not reachable, which is the normal
    case for a wheel installed from PyPI: the JSON Schemas ship with the
    repository, not with the package. Set ``OPEN_EXTENSIONS_SPECS_DIR`` to
    point at them explicitly.

    Three locations are tried, in order: the environment override, the
    directories above this file (a source checkout or an editable install),
    and the directories above the current working directory (a non-editable
    install used from inside a checkout).
    """
    override = os.environ.get("OPEN_EXTENSIONS_SPECS_DIR")
    if override:
        candidate = Path(override)
        return candidate if candidate.is_dir() else None

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "specs"
        if candidate.is_dir() and (candidate / "common").is_dir():
            return candidate

    try:
        cwd = Path.cwd().resolve()
    except OSError:  # pragma: no cover - the working directory may be gone
        return None
    for parent in cwd.parents:
        candidate = parent / "specs"
        if candidate.is_dir() and (candidate / "common").is_dir():
            return candidate
    return None


def load_schema(format_name: str) -> dict[str, Any] | None:
    """Load a format's JSON Schema.

    The schemas ship inside the ``open-extensions-core`` package, so schema
    validation works for a plain ``pip install`` and not only inside a
    checkout. A checkout is used as a fallback, and the packaged copy is
    checked against it by the test suite.
    """
    packaged = Path(__file__).resolve().parent / "schemas" / f"{format_name}.json"
    if packaged.is_file():
        return json.loads(packaged.read_text(encoding="utf-8"))
    specs = find_specs_dir()
    if specs is None:
        return None
    path = specs / format_name / "0.1.0" / "schema.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def schema_errors(format_name: str, instance: Any) -> list[str]:
    """Validate an instance against a format's JSON Schema.

    Returns an empty list when the schema is unavailable or ``jsonschema`` is
    not installed, because semantic validation is always performed separately.
    """
    schema = load_schema(format_name)
    if schema is None:
        return []
    try:
        from jsonschema import Draft202012Validator
    except ImportError:  # pragma: no cover - optional at runtime
        return []
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return [
        f"schema: {error.json_path or '/'}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    ]


# --- errors ----------------------------------------------------------------

class ContainerError(Exception):
    """Base class for Open Extensions container errors."""


class FormatError(ContainerError):
    """The container framing or metadata is invalid or unsupported."""


class ValidationError(ContainerError):
    """The document does not satisfy the v0.1 data model."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))
