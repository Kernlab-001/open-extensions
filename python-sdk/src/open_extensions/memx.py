"""MEMX v0.1 reference implementation.

The binary container is authenticated with AES-256-GCM. A password-derived
key is produced with Argon2id. The encrypted plaintext is canonical JSON
compressed with zlib.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import struct
import tempfile
import zlib
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MEMX\r\n\x1a\n"  # 8 bytes
FORMAT_VERSION = "0.1.0"
SCHEMA_URI = "urn:open-extensions:spec:memx:0.1.0"

# v0.1 fixes one interoperable KDF profile. A future profile belongs in a new
# format version; readers must never accept arbitrary attacker-chosen costs.
KDF_PROFILE = {
    "algorithm": "Argon2id",
    "memory_kib": 65_536,
    "parallelism": 4,
    "time_cost": 3,
    "version": 19,
    "key_length": 32,
}
NONCE_LENGTH = 12
SALT_LENGTH = 16
TAG_LENGTH = 16
MAX_HEADER_LENGTH = 16 * 1024
MAX_PAYLOAD_LENGTH = 16 * 1024 * 1024
MAX_COMPRESSED_LENGTH = MAX_PAYLOAD_LENGTH + 64 * 1024
MAX_CONTAINER_LENGTH = len(MAGIC) + 4 + MAX_HEADER_LENGTH + MAX_COMPRESSED_LENGTH + TAG_LENGTH
MAX_PASSWORD_BYTES = 1024

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$")


class MemxError(Exception):
    """Base class for MEMX errors."""


class MemxFormatError(MemxError):
    """The container framing or header is invalid or unsupported."""


class MemxAuthenticationError(MemxError):
    """The password is incorrect or authenticated data has been modified."""


class MemxPayloadError(MemxError):
    """The decrypted payload is malformed or invalid."""


class MemxValidationError(MemxPayloadError):
    """The supplied payload does not satisfy the v0.1 data model."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise MemxPayloadError(f"Value cannot be represented as canonical JSON: {exc}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _loads_json(raw: bytes, description: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MemxPayloadError(f"Invalid {description} JSON: {exc}") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: Any, name: str, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise MemxFormatError(f"Header field {name!r} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise MemxFormatError(f"Header field {name!r} is invalid base64url") from exc
    if len(decoded) != expected_length or _b64url_encode(decoded) != value:
        raise MemxFormatError(f"Header field {name!r} has an invalid length or encoding")
    return decoded


def _password_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        try:
            encoded = password.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise MemxError("Password cannot be encoded as UTF-8") from exc
    elif isinstance(password, bytes):
        encoded = password
    else:
        raise TypeError("password must be str or bytes")
    if not encoded:
        raise MemxError("Password must not be empty")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise MemxError(f"Password exceeds {MAX_PASSWORD_BYTES} UTF-8 bytes")
    return encoded


def _derive_key(password: str | bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=_password_bytes(password),
        salt=salt,
        time_cost=KDF_PROFILE["time_cost"],
        memory_cost=KDF_PROFILE["memory_kib"],
        parallelism=KDF_PROFILE["parallelism"],
        hash_len=KDF_PROFILE["key_length"],
        type=Type.ID,
        version=KDF_PROFILE["version"],
    )


def _timestamp_is_valid(value: Any) -> bool:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    except ValueError:
        return False


def _validate_payload(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["payload root must be an object"]

    allowed_root = {"memx_version", "exported_at", "profiles", "source", "extensions"}
    missing = {"memx_version", "exported_at", "profiles"} - payload.keys()
    extra = payload.keys() - allowed_root
    if missing:
        errors.append(f"missing root field(s): {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"unknown root field(s): {', '.join(sorted(extra))}")
    if payload.get("memx_version") != FORMAT_VERSION:
        errors.append(f"memx_version must equal {FORMAT_VERSION}")
    if not _timestamp_is_valid(payload.get("exported_at")):
        errors.append("exported_at must be an RFC 3339 UTC timestamp ending in Z")

    if "source" in payload:
        source = payload["source"]
        if not isinstance(source, dict) or any(
            key not in {"application", "application_version", "model"} for key in source
        ):
            errors.append("source must be an object with only application, application_version, and model")
        elif any(not isinstance(value, str) or len(value) > 200 for value in source.values()):
            errors.append("source values must be strings of at most 200 characters")

    if "extensions" in payload and not isinstance(payload["extensions"], dict):
        errors.append("extensions must be an object")

    profiles = payload.get("profiles")
    if not isinstance(profiles, list) or not (1 <= len(profiles) <= 100):
        errors.append("profiles must be an array containing 1 to 100 profiles")
        return errors

    seen_profile_ids: set[str] = set()
    for index, profile in enumerate(profiles):
        prefix = f"profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{prefix} must be an object")
            continue
        required = {"id", "label", "preferences", "coding_profiles", "context_items"}
        if required - profile.keys():
            errors.append(f"{prefix} is missing: {', '.join(sorted(required - profile.keys()))}")
        if profile.keys() - required:
            errors.append(f"{prefix} contains unsupported fields: {', '.join(sorted(profile.keys() - required))}")

        profile_id = profile.get("id")
        if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 100:
            errors.append(f"{prefix}.id must be a non-empty string of at most 100 characters")
        elif profile_id in seen_profile_ids:
            errors.append(f"{prefix}.id must be unique")
        else:
            seen_profile_ids.add(profile_id)

        label = profile.get("label")
        if not isinstance(label, str) or not label.strip() or len(label) > 80:
            errors.append(f"{prefix}.label must be a non-empty string of at most 80 characters")

        if not isinstance(profile.get("preferences"), dict):
            errors.append(f"{prefix}.preferences must be an object")

        coding_profiles = profile.get("coding_profiles")
        if not isinstance(coding_profiles, dict):
            errors.append(f"{prefix}.coding_profiles must be an object keyed by language or tool")
        else:
            for language, settings in coding_profiles.items():
                if not isinstance(language, str) or not language or len(language) > 80:
                    errors.append(f"{prefix}.coding_profiles has an invalid key")
                    continue
                if not isinstance(settings, dict):
                    errors.append(f"{prefix}.coding_profiles[{language!r}] must be an object")
                elif settings.keys() - {"style_guide", "formatting", "examples"}:
                    errors.append(f"{prefix}.coding_profiles[{language!r}] has unsupported fields")
                else:
                    style_guide = settings.get("style_guide", "")
                    if not isinstance(style_guide, str) or len(style_guide) > 100_000:
                        errors.append(f"{prefix}.coding_profiles[{language!r}].style_guide must be a string up to 100000 characters")
                    if "formatting" in settings and not isinstance(settings["formatting"], dict):
                        errors.append(f"{prefix}.coding_profiles[{language!r}].formatting must be an object")
                    if "examples" in settings:
                        examples = settings["examples"]
                        if not isinstance(examples, list) or len(examples) > 50 or any(not isinstance(x, str) or len(x) > 20_000 for x in examples):
                            errors.append(f"{prefix}.coding_profiles[{language!r}].examples must be an array of up to 50 strings (20000 chars each)")

        context_items = profile.get("context_items")
        if not isinstance(context_items, list) or len(context_items) > 10_000:
            errors.append(f"{prefix}.context_items must be an array of at most 10000 items")
        else:
            seen_context_ids: set[str] = set()
            for item_index, item in enumerate(context_items):
                item_prefix = f"{prefix}.context_items[{item_index}]"
                if not isinstance(item, dict):
                    errors.append(f"{item_prefix} must be an object")
                    continue
                item_required = {"id", "kind", "content", "updated_at", "tags"}
                if item.keys() != item_required:
                    errors.append(f"{item_prefix} must contain exactly: {', '.join(sorted(item_required))}")
                item_id = item.get("id")
                if not isinstance(item_id, str) or not item_id or len(item_id) > 100:
                    errors.append(f"{item_prefix}.id must be a non-empty string of at most 100 characters")
                elif item_id in seen_context_ids:
                    errors.append(f"{item_prefix}.id must be unique within its profile")
                else:
                    seen_context_ids.add(item_id)
                kind = item.get("kind")
                if not isinstance(kind, str) or kind not in {"preference", "project", "fact", "instruction", "workflow", "other"}:
                    errors.append(f"{item_prefix}.kind is not a supported context kind")
                content = item.get("content")
                if not isinstance(content, str) or not content.strip() or len(content) > 200_000:
                    errors.append(f"{item_prefix}.content must be a non-empty string up to 200000 characters")
                if not _timestamp_is_valid(item.get("updated_at")):
                    errors.append(f"{item_prefix}.updated_at must be an RFC 3339 UTC timestamp ending in Z")
                tags = item.get("tags")
                if not isinstance(tags, list) or len(tags) > 100 or any(not isinstance(tag, str) or len(tag) > 80 for tag in tags):
                    errors.append(f"{item_prefix}.tags must be an array of up to 100 strings (80 chars each)")
    return errors


def _read_source(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        raw = bytes(source)
    else:
        try:
            path = Path(source)
            if path.stat().st_size > MAX_CONTAINER_LENGTH:
                raise MemxFormatError("Container exceeds the v0.1 maximum file size")
            raw = path.read_bytes()
        except OSError as exc:
            raise MemxFormatError(f"Cannot read MEMX file: {exc}") from exc
    if len(raw) > MAX_CONTAINER_LENGTH:
        raise MemxFormatError("Container exceeds the v0.1 maximum file size")
    return raw


def _parse_container(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    raw = _read_source(source)
    if len(raw) < len(MAGIC) + 4 or raw[:len(MAGIC)] != MAGIC:
        raise MemxFormatError("Invalid MEMX magic bytes")
    header_length = struct.unpack(">I", raw[len(MAGIC):len(MAGIC) + 4])[0]
    if not (2 <= header_length <= MAX_HEADER_LENGTH):
        raise MemxFormatError("Header length is outside the v0.1 bounds")
    header_start = len(MAGIC) + 4
    header_end = header_start + header_length
    if header_end > len(raw):
        raise MemxFormatError("Truncated MEMX header")

    header_raw = raw[header_start:header_end]
    header = _loads_json(header_raw, "header")
    if not isinstance(header, dict):
        raise MemxFormatError("Header must be a JSON object")
    if _canonical_json(header) != header_raw:
        raise MemxFormatError("Header JSON is not in canonical v0.1 encoding")

    expected_keys = {
        "cipher", "ciphertext_length", "compression", "created_at", "format",
        "format_version", "kdf", "nonce", "payload_length", "payload_schema", "payload_type",
    }
    if header.keys() != expected_keys:
        raise MemxFormatError("Header fields do not match the MEMX v0.1 profile")
    if header.get("format") != "memx" or header.get("format_version") != FORMAT_VERSION:
        raise MemxFormatError("Unsupported MEMX format or version")
    if header.get("cipher") != "AES-256-GCM" or header.get("compression") != "zlib":
        raise MemxFormatError("Unsupported MEMX cipher or compression profile")
    if header.get("payload_type") != "application/json; charset=utf-8" or header.get("payload_schema") != SCHEMA_URI:
        raise MemxFormatError("Unsupported MEMX payload type or schema")
    if not _timestamp_is_valid(header.get("created_at")):
        raise MemxFormatError("Header created_at must be an RFC 3339 UTC timestamp ending in Z")

    kdf = header.get("kdf")
    if not isinstance(kdf, dict) or set(kdf) != (set(KDF_PROFILE) | {"salt"}):
        raise MemxFormatError("Invalid MEMX KDF profile")
    # Exact fixed profile; never trust KDF parameters supplied by a file.
    if {key: value for key, value in kdf.items() if key != "salt"} != KDF_PROFILE:
        raise MemxFormatError("Unsupported MEMX KDF parameters")
    salt = _b64url_decode(kdf.get("salt"), "kdf.salt", SALT_LENGTH)
    nonce = _b64url_decode(header.get("nonce"), "nonce", NONCE_LENGTH)

    payload_length = header.get("payload_length")
    ciphertext_length = header.get("ciphertext_length")
    if isinstance(payload_length, bool) or not isinstance(payload_length, int) or not (1 <= payload_length <= MAX_PAYLOAD_LENGTH):
        raise MemxFormatError("payload_length is outside the v0.1 bounds")
    if isinstance(ciphertext_length, bool) or not isinstance(ciphertext_length, int) or not (TAG_LENGTH + 1 <= ciphertext_length <= MAX_COMPRESSED_LENGTH + TAG_LENGTH):
        raise MemxFormatError("ciphertext_length is outside the v0.1 bounds")

    ciphertext = raw[header_end:]
    if len(ciphertext) != ciphertext_length:
        raise MemxFormatError("ciphertext_length does not match the actual container size")
    aad = raw[:header_end]
    # Return salt via a private, in-memory key to avoid copying it into user-facing metadata.
    header["_decoded_salt"] = salt
    header["_decoded_nonce"] = nonce
    return header, header_raw, ciphertext, aad


def create_memx(payload: Mapping[str, Any], password: str | bytes) -> bytes:
    """Create a MEMX v0.1 container and return its bytes."""
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    payload_obj = dict(payload)
    errors = _validate_payload(payload_obj)
    if errors:
        raise MemxValidationError(errors)
    payload_raw = _canonical_json(payload_obj)
    if not (1 <= len(payload_raw) <= MAX_PAYLOAD_LENGTH):
        raise MemxPayloadError("Canonical payload size exceeds the v0.1 limit")
    compressed = zlib.compress(payload_raw, level=9)
    if len(compressed) > MAX_COMPRESSED_LENGTH:
        raise MemxPayloadError("Compressed payload exceeds the v0.1 limit")

    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    header: dict[str, Any] = {
        "cipher": "AES-256-GCM",
        "ciphertext_length": len(compressed) + TAG_LENGTH,
        "compression": "zlib",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "format": "memx",
        "format_version": FORMAT_VERSION,
        "kdf": {**KDF_PROFILE, "salt": _b64url_encode(salt)},
        "nonce": _b64url_encode(nonce),
        "payload_length": len(payload_raw),
        "payload_schema": SCHEMA_URI,
        "payload_type": "application/json; charset=utf-8",
    }
    header_raw = _canonical_json(header)
    if len(header_raw) > MAX_HEADER_LENGTH:
        raise MemxFormatError("Generated header exceeds the v0.1 maximum")
    prefix = MAGIC + struct.pack(">I", len(header_raw))
    aad = prefix + header_raw
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, aad)
    if len(ciphertext) != header["ciphertext_length"]:
        raise MemxError("Internal error: unexpected AES-GCM output length")
    container = aad + ciphertext
    if len(container) > MAX_CONTAINER_LENGTH:
        raise MemxFormatError("Generated container exceeds the v0.1 maximum")
    return container


def read_memx(source: bytes | bytearray | memoryview | str | os.PathLike[str], password: str | bytes) -> dict[str, Any]:
    """Authenticate, decrypt, decompress, and return the MEMX JSON payload."""
    header, _header_raw, ciphertext, aad = _parse_container(source)
    salt = header.pop("_decoded_salt")
    nonce = header.pop("_decoded_nonce")
    key = _derive_key(password, salt)
    try:
        compressed = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise MemxAuthenticationError("Authentication failed: wrong password or modified file") from exc

    if len(compressed) > MAX_COMPRESSED_LENGTH:
        raise MemxPayloadError("Compressed payload exceeds the v0.1 limit")
    try:
        decompressor = zlib.decompressobj()
        payload_raw = decompressor.decompress(compressed, header["payload_length"] + 1)
        if len(payload_raw) > header["payload_length"] or decompressor.unconsumed_tail:
            raise MemxPayloadError("Decompressed payload exceeds its declared size")
        if not decompressor.eof or decompressor.unused_data:
            raise MemxPayloadError("Compressed payload is truncated or contains trailing data")
        tail = decompressor.flush()
        if tail:
            payload_raw += tail
    except zlib.error as exc:
        raise MemxPayloadError("Compressed payload is not valid zlib data") from exc

    if len(payload_raw) != header["payload_length"]:
        raise MemxPayloadError("Decompressed length does not match payload_length")
    payload = _loads_json(payload_raw, "payload")
    if _canonical_json(payload) != payload_raw:
        raise MemxPayloadError("Payload JSON is not in canonical v0.1 encoding")
    errors = _validate_payload(payload)
    if errors:
        raise MemxValidationError(errors)
    return payload


def inspect_memx(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> dict[str, Any]:
    """Return the unauthenticated, non-secret header for inspection."""
    header, _header_raw, _ciphertext, _aad = _parse_container(source)
    header.pop("_decoded_salt", None)
    header.pop("_decoded_nonce", None)
    return header


def validate_memx(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    password: str | bytes | None = None,
) -> list[str]:
    """Return validation errors; with a password, also verify/decode the payload.

    Without a password, this checks framing, header profile, and length fields,
    but cannot authenticate ciphertext or validate its encrypted JSON payload.
    """
    try:
        _parse_container(source)
        if password is not None:
            read_memx(source, password)
        return []
    except MemxError as exc:
        if isinstance(exc, MemxValidationError):
            return list(exc.errors)
        return [str(exc)]


def write_memx(
    output: str | os.PathLike[str],
    payload: Mapping[str, Any],
    password: str | bytes,
) -> None:
    """Create a MEMX file using an atomic replacement and a private temp file."""
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    container = create_memx(payload, password)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(container)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, destination)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
