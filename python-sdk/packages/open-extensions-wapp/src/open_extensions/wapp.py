"""WAPP v0.1 reference implementation.

A ``.wapp`` package is a single-file container for an offline web
application: a canonical JSON manifest followed by a ZIP archive holding the
``app/`` payload and an optional ``storage/seed.sqlite`` seed database. The
framing, the manifest, and the permission model are defined by
``specs/wapp/0.1.0/spec.md``.

Container framing (all integers are unsigned big-endian)::

    | Order | Length | Field                                              |
    |-------|--------|----------------------------------------------------|
    | 1     | 8      | magic ``WAPP\\r\\n\\x1a\\n``                          |
    | 2     | 4      | manifest length (1 byte to 4 MiB)                   |
    | 3     | N      | canonical UTF-8 JSON manifest                       |
    | 4     | 8      | ZIP/ZIP64 archive length                            |
    | 5     | M      | ZIP archive with ``app/`` files and optional seed   |

No trailing data is allowed and ZIP encryption is forbidden.

Permission model
----------------
``permissions`` is the *only* declaration channel. The v0.1 vocabulary is the
seven capabilities of the manifest schema: ``storage.sqlite``,
``clipboard.read``, ``clipboard.write``, ``notifications``, ``camera``,
``microphone`` and ``geolocation``. The validator models three kinds of
finding:

1. A capability that the vocabulary can express (camera, microphone,
   geolocation, clipboard, notifications) is reported when the package
   requests it in its content without declaring the matching permission.
2. A capability that the vocabulary cannot express (downloads, popups,
   external protocol handlers, file chooser, native filesystem access) is
   reported whenever it is requested, because the runtime would have to grant
   an undeclared capability. ``security.allow_popups`` and
   ``security.external_navigation`` are the manifest-level signals for the
   same rule.
3. A declared permission that is not in the vocabulary is reported as an
   unknown capability.

Static limits of this module
----------------------------
This module is a container encoder, decoder, and validator. It is **not** a
security audit of arbitrary JavaScript, and it does not sandbox anything.
Validation is not a security audit of arbitrary JavaScript: the checks below
cover framing, hashes, archive safety, manifest policy, and local capability
markers only. The capability scan is a marker scan over the package text
assets: it finds the plain API spellings of a capability request and cannot
find one that is obfuscated, minified into a computed property, or fetched at
runtime. A clean scan is therefore not evidence that a package stays inside
its declared permissions. A real WAPP runtime is a separate, separately
installed, OS-registered component that creates an isolated WebView, enforces
the declared capability policy, and mediates SQLite access through a narrow
parameterized host bridge. No such runtime exists in this repository.

``serve_wapp`` is therefore a **development inspection server only**. It is
not a security-enforcing runtime: it does not enforce the declared permission
policy, it does not provide the WebView isolation or the SQLite host bridge,
and the JavaScript it serves is untrusted.
"""
from __future__ import annotations

import hashlib
import io
import mimetypes
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import zipfile
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from ._container import (
    ContainerError,
    FormatError,
    ValidationError,
    ZipLimits,
    atomic_write_bytes,
    canonical_json,
    extract_zip_safely,
    parse_canonical_body,
    read_length_prefixed,
    read_source,
    schema_errors,
    zip_safety_errors,
)

MAGIC = b"WAPP\r\n\x1a\n"  # 8 bytes
FORMAT_VERSION = "0.1.0"

MIN_MANIFEST_LENGTH = 1
MAX_MANIFEST_LENGTH = 4 * 1024 * 1024
MAX_ARCHIVE_LENGTH = 512 * 1024 * 1024
MAX_CONTAINER_LENGTH = len(MAGIC) + 4 + MAX_MANIFEST_LENGTH + 8 + MAX_ARCHIVE_LENGTH

APP_PREFIX = "app/"
STORAGE_PREFIX = "storage/"
SEED_PATH = "storage/seed.sqlite"
DEFAULT_ENTRYPOINT = "app/index.html"

# The only top-level trees a packed project may contribute to the archive.
_PACKAGE_ROOTS = frozenset({"app", "storage"})

# Fixed ZIP profile so that packing the same inputs twice is byte-identical.
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
ZIP_LIMITS = ZipLimits(
    max_entries=10_000,
    max_total_bytes=512 * 1024 * 1024,
    max_entry_bytes=256 * 1024 * 1024,
    max_ratio=200,
)

# The complete v0.1 permission vocabulary. A package may only request these.
ALLOWED_PERMISSIONS = frozenset(
    {
        "storage.sqlite",
        "clipboard.read",
        "clipboard.write",
        "notifications",
        "camera",
        "microphone",
        "geolocation",
    }
)

# Permissions that require a matching manifest block.
_STORAGE_PERMISSION = "storage.sqlite"

_SCAN_MAX_FILE_BYTES = 2 * 1024 * 1024
_SCAN_EXTENSIONS = frozenset(
    {
        ".html",
        ".htm",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        ".css",
        ".json",
        ".txt",
        ".md",
        ".svg",
        ".xml",
        ".webmanifest",
    }
)

# Content markers for a locally requested capability. Each marker maps to a
# capability name; a capability either needs declared permissions or can never
# be declared in v0.1.
_CAPABILITY_MARKERS: tuple[tuple[str, str], ...] = (
    ("getusermedia", "camera/microphone capture"),
    ("mediadevices", "camera/microphone capture"),
    ("navigator.geolocation", "geolocation"),
    ("getcurrentposition", "geolocation"),
    ("clipboard.readtext", "clipboard read"),
    ("navigator.clipboard.read", "clipboard read"),
    ("clipboard.writetext", "clipboard write"),
    ("navigator.clipboard.write", "clipboard write"),
    ("shownotification", "notifications"),
    ("notification.permission", "notifications"),
    ("notification.requestpermission", "notifications"),
    ("showopenfilepicker", "file chooser"),
    ("showsavefilepicker", "file chooser"),
    ("webkitdirectory", "file chooser"),
    ('type="file"', "file chooser"),
    ("type='file'", "file chooser"),
    ("type=file", "file chooser"),
    ("node:fs", "native filesystem access"),
    ("require('fs')", "native filesystem access"),
    ('require("fs")', "native filesystem access"),
    ("from 'fs'", "native filesystem access"),
    ('from "fs"', "native filesystem access"),
    ("file://", "native filesystem access"),
    ("window.open(", "popups"),
    ("download=", "downloads"),
    (".download", "downloads"),
    ("javascript:", "external protocol handler"),
    ("vbscript:", "external protocol handler"),
    ("intent:", "external protocol handler"),
    ("ms-msdt:", "external protocol handler"),
)

# Capability -> permissions that must be declared. ``None`` means the v0.1
# permission vocabulary cannot express the capability at all.
_CAPABILITY_REQUIREMENTS: dict[str, tuple[str, ...] | None] = {
    "camera/microphone capture": ("camera", "microphone"),
    "geolocation": ("geolocation",),
    "clipboard read": ("clipboard.read",),
    "clipboard write": ("clipboard.write",),
    "notifications": ("notifications",),
    "file chooser": None,
    "native filesystem access": None,
    "popups": None,
    "downloads": None,
    "external protocol handler": None,
}

# Allowed source tokens per CSP directive, before declared network origins
# are added. The default profile forbids inline and remote scripts.
_CSP_TOKEN_SETS: dict[str, frozenset[str]] = {
    "default-src": frozenset({"'none'"}),
    "script-src": frozenset({"'self'", "'none'"}),
    "script-src-elem": frozenset({"'self'", "'none'"}),
    "script-src-attr": frozenset({"'none'"}),
    "style-src": frozenset({"'self'", "'none'"}),
    "style-src-elem": frozenset({"'self'", "'none'"}),
    "style-src-attr": frozenset({"'none'"}),
    "img-src": frozenset({"'self'", "'none'", "data:"}),
    "font-src": frozenset({"'self'", "'none'", "data:"}),
    "media-src": frozenset({"'self'", "'none'", "data:", "blob:"}),
    "connect-src": frozenset({"'self'", "'none'"}),
    "object-src": frozenset({"'none'"}),
    "base-uri": frozenset({"'none'"}),
    "frame-ancestors": frozenset({"'none'"}),
    "form-action": frozenset({"'self'"}),
}

# Directives that may additionally list individually declared network origins.
_CSP_ORIGIN_DIRECTIVES = frozenset({"connect-src", "img-src", "font-src", "media-src", "style-src"})

_ORIGIN_RE = re.compile(r"^https://(?P<host>[A-Za-z0-9.-]+)(?::(?P<port>[0-9]{1,5}))?$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class WappError(ContainerError):
    """Base class for WAPP errors."""


class WappFormatError(WappError, FormatError):
    """The container framing, archive, or metadata is invalid or unsupported."""


class WappValidationError(WappError, ValidationError):
    """The package does not satisfy the WAPP v0.1 data model."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__(self.errors)


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of some bytes."""
    return hashlib.sha256(data).hexdigest()


def _normalize_member_path(name: str) -> str | None:
    """Return a safe relative archive path, or ``None`` when the path is unsafe.

    Unsafe means absolute, drive-prefixed, UNC-rooted, containing a NUL byte,
    containing a backslash, or containing a ``..`` component.
    """
    if not isinstance(name, str) or not name or "\x00" in name:
        return None
    if "\\" in name or name.startswith("/"):
        return None
    if len(name) > 1 and name[1] == ":":
        return None
    parts = PurePosixPath(name).parts
    if not parts or any(part == ".." for part in parts):
        return None
    normalized = "/".join(parts)
    if not normalized or normalized.startswith("/"):
        return None
    return normalized


def _is_below_app(path: str) -> bool:
    """Return True when a normalized path is a path below ``app/``."""
    return path.startswith(APP_PREFIX) and len(path) > len(APP_PREFIX)


def _read_container(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> tuple[dict[str, Any], bytes, bytes]:
    """Parse the WAPP framing and return ``(manifest, manifest bytes, archive bytes)``."""
    try:
        raw = read_source(source, MAX_CONTAINER_LENGTH, "WAPP package")
    except FormatError as exc:
        raise WappFormatError(str(exc)) from exc
    if not raw.startswith(MAGIC):
        raise WappFormatError("Invalid WAPP magic bytes")
    try:
        manifest_raw, offset = read_length_prefixed(
            raw,
            MAGIC,
            prefix_size=4,
            min_length=MIN_MANIFEST_LENGTH,
            max_length=MAX_MANIFEST_LENGTH,
            label="manifest",
        )
        manifest = parse_canonical_body(manifest_raw, "manifest")
        if len(raw) < offset + 8:
            raise FormatError("Truncated WAPP archive length")
        archive_length = struct.unpack(">Q", raw[offset : offset + 8])[0]
        if not (1 <= archive_length <= MAX_ARCHIVE_LENGTH):
            raise FormatError("Archive length is outside the v0.1 bounds")
        archive_start = offset + 8
        archive_end = archive_start + archive_length
        if archive_end > len(raw):
            raise FormatError("Truncated WAPP archive")
        if archive_end != len(raw):
            raise FormatError("WAPP package has trailing data after the archive")
        archive_bytes = raw[archive_start:archive_end]
    except FormatError as exc:
        raise WappFormatError(str(exc)) from exc
    if manifest.get("format") != "wapp" or manifest.get("format_version") != FORMAT_VERSION:
        raise WappFormatError(f"Unsupported WAPP format or version; expected wapp {FORMAT_VERSION}")
    return manifest, manifest_raw, archive_bytes


def _open_archive(archive_bytes: bytes) -> zipfile.ZipFile:
    """Open the embedded ZIP archive of a WAPP package."""
    try:
        return zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise WappFormatError(f"WAPP archive is not a valid ZIP archive: {exc}") from exc


def _build_archive(files: Mapping[str, bytes]) -> bytes:
    """Build the deterministic ZIP archive of a WAPP package.

    Entries are written in sorted path order with a fixed timestamp, using
    ``ZIP_DEFLATED`` and no encryption, so that identical inputs always
    produce identical archive bytes.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(filename=name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    return buffer.getvalue()


def _media_type(path: str) -> str:
    """Return the media type for an archive path."""
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def _file_entry(path: str, data: bytes) -> dict[str, Any]:
    """Return the manifest file entry for one archive member."""
    return {
        "path": path,
        "byte_length": len(data),
        "sha256": _sha256_hex(data),
        "media_type": _media_type(path),
    }


def _entrypoint_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return the entrypoint policy errors for a manifest."""
    entrypoint = manifest.get("entrypoint")
    if not isinstance(entrypoint, str) or not entrypoint:
        return ["manifest entrypoint must be a non-empty string"]
    normalized = _normalize_member_path(entrypoint)
    if normalized is None:
        return [f"manifest entrypoint {entrypoint!r} is not a safe relative path"]
    if normalized != entrypoint:
        return [f"manifest entrypoint {entrypoint!r} must be a normalized relative path"]
    if not _is_below_app(entrypoint):
        return [f"manifest entrypoint {entrypoint!r} must be a path below 'app/'"]
    return []


def _declared_permissions(manifest: Mapping[str, Any]) -> list[str]:
    """Return the declared permissions of a manifest."""
    permissions = manifest.get("permissions")
    if not isinstance(permissions, list):
        return []
    return [item for item in permissions if isinstance(item, str)]


def _permission_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return the permission model errors for a manifest."""
    errors: list[str] = []
    permissions = manifest.get("permissions")
    if not isinstance(permissions, list):
        return ["manifest permissions must be an array"]
    seen: set[str] = set()
    for item in permissions:
        if not isinstance(item, str) or item not in ALLOWED_PERMISSIONS:
            errors.append(
                f"permissions declares {item!r}, which is not part of the WAPP v0.1 permission vocabulary"
            )
        elif item in seen:
            errors.append(f"permissions declares {item!r} more than once")
        else:
            seen.add(item)
    return errors


def _origin_errors(origin: Any) -> list[str]:
    """Return the errors for a single network allowlist origin."""
    if not isinstance(origin, str) or not origin:
        return ["network allowed_origins must contain non-empty strings"]
    errors: list[str] = []
    if "*" in origin:
        errors.append(f"network allowed origin {origin!r} uses a wildcard host; exact origins are required")
        return errors
    if not origin.startswith("https://"):
        errors.append(f"network allowed origin {origin!r} must use the https scheme")
        return errors
    match = _ORIGIN_RE.match(origin)
    if match is None:
        errors.append(
            f"network allowed origin {origin!r} must be an exact origin of the form https://host[:port] "
            "without a path, query, or fragment"
        )
        return errors
    host = match.group("host")
    labels = host.split(".")
    if len(labels) < 2:
        errors.append(f"network allowed origin {origin!r} uses a bare host; a fully qualified host is required")
        return errors
    if any(not _HOST_LABEL_RE.match(label) for label in labels):
        errors.append(f"network allowed origin {origin!r} has an invalid host")
        return errors
    if not labels[-1].isalpha() and not all(label.isdigit() for label in labels):
        errors.append(f"network allowed origin {origin!r} must have an alphabetic top-level domain")
        return errors
    port = match.group("port")
    if port is not None and not (1 <= int(port) <= 65535):
        errors.append(f"network allowed origin {origin!r} has an out-of-range port")
    return errors


def _network_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return the network policy errors for a manifest."""
    errors: list[str] = []
    network = manifest.get("network")
    if not isinstance(network, Mapping):
        return ["manifest network must be an object"]
    mode = network.get("mode")
    if mode not in ("deny", "allowlist"):
        errors.append("network mode must be 'deny' or 'allowlist'; the default policy is 'deny'")
    origins = network.get("allowed_origins")
    if not isinstance(origins, list):
        errors.append("network allowed_origins must be an array")
        return errors
    seen: set[str] = set()
    for origin in origins:
        errors.extend(_origin_errors(origin))
        if isinstance(origin, str):
            if origin in seen:
                errors.append(f"network allowed origins lists {origin!r} more than once")
            seen.add(origin)
    if mode == "deny" and origins:
        errors.append("network mode is 'deny' but allowed_origins is not empty")
    if mode == "allowlist" and not origins:
        errors.append("network mode is 'allowlist' but allowed_origins is empty")
    return errors


def _csp_directives(csp: str) -> dict[str, list[str]]:
    """Return the lower-cased directives and source tokens of a CSP."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives.setdefault(name, []).extend(token.lower() for token in tokens[1:])
    return directives


def _csp_token_reason(token: str) -> str:
    """Describe why a CSP source token is not allowed in the default profile."""
    if token in ("'unsafe-eval'", "'unsafe-inline'"):
        return f"{token} is forbidden; eval and inline scripts are disabled in the default profile"
    if token == "*":
        return "a wildcard source is not a restrictive policy"
    if token.startswith(("http://", "https://", "//")):
        return "remote sources are only allowed when the origin is individually declared in network allowed_origins"
    if token.startswith(("nonce-", "sha256-", "sha384-", "sha512-")):
        return "inline script sources are forbidden; inline scripts are disabled in the default profile"
    if token in ("data:", "blob:", "filesystem:"):
        return f"the {token} scheme is not allowed in the default profile"
    return "only same-package sources and individually declared network origins may be allowed"


def _csp_errors(csp: str, allowed_origins: list[str]) -> list[str]:
    """Return the Content Security Policy errors for a manifest."""
    errors: list[str] = []
    directives = _csp_directives(csp)
    if "default-src" not in directives:
        errors.append("security csp must declare default-src 'none'")
    else:
        for token in directives["default-src"]:
            if token != "'none'":
                errors.append("security csp must set default-src to 'none'")
    declared = set(allowed_origins)
    for name, tokens in directives.items():
        if name == "default-src":
            continue
        allowed = set(_CSP_TOKEN_SETS.get(name, frozenset({"'self'", "'none'"})))
        if name in _CSP_ORIGIN_DIRECTIVES:
            allowed |= declared
        for token in tokens:
            if token in ("'unsafe-eval'", "'unsafe-inline'"):
                errors.append(f"security csp {name} must not allow {token}")
            elif token == "*":
                errors.append(f"security csp {name} must not allow the wildcard source '*'")
            elif token not in allowed:
                errors.append(f"security csp {name} source {token!r} is not allowed: {_csp_token_reason(token)}")
    return errors


def _security_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return the security policy errors for a manifest."""
    errors: list[str] = []
    security = manifest.get("security")
    if not isinstance(security, Mapping):
        return ["manifest security must be an object"]
    origins = manifest.get("network")
    allowed_origins: list[str] = []
    if isinstance(origins, Mapping) and isinstance(origins.get("allowed_origins"), list):
        allowed_origins = [item for item in origins["allowed_origins"] if isinstance(item, str)]
    csp = security.get("csp")
    if not isinstance(csp, str) or not csp.strip():
        errors.append("security csp must be a non-empty Content Security Policy")
    else:
        errors.extend(_csp_errors(csp, allowed_origins))
    if security.get("allow_inline_scripts") is not False:
        errors.append("security allow_inline_scripts must be false; inline scripts are disabled in the default profile")
    if security.get("allow_eval") is not False:
        errors.append("security allow_eval must be false; eval is disabled in the default profile")
    if security.get("allow_popups") is not False:
        errors.append(
            "security allow_popups must be false; popups cannot be declared in the WAPP v0.1 permission model"
        )
    if security.get("external_navigation") != "deny":
        errors.append(
            "security external_navigation must be 'deny'; external navigation and external protocol "
            "handlers cannot be declared in the WAPP v0.1 permission model"
        )
    return errors


def _storage_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return the storage policy errors for a manifest."""
    errors: list[str] = []
    permissions = _declared_permissions(manifest)
    storage = manifest.get("storage")
    if storage is None:
        if _STORAGE_PERMISSION in permissions:
            errors.append(
                f"permissions declares {_STORAGE_PERMISSION!r} but the manifest has no storage block"
            )
        return errors
    if not isinstance(storage, Mapping):
        return ["manifest storage must be an object"]
    if storage.get("seed_path") != SEED_PATH:
        errors.append(f"storage seed_path must be {SEED_PATH!r}")
    if _STORAGE_PERMISSION not in permissions:
        errors.append(
            f"manifest declares a storage block but permissions does not declare {_STORAGE_PERMISSION!r}"
        )
    return errors


def _file_entry_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return the errors of the manifest file list."""
    errors: list[str] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        return ["manifest files must be an array"]
    if not files:
        return ["manifest files must list at least one file"]
    seen: set[str] = set()
    for index, entry in enumerate(files):
        prefix = f"files[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{prefix} must be an object")
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            errors.append(f"{prefix} path must be a non-empty string")
        else:
            normalized = _normalize_member_path(path)
            if normalized is None or normalized != path:
                errors.append(f"{prefix} path {path!r} is not a safe normalized relative path")
            elif path in seen:
                errors.append(f"{prefix} path {path!r} is listed more than once")
            else:
                seen.add(path)
        byte_length = entry.get("byte_length")
        if isinstance(byte_length, bool) or not isinstance(byte_length, int) or byte_length < 0:
            errors.append(f"{prefix} byte_length must be a non-negative integer")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not _SHA256_RE.match(digest):
            errors.append(f"{prefix} sha256 must be a lowercase hex SHA-256 digest")
        if not isinstance(entry.get("media_type"), str) or not entry.get("media_type"):
            errors.append(f"{prefix} media_type must be a non-empty string")
    return errors


def _manifest_errors(manifest: Mapping[str, Any]) -> list[str]:
    """Return every manifest-level error, including the JSON Schema errors."""
    if not isinstance(manifest, Mapping):
        return ["manifest must be a JSON object"]
    errors: list[str] = []
    errors.extend(schema_errors("wapp", manifest))
    if manifest.get("format") != "wapp":
        errors.append("manifest format must be 'wapp'")
    if manifest.get("format_version") != FORMAT_VERSION:
        errors.append(f"manifest format_version must be {FORMAT_VERSION}")
    errors.extend(_entrypoint_errors(manifest))
    errors.extend(_permission_errors(manifest))
    errors.extend(_network_errors(manifest))
    errors.extend(_security_errors(manifest))
    errors.extend(_storage_errors(manifest))
    errors.extend(_file_entry_errors(manifest))
    return errors


def _file_consistency_errors(manifest: Mapping[str, Any], files: Mapping[str, bytes]) -> list[str]:
    """Return the errors between the manifest file list and the archive content."""
    errors: list[str] = []
    listed = manifest.get("files")
    if not isinstance(listed, list):
        return errors
    for index, entry in enumerate(listed):
        if not isinstance(entry, Mapping):
            continue
        path = entry.get("path")
        if not isinstance(path, str) or path not in files:
            errors.append(f"files[{index}] path {path!r} is not present in the package content")
            continue
        data = files[path]
        byte_length = entry.get("byte_length")
        if isinstance(byte_length, int) and not isinstance(byte_length, bool) and byte_length != len(data):
            errors.append(f"files[{index}] path {path!r} declares byte_length {byte_length} but the content is {len(data)} bytes")
        digest = entry.get("sha256")
        if isinstance(digest, str) and digest != _sha256_hex(data):
            errors.append(f"files[{index}] path {path!r} declares a sha256 that does not match the content")
    listed_paths = {
        entry.get("path") for entry in listed if isinstance(entry, Mapping) and isinstance(entry.get("path"), str)
    }
    for path in sorted(files):
        if path not in listed_paths:
            errors.append(f"package content {path!r} is not listed in the manifest files")
    storage = manifest.get("storage")
    if isinstance(storage, Mapping) and SEED_PATH not in files:
        errors.append(f"manifest declares a storage block but the package does not contain {SEED_PATH!r}")
    return errors


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, max_bytes: int) -> bytes:
    """Read one archive member with a size bound."""
    with archive.open(info) as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise WappFormatError(f"archive member {info.filename!r} exceeds its size limit")
    return data


def _member_digest(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[int, str]:
    """Return the byte length and SHA-256 digest of one archive member."""
    digest = hashlib.sha256()
    total = 0
    with archive.open(info) as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    return total, digest.hexdigest()


def _seed_errors(data: bytes) -> list[str]:
    """Return the SQLite integrity errors of a seed database."""
    with tempfile.TemporaryDirectory(prefix="wapp-seed-") as workspace:
        path = Path(workspace) / "seed.sqlite"
        path.write_bytes(data)
        uri = f"{path.resolve().as_uri()}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True)
        except sqlite3.Error as exc:
            return [f"{SEED_PATH} could not be opened as a read-only SQLite database: {exc}"]
        try:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.DatabaseError as exc:
            return [f"{SEED_PATH} failed the SQLite integrity check: {exc}"]
        finally:
            connection.close()
    if [row[0] for row in rows] != ["ok"]:
        return [f"{SEED_PATH} failed the SQLite integrity check: {rows!r}"]
    return []


def _capability_errors(declared: list[str], contents: dict[str, bytes]) -> list[str]:
    """Return the forbidden or unrequested capability errors of package content."""
    errors: list[str] = []
    declared_set = set(declared)
    requested: dict[str, list[str]] = {}
    for path, data in sorted(contents.items()):
        text = data.decode("utf-8", errors="ignore").lower()
        for marker, capability in _CAPABILITY_MARKERS:
            if marker in text:
                requested.setdefault(capability, [])
                if path not in requested[capability]:
                    requested[capability].append(path)
    for capability, paths in sorted(requested.items()):
        required = _CAPABILITY_REQUIREMENTS.get(capability)
        location = ", ".join(repr(path) for path in paths[:3])
        if required is None:
            errors.append(
                f"package requests the {capability} capability at {location}, which the WAPP v0.1 "
                "permission model cannot declare"
            )
        elif not (set(required) & declared_set):
            errors.append(
                f"package requests the {capability} capability at {location} without declaring the "
                f"permission(s): {', '.join(required)}"
            )
    return errors


def _archive_errors(archive: zipfile.ZipFile, manifest: Mapping[str, Any]) -> list[str]:
    """Return the archive-level errors of a package."""
    errors: list[str] = list(zip_safety_errors(archive, ZIP_LIMITS))
    members: dict[str, zipfile.ZipInfo] = {}
    for info in archive.infolist():
        if info.is_dir():
            continue
        normalized = _normalize_member_path(info.filename)
        if normalized is None:
            errors.append(f"archive member {info.filename!r} does not use a safe relative path")
            continue
        if not (normalized.startswith(APP_PREFIX) or normalized.startswith(STORAGE_PREFIX)):
            errors.append(
                f"archive member {normalized!r} is outside the required 'app/' and 'storage/' layout"
            )
        members[normalized] = info

    listed = manifest.get("files")
    listed_paths: set[str] = set()
    if isinstance(listed, list):
        for index, entry in enumerate(listed):
            if not isinstance(entry, Mapping):
                continue
            path = entry.get("path")
            if not isinstance(path, str):
                continue
            listed_paths.add(path)
            info = members.get(path)
            if info is None:
                errors.append(f"files[{index}] path {path!r} is missing from the archive")
                continue
            byte_length, digest = _member_digest(archive, info)
            declared_length = entry.get("byte_length")
            if isinstance(declared_length, int) and not isinstance(declared_length, bool):
                if declared_length != byte_length:
                    errors.append(
                        f"files[{index}] path {path!r} declares byte_length {declared_length} but the archive member is {byte_length} bytes"
                    )
            declared_digest = entry.get("sha256")
            if isinstance(declared_digest, str) and declared_digest != digest:
                errors.append(f"files[{index}] path {path!r} declares a sha256 that does not match the archive member")
    for path in sorted(members):
        if path not in listed_paths:
            errors.append(f"archive member {path!r} is not listed in the manifest files")

    entrypoint = manifest.get("entrypoint")
    if isinstance(entrypoint, str):
        if not _is_below_app(entrypoint):
            errors.append(f"manifest entrypoint {entrypoint!r} must be a path below 'app/'")
        elif entrypoint not in members:
            errors.append(f"manifest entrypoint {entrypoint!r} is missing from the archive")
    if DEFAULT_ENTRYPOINT not in members:
        errors.append(f"archive does not contain the required {DEFAULT_ENTRYPOINT!r} entry")

    storage = manifest.get("storage")
    seed_info = members.get(SEED_PATH)
    if seed_info is not None:
        errors.extend(_seed_errors(_read_member(archive, seed_info, ZIP_LIMITS.max_entry_bytes)))
    elif isinstance(storage, Mapping):
        errors.append(f"manifest declares a storage block but the archive does not contain {SEED_PATH!r}")

    contents: dict[str, bytes] = {}
    for path, info in members.items():
        if not path.startswith(APP_PREFIX):
            continue
        if Path(path).suffix.lower() not in _SCAN_EXTENSIONS:
            continue
        if info.file_size > _SCAN_MAX_FILE_BYTES:
            continue
        contents[path] = _read_member(archive, info, _SCAN_MAX_FILE_BYTES)
    errors.extend(_capability_errors(_declared_permissions(manifest), contents))
    return errors


def create_wapp(manifest: Mapping[str, Any], files: Mapping[str, bytes]) -> bytes:
    """Create a WAPP v0.1 package and return its bytes.

    The manifest must be a complete v0.1 manifest whose ``files`` list exactly
    describes ``files``: every manifest entry needs a matching archive member
    with the declared byte length and SHA-256 digest, and every archive member
    must be listed. Validation errors are raised as
    :class:`WappValidationError`.

    The embedded ZIP archive is written deterministically: entries are sorted
    by path, every entry carries a fixed timestamp, entries are deflated, and
    no entry is encrypted.
    """
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    if not isinstance(files, Mapping):
        raise TypeError("files must be a mapping")
    manifest_obj = dict(manifest)
    file_map: dict[str, bytes] = {}
    for name, data in files.items():
        if not isinstance(name, str):
            raise TypeError("file paths must be strings")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("file content must be bytes")
        file_map[name] = bytes(data)

    errors = _manifest_errors(manifest_obj)
    errors.extend(_file_consistency_errors(manifest_obj, file_map))
    if errors:
        raise WappValidationError(errors)

    manifest_raw = canonical_json(manifest_obj)
    if not (MIN_MANIFEST_LENGTH <= len(manifest_raw) <= MAX_MANIFEST_LENGTH):
        raise WappFormatError("Canonical manifest size exceeds the v0.1 limit")
    archive = _build_archive(file_map)
    if not (1 <= len(archive) <= MAX_ARCHIVE_LENGTH):
        raise WappFormatError("Generated archive exceeds the v0.1 limit")
    return MAGIC + struct.pack(">I", len(manifest_raw)) + manifest_raw + struct.pack(">Q", len(archive)) + archive


def pack_wapp(source_dir: str | os.PathLike[str], manifest: Mapping[str, Any]) -> bytes:
    """Pack a project directory into a WAPP v0.1 package and return its bytes.

    ``source_dir`` holds the package layout: an ``app/`` directory with the web
    payload and, when the manifest declares storage, a ``storage/`` directory
    with the ``seed.sqlite`` seed database. Only the ``app/`` and ``storage/``
    trees are packaged, because the archive layout of the specification allows
    nothing else; files elsewhere in ``source_dir`` (a manifest file kept next
    to ``app/``, for example) are skipped and reported on stderr rather than
    silently dropped or treated as an error.

    The ``files`` list of the manifest is rebuilt from the directory, so the
    manifest records the real length and SHA-256 digest of every packaged file.
    """
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    root = Path(source_dir)
    if not root.is_dir():
        raise WappFormatError(f"Source directory not found: {root}")
    files: dict[str, bytes] = {}
    skipped: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative.split("/", 1)[0] not in _PACKAGE_ROOTS:
            skipped.append(relative)
            continue
        if path.is_symlink():
            raise WappFormatError(f"Refusing to package the symlink {path}")
        if path.is_dir():
            continue
        normalized = _normalize_member_path(relative)
        if normalized is None:
            raise WappFormatError(f"Refusing to package the unsafe path {relative!r}")
        files[normalized] = path.read_bytes()
    if skipped:
        print(
            f"Skipping {len(skipped)} file(s) outside the app/ and storage/ layout: "
            f"{', '.join(sorted(skipped)[:5])}",
            file=sys.stderr,
        )
    manifest_obj = dict(manifest)
    manifest_obj["files"] = [_file_entry(path, files[path]) for path in sorted(files)]
    entrypoint = manifest_obj.get("entrypoint")
    if not isinstance(entrypoint, str) or entrypoint not in files:
        raise WappValidationError([f"manifest entrypoint {entrypoint!r} is not present in the source directory"])
    return create_wapp(manifest_obj, files)


def read_wapp_manifest(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> dict[str, Any]:
    """Read the manifest of a WAPP package.

    The framing is checked in full; the returned manifest is the parsed
    canonical JSON document and is not re-validated. Use
    :func:`validate_wapp` for the full policy check.
    """
    manifest, _manifest_raw, _archive_bytes = _read_container(source)
    return manifest


def validate_wapp(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> list[str]:
    """Return the validation errors of a WAPP package; an empty list means valid.

    The checks cover the framing, the canonical manifest encoding, the
    manifest schema, the manifest permission policy, the archive safety
    profile, the file hashes and lengths, the entrypoint, the network
    allowlist, the Content Security Policy, the SQLite seed integrity, and the
    capability markers found in the package content.

    Validation is not a security audit of arbitrary JavaScript. The checks
    below cannot establish that a package's code is safe, and only the WAPP
    runtime can enforce the declared permission policy.
    """
    try:
        manifest, _manifest_raw, archive_bytes = _read_container(source)
    except ContainerError as exc:
        return [str(exc)]
    errors = _manifest_errors(manifest)
    try:
        archive = _open_archive(archive_bytes)
    except ContainerError as exc:
        return errors + [str(exc)]
    try:
        errors.extend(_archive_errors(archive, manifest))
    except ContainerError as exc:
        errors.append(str(exc))
    return errors


def inspect_wapp(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> dict[str, Any]:
    """Return a summary of a WAPP package for display purposes."""
    manifest, manifest_raw, archive_bytes = _read_container(source)
    files = manifest.get("files")
    entries: list[dict[str, Any]] = []
    if isinstance(files, list):
        for entry in files:
            if isinstance(entry, Mapping):
                entries.append(
                    {
                        "path": entry.get("path"),
                        "byte_length": entry.get("byte_length"),
                        "sha256": entry.get("sha256"),
                        "media_type": entry.get("media_type"),
                    }
                )
    return {
        "format": manifest.get("format"),
        "format_version": manifest.get("format_version"),
        "app_id": manifest.get("app_id"),
        "name": manifest.get("name"),
        "app_version": manifest.get("app_version"),
        "runtime_min": manifest.get("runtime_min"),
        "entrypoint": manifest.get("entrypoint"),
        "permissions": _declared_permissions(manifest),
        "network": manifest.get("network"),
        "security": manifest.get("security"),
        "storage": manifest.get("storage"),
        "manifest_length": len(manifest_raw),
        "archive_length": len(archive_bytes),
        "file_count": len(entries),
        "files": entries,
    }


def list_wapp(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Return a summary of every file in the archive of a WAPP package."""
    manifest, _manifest_raw, archive_bytes = _read_container(source)
    archive = _open_archive(archive_bytes)
    declared: dict[str, str] = {}
    files = manifest.get("files")
    if isinstance(files, list):
        for entry in files:
            if isinstance(entry, Mapping) and isinstance(entry.get("path"), str):
                media_type = entry.get("media_type")
                declared[entry["path"]] = media_type if isinstance(media_type, str) else ""
    summaries: list[dict[str, Any]] = []
    for info in sorted(archive.infolist(), key=lambda item: item.filename):
        if info.is_dir():
            continue
        byte_length, digest = _member_digest(archive, info)
        summaries.append(
            {
                "path": info.filename,
                "byte_length": byte_length,
                "sha256": digest,
                "media_type": declared.get(info.filename) or _media_type(info.filename),
            }
        )
    return summaries


def extract_wapp(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> list[str]:
    """Extract the archive of a WAPP package into a directory.

    Extraction refuses to overwrite an existing file and refuses members that
    escape the destination directory. The returned list holds the extracted
    member paths.
    """
    _manifest, _manifest_raw, archive_bytes = _read_container(source)
    archive = _open_archive(archive_bytes)
    try:
        return extract_zip_safely(archive, destination)
    except FormatError as exc:
        raise WappFormatError(str(exc)) from exc


def write_wapp(output: str | os.PathLike[str], manifest: Mapping[str, Any], files: Mapping[str, bytes]) -> None:
    """Write a WAPP package to disk using an atomic replacement."""
    atomic_write_bytes(output, create_wapp(manifest, files))


def _dev_handler(app_root: Path, csp: str) -> type[BaseHTTPRequestHandler]:
    """Return the request handler of the development inspection server."""

    class _Handler(BaseHTTPRequestHandler):
        """Serve the extracted ``app/`` directory of a WAPP package."""

        server_version = "open-extensions-wapp-dev/0.1.0"
        root = app_root
        policy = csp

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            """Serve a GET request."""
            self._respond(with_body=True)

        def do_HEAD(self) -> None:  # noqa: N802 - http.server API
            """Serve a HEAD request."""
            self._respond(with_body=False)

        def _respond(self, with_body: bool) -> None:
            status, target = self._resolve_target()
            if target is None:
                self.send_error(status, "Not Found" if status == 404 else "Refused")
                return
            try:
                data = target.read_bytes()
            except OSError:
                self.send_error(404, "Not Found")
                return
            self.send_response(200)
            self.send_header("Content-Type", _media_type(target.name))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", self.policy)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if with_body:
                self.wfile.write(data)

        def _resolve_target(self) -> tuple[int, Path | None]:
            try:
                decoded = unquote(urlsplit(self.path).path, errors="strict")
            except (UnicodeDecodeError, ValueError):
                return 400, None
            if "\x00" in decoded:
                return 400, None
            relative = decoded.lstrip("/")
            if not relative:
                relative = "index.html"
            elif relative.endswith("/"):
                relative = f"{relative}index.html"
            root = self.root.resolve()
            try:
                candidate = (root / relative).resolve()
            except OSError:
                return 403, None
            if not candidate.is_relative_to(root):
                return 403, None
            if not candidate.is_file():
                return 404, None
            return 200, candidate

    return _Handler


def serve_wapp(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    stop_event: threading.Event | None = None,
) -> None:
    """Serve a WAPP package over HTTP for local development inspection.

    This is a **development inspection server only**. It is not a
    security-enforcing runtime: it does not enforce the declared permission
    policy, it does not provide the isolated WebView or the narrow SQLite
    host bridge described by the specification, and the JavaScript it serves is
    untrusted. Only the separately installed WAPP runtime can enforce the
    permission policy and the process isolation.

    The package is extracted into a temporary directory and served from
    ``app/`` only, with the declared Content Security Policy and
    ``X-Content-Type-Options: nosniff`` set on every response. Paths that
    resolve outside the extracted ``app/`` directory are refused. The URL is
    printed to stdout, and the server runs until it is interrupted or until
    ``stop_event`` is set.
    """
    errors = validate_wapp(source)
    if errors:
        raise WappValidationError(errors)
    manifest, _manifest_raw, archive_bytes = _read_container(source)
    security = manifest.get("security")
    csp = security.get("csp") if isinstance(security, Mapping) else None
    if not isinstance(csp, str) or not csp:
        raise WappFormatError("Package does not declare a Content Security Policy")

    workspace = Path(tempfile.mkdtemp(prefix="wapp-serve-"))
    try:
        archive = _open_archive(archive_bytes)
        try:
            extract_zip_safely(archive, workspace)
        except FormatError as exc:
            raise WappFormatError(str(exc)) from exc
        app_root = workspace / "app"
        if not app_root.is_dir():
            raise WappFormatError("Package does not contain an 'app/' directory")
        server = ThreadingHTTPServer((host, port), _dev_handler(app_root, csp))
        server.timeout = 0.25
        try:
            bound_host, bound_port = server.server_address[:2]
            print(
                f"Serving WAPP package on http://{bound_host}:{bound_port}/ "
                "(development inspection server; not a security-enforcing runtime)",
                flush=True,
            )
            stop = stop_event or threading.Event()
            try:
                while not stop.is_set():
                    server.handle_request()
            except KeyboardInterrupt:
                pass
        finally:
            server.server_close()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
