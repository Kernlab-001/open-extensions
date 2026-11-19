"""PODX v0.1 reference implementation.

A ``.podx`` container frames a canonical JSON manifest and a deterministic ZIP
archive of audio assets::

    magic (8 bytes) | manifest length (uint32) | manifest JSON
                   | archive length (uint64)   | ZIP archive

The v0.1 profile fixes a 48 kHz tick timebase and integer timestamps only.
Readers MUST support Opus in Ogg (``opus-ogg``) and FLAC (``flac``). Any other
codec needs an explicit required capability that v0.1 does not define, so it is
rejected instead of being silently decoded as something else.

Assets are opaque bytes in v0.1. The container verifies declared lengths,
ZIP CRCs, and the manifest SHA-256 digests, but it never parses, transcodes,
or normalises a media payload.

There is no renderer, mixer, or player in this module. The spec keeps
``render`` out of v0.1 until the codec dependency and licensing policy is
fixed, so playback, mixing, transcript highlighting, and chapter clicks stay
application behaviour.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

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

MAGIC = b"PODX\r\n\x1a\n"  # 8 bytes
FORMAT_VERSION = "0.1.0"
TIMEBASE_HZ = 48000
SCHEMA_URI = "urn:open-extensions:spec:podx:0.1.0"

# Codecs a v0.1 reader MUST support. Everything else requires an explicit
# required capability that v0.1 does not define and is therefore rejected.
SUPPORTED_CODECS = frozenset({"opus-ogg", "flac"})

# Track roles defined by the v0.1 manifest model.
TRACK_KINDS = frozenset({"voice", "music", "sfx", "ambience", "other"})

# Every media asset lives under this relative directory inside the archive.
ASSET_ROOT = "tracks/"

# Name used when the manifest is written next to the extracted assets.
MANIFEST_FILENAME = "manifest.json"

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ASSET_BYTES = 256 * 1024 * 1024
MAX_CONTAINER_BYTES = len(MAGIC) + 4 + MAX_MANIFEST_BYTES + 8 + MAX_ARCHIVE_BYTES

# Deterministic ZIP profile: one fixed entry timestamp, sorted entry order,
# deflate compression, and no encryption.
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_LIMITS = ZipLimits(
    max_entries=1024,
    max_total_bytes=MAX_ARCHIVE_BYTES,
    max_entry_bytes=MAX_ASSET_BYTES,
    max_ratio=200,
)

# The JSON Schema pattern for a track path.
_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

_ROOT_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "title",
        "timebase_hz",
        "duration_ticks",
        "tracks",
        "transcript",
        "chapters",
        "speakers",
        "extensions",
    }
)


class PodxError(ContainerError):
    """Base class for PODX errors."""


class PodxFormatError(PodxError, FormatError):
    """The container framing, archive, or asset layout is invalid."""


class PodxValidationError(PodxError, ValidationError):
    """The manifest does not satisfy the PODX v0.1 data model."""

    def __init__(self, errors: list[str]):
        ValidationError.__init__(self, errors)


def _is_int(value: Any) -> bool:
    """Return True for a JSON integer; booleans are not integers."""
    return isinstance(value, int) and not isinstance(value, bool)


def _ticks_to_seconds(value: Any) -> float | None:
    """Convert an integer tick count to seconds, or return None."""
    if not _is_int(value):
        return None
    return round(value / TIMEBASE_HZ, 6)


def _path_errors(path: str, *, require_asset_root: bool) -> list[str]:
    """Return the archive-path violations of one member path."""
    errors: list[str] = []
    if require_asset_root and not path.startswith(ASSET_ROOT):
        errors.append(f"path must start with {ASSET_ROOT!r}")
    if not path:
        errors.append("path must not be empty")
        return errors
    if "\\" in path:
        errors.append("path must use forward slashes")
    if "\x00" in path:
        errors.append("path must not contain a NUL byte")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        errors.append("path must be relative")
    if any(part in ("", ".", "..") for part in path.split("/")):
        errors.append("path must be normalized and must not contain '.' or '..' components")
    if not _PATH_RE.fullmatch(path):
        errors.append("path may only contain letters, digits, '.', '_', '-', and '/'")
    return errors


def _validate_track(track: Any, index: int, duration: int | None) -> tuple[list[str], str | None]:
    """Return the errors and the declared id of one track."""
    prefix = f"tracks[{index}]"
    errors: list[str] = []
    if not isinstance(track, dict):
        return [f"{prefix} must be an object"], None

    track_id = track.get("id")
    if not isinstance(track_id, str) or not track_id:
        errors.append(f"{prefix}.id must be a non-empty string")
        track_id = None

    if track.get("kind") not in TRACK_KINDS:
        errors.append(f"{prefix}.kind must be one of: {', '.join(sorted(TRACK_KINDS))}")

    path = track.get("path")
    if not isinstance(path, str) or not path:
        errors.append(f"{prefix}.path must be a non-empty string")
    else:
        errors.extend(f"{prefix}.{message}" for message in _path_errors(path, require_asset_root=True))

    media_type = track.get("media_type")
    if not isinstance(media_type, str) or not media_type:
        errors.append(f"{prefix}.media_type must be a non-empty string")

    codec = track.get("codec")
    if codec not in SUPPORTED_CODECS:
        errors.append(
            f"{prefix}.codec {codec!r} is not supported by the v0.1 profile; "
            f"supported codecs: {', '.join(sorted(SUPPORTED_CODECS))}"
        )

    sample_rate = track.get("sample_rate_hz")
    if not _is_int(sample_rate) or not (8000 <= sample_rate <= 384000):
        errors.append(f"{prefix}.sample_rate_hz must be an integer between 8000 and 384000")

    channels = track.get("channels")
    if not _is_int(channels) or not (1 <= channels <= 8):
        errors.append(f"{prefix}.channels must be an integer between 1 and 8")

    start_tick = track.get("start_tick")
    if not _is_int(start_tick) or start_tick < 0:
        errors.append(f"{prefix}.start_tick must be a non-negative integer")
        start_tick = None

    track_duration = track.get("duration_ticks")
    if not _is_int(track_duration) or track_duration < 1:
        errors.append(f"{prefix}.duration_ticks must be a positive integer")
        track_duration = None

    if start_tick is not None and track_duration is not None and duration is not None:
        if start_tick + track_duration > duration:
            errors.append(f"{prefix} ends after the manifest duration_ticks")

    digest = track.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        errors.append(f"{prefix}.sha256 must be 64 lowercase hexadecimal characters")

    byte_length = track.get("byte_length")
    if not _is_int(byte_length) or byte_length < 1:
        errors.append(f"{prefix}.byte_length must be a positive integer")

    if "gain_db" in track:
        gain = track["gain_db"]
        if isinstance(gain, bool) or not isinstance(gain, (int, float)) or not (-60 <= gain <= 24):
            errors.append(f"{prefix}.gain_db must be a number between -60 and 24")
    if "language" in track and not isinstance(track["language"], str):
        errors.append(f"{prefix}.language must be a string")

    return errors, track_id


def _validate_speakers(speakers: Any) -> tuple[list[str], set[str]]:
    """Return the errors and the declared speaker ids."""
    errors: list[str] = []
    speaker_ids: set[str] = set()
    if speakers is None:
        return errors, speaker_ids
    if not isinstance(speakers, list):
        return ["speakers must be an array"], speaker_ids
    for index, speaker in enumerate(speakers):
        prefix = f"speakers[{index}]"
        if not isinstance(speaker, dict):
            errors.append(f"{prefix} must be an object")
            continue
        speaker_id = speaker.get("id")
        if not isinstance(speaker_id, str) or not speaker_id:
            errors.append(f"{prefix}.id must be a non-empty string")
        elif speaker_id in speaker_ids:
            errors.append(f"{prefix}.id must be unique: {speaker_id!r}")
        else:
            speaker_ids.add(speaker_id)
        if "label" in speaker and not isinstance(speaker["label"], str):
            errors.append(f"{prefix}.label must be a string")
        if "locale" in speaker and not isinstance(speaker["locale"], str):
            errors.append(f"{prefix}.locale must be a string")
    return errors, speaker_ids


def _validate_words(
    words: Any,
    duration: int | None,
    track_ids: set[str],
    speaker_ids: set[str],
) -> list[str]:
    """Return the errors of the transcript word list."""
    errors: list[str] = []
    if not isinstance(words, list):
        return ["transcript.words must be an array"]
    previous_start = 0
    previous_end = 0
    for index, word in enumerate(words):
        prefix = f"transcript.words[{index}]"
        if not isinstance(word, dict):
            errors.append(f"{prefix} must be an object")
            continue

        start_tick = word.get("start_tick")
        end_tick = word.get("end_tick")
        if not _is_int(start_tick) or start_tick < 0:
            errors.append(f"{prefix}.start_tick must be a non-negative integer")
            start_tick = None
        if not _is_int(end_tick) or end_tick < 1:
            errors.append(f"{prefix}.end_tick must be a positive integer")
            end_tick = None

        if start_tick is not None and end_tick is not None:
            if start_tick >= end_tick:
                errors.append(f"{prefix} must satisfy start_tick < end_tick")
            elif duration is not None and end_tick > duration:
                errors.append(f"{prefix} ends after the manifest duration_ticks")
            elif start_tick < previous_start:
                errors.append(f"{prefix} is not in chronological order")
            elif start_tick < previous_end:
                errors.append(f"{prefix} overlaps the previous word")

        text = word.get("text")
        if not isinstance(text, str) or not text:
            errors.append(f"{prefix}.text must be a non-empty string")

        track_id = word.get("track_id")
        if track_id is not None:
            if not isinstance(track_id, str) or not track_id:
                errors.append(f"{prefix}.track_id must be a non-empty string")
            elif track_id not in track_ids:
                errors.append(f"{prefix}.track_id {track_id!r} does not match any track")

        speaker_id = word.get("speaker_id")
        if speaker_id is not None:
            if not isinstance(speaker_id, str) or not speaker_id:
                errors.append(f"{prefix}.speaker_id must be a non-empty string")
            elif speaker_id not in speaker_ids:
                errors.append(f"{prefix}.speaker_id {speaker_id!r} does not match any speaker")

        confidence = word.get("confidence_ppm")
        if confidence is not None and (not _is_int(confidence) or not (0 <= confidence <= 1_000_000)):
            errors.append(f"{prefix}.confidence_ppm must be an integer between 0 and 1000000")

        if start_tick is not None:
            previous_start = start_tick
        if end_tick is not None:
            previous_end = end_tick
    return errors


def _validate_chapters(chapters: Any, duration: int | None) -> list[str]:
    """Return the errors of the chapter list."""
    errors: list[str] = []
    if not isinstance(chapters, list):
        return ["chapters must be an array"]
    chapter_ids: set[str] = set()
    previous_start = 0
    previous_end = 0
    for index, chapter in enumerate(chapters):
        prefix = f"chapters[{index}]"
        if not isinstance(chapter, dict):
            errors.append(f"{prefix} must be an object")
            continue

        chapter_id = chapter.get("id")
        if not isinstance(chapter_id, str) or not chapter_id:
            errors.append(f"{prefix}.id must be a non-empty string")
        elif chapter_id in chapter_ids:
            errors.append(f"{prefix}.id must be unique: {chapter_id!r}")
        else:
            chapter_ids.add(chapter_id)

        title = chapter.get("title")
        if not isinstance(title, str) or not title:
            errors.append(f"{prefix}.title must be a non-empty string")

        if "description" in chapter and not isinstance(chapter["description"], str):
            errors.append(f"{prefix}.description must be a string")

        start_tick = chapter.get("start_tick")
        end_tick = chapter.get("end_tick")
        if not _is_int(start_tick) or start_tick < 0:
            errors.append(f"{prefix}.start_tick must be a non-negative integer")
            start_tick = None
        if not _is_int(end_tick) or end_tick < 1:
            errors.append(f"{prefix}.end_tick must be a positive integer")
            end_tick = None

        if start_tick is not None and end_tick is not None:
            if start_tick >= end_tick:
                errors.append(f"{prefix} must satisfy start_tick < end_tick")
            elif duration is not None and end_tick > duration:
                errors.append(f"{prefix} ends after the manifest duration_ticks")
            elif start_tick < previous_start:
                errors.append(f"{prefix} is not in chronological order")
            elif start_tick < previous_end:
                errors.append(f"{prefix} overlaps the previous chapter")

        if start_tick is not None:
            previous_start = start_tick
        if end_tick is not None:
            previous_end = end_tick
    return errors


def _validate_manifest(manifest: Any) -> list[str]:
    """Return every schema and semantic violation of a manifest."""
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]

    errors: list[str] = list(schema_errors("podx", manifest))

    missing = _ROOT_FIELDS - manifest.keys() - {"speakers", "extensions"}
    if missing:
        errors.append(f"missing root field(s): {', '.join(sorted(missing))}")
    unknown = manifest.keys() - _ROOT_FIELDS
    if unknown:
        errors.append(f"unknown root field(s): {', '.join(sorted(unknown))}")

    if manifest.get("format") != "podx":
        errors.append("format must equal 'podx'")
    if manifest.get("format_version") != FORMAT_VERSION:
        errors.append(f"format_version must equal {FORMAT_VERSION}")

    title = manifest.get("title")
    if not isinstance(title, str) or not title:
        errors.append("title must be a non-empty string")

    timebase = manifest.get("timebase_hz")
    if not _is_int(timebase):
        errors.append("timebase_hz must be an integer")
    elif timebase != TIMEBASE_HZ:
        errors.append(f"timebase_hz must equal {TIMEBASE_HZ} in v0.1")

    duration = manifest.get("duration_ticks")
    if not _is_int(duration) or duration < 1:
        errors.append("duration_ticks must be a positive integer")
        duration = None

    extensions = manifest.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        errors.append("extensions must be an object")

    tracks = manifest.get("tracks")
    if not isinstance(tracks, list) or not tracks:
        errors.append("tracks must be a non-empty array")
        tracks = []

    track_ids: set[str] = set()
    for index, track in enumerate(tracks):
        track_errors, track_id = _validate_track(track, index, duration)
        errors.extend(track_errors)
        if track_id is not None:
            if track_id in track_ids:
                errors.append(f"tracks[{index}].id must be unique: {track_id!r}")
            else:
                track_ids.add(track_id)

    speaker_errors, speaker_ids = _validate_speakers(manifest.get("speakers"))
    errors.extend(speaker_errors)

    transcript = manifest.get("transcript")
    if not isinstance(transcript, dict):
        errors.append("transcript must be an object")
        transcript = {}
    errors.extend(_validate_words(transcript.get("words"), duration, track_ids, speaker_ids))

    errors.extend(_validate_chapters(manifest.get("chapters"), duration))
    return errors


def _read_container(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> bytes:
    """Read a container from bytes or a path, enforcing the v0.1 size bound."""
    try:
        return read_source(source, MAX_CONTAINER_BYTES, "PODX file")
    except FormatError as exc:
        raise PodxFormatError(str(exc)) from exc


def _parse_container(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> tuple[dict[str, Any], bytes]:
    """Return the manifest and the raw ZIP archive bytes of a container."""
    raw = _read_container(source)
    try:
        manifest_bytes, offset = read_length_prefixed(
            raw,
            MAGIC,
            prefix_size=4,
            min_length=1,
            max_length=MAX_MANIFEST_BYTES,
            label="manifest",
        )
        manifest = parse_canonical_body(manifest_bytes, "manifest")
    except FormatError as exc:
        raise PodxFormatError(str(exc)) from exc

    tail = raw[offset:]
    if len(tail) < 8:
        raise PodxFormatError("Truncated archive length prefix")
    try:
        # The archive length prefix carries no magic of its own.
        archive_bytes, end = read_length_prefixed(
            tail,
            b"",
            prefix_size=8,
            min_length=1,
            max_length=MAX_ARCHIVE_BYTES,
            label="archive",
        )
    except FormatError as exc:
        raise PodxFormatError(str(exc)) from exc
    if offset + end != len(raw):
        raise PodxFormatError("PODX file contains trailing data after the archive")
    return manifest, archive_bytes


def _open_archive(archive_bytes: bytes) -> zipfile.ZipFile:
    """Open the embedded ZIP archive."""
    try:
        return zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise PodxFormatError(f"archive is not a valid ZIP file: {exc}") from exc


def _build_archive(assets: Mapping[str, bytes]) -> bytes:
    """Build a deterministic ZIP archive from the asset bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(assets):
            info = zipfile.ZipInfo(filename=name, date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix
            info.external_attr = 0o100644 << 16  # regular file, rw-r--r--
            archive.writestr(info, assets[name])
    return buffer.getvalue()


def _prepare_manifest(
    manifest: Mapping[str, Any],
    assets: Mapping[str, bytes],
    *,
    recompute: bool,
) -> tuple[dict[str, Any], list[str]]:
    """Return the manifest with computed digests and the matching errors.

    With ``recompute`` the encoder owns the digests: the declared ``sha256``
    and ``byte_length`` are replaced by the real values of the stored bytes.
    Without it, a declared value that disagrees with the asset is an error.
    """
    errors: list[str] = []
    manifest_obj = dict(manifest)

    tracks = manifest_obj.get("tracks")
    if not isinstance(tracks, list):
        return manifest_obj, errors

    prepared: list[Any] = []
    for index, track in enumerate(tracks):
        if not isinstance(track, Mapping):
            prepared.append(track)
            continue
        new_track = dict(track)
        path = new_track.get("path")
        if not isinstance(path, str) or not path:
            prepared.append(new_track)
            continue
        if path not in assets:
            errors.append(f"tracks[{index}] has no asset at {path!r}")
            prepared.append(new_track)
            continue
        data = assets[path]
        digest = hashlib.sha256(data).hexdigest()
        if not recompute:
            declared_digest = new_track.get("sha256")
            if declared_digest is not None and declared_digest != digest:
                errors.append(
                    f"tracks[{index}] declares sha256 {declared_digest!r} but the asset at {path!r} digests to {digest}"
                )
            declared_length = new_track.get("byte_length")
            if declared_length is not None and declared_length != len(data):
                errors.append(
                    f"tracks[{index}] declares byte_length {declared_length} but the asset at {path!r} is {len(data)} bytes"
                )
        new_track["sha256"] = digest
        new_track["byte_length"] = len(data)
        prepared.append(new_track)

    manifest_obj["tracks"] = prepared
    return manifest_obj, errors


def _track_summary(track: Mapping[str, Any]) -> dict[str, Any]:
    """Return the public summary of one track."""
    summary: dict[str, Any] = {
        "id": track.get("id"),
        "kind": track.get("kind"),
        "path": track.get("path"),
        "media_type": track.get("media_type"),
        "codec": track.get("codec"),
        "sample_rate_hz": track.get("sample_rate_hz"),
        "channels": track.get("channels"),
        "start_tick": track.get("start_tick"),
        "duration_ticks": track.get("duration_ticks"),
        "start_seconds": _ticks_to_seconds(track.get("start_tick")),
        "duration_seconds": _ticks_to_seconds(track.get("duration_ticks")),
        "byte_length": track.get("byte_length"),
        "sha256": track.get("sha256"),
    }
    for optional in ("gain_db", "language"):
        if optional in track:
            summary[optional] = track[optional]
    return summary


def _read_member(
    archive: zipfile.ZipFile,
    track: Mapping[str, Any],
) -> tuple[list[str], bytes | None]:
    """Return the archive errors and the verified bytes of one declared asset."""
    path = track.get("path")
    digest = track.get("sha256")
    byte_length = track.get("byte_length")
    errors: list[str] = []

    try:
        info = archive.getinfo(path)
    except (KeyError, TypeError):
        return [f"archive is missing track asset {path!r}"], None

    if _is_int(byte_length) and info.file_size != byte_length:
        errors.append(
            f"archive member {path!r} is {info.file_size} bytes but the manifest declares byte_length {byte_length}"
        )
    if info.file_size > MAX_ASSET_BYTES:
        errors.append(f"archive member {path!r} exceeds the v0.1 asset size limit")
        return errors, None

    try:
        with archive.open(info) as stream:
            data = stream.read(MAX_ASSET_BYTES + 1)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        errors.append(f"archive member {path!r} failed its integrity check: {exc}")
        return errors, None

    if len(data) != info.file_size:
        errors.append(f"archive member {path!r} does not match its declared size")
    if isinstance(digest, str) and hashlib.sha256(data).hexdigest() != digest:
        errors.append(f"archive member {path!r} does not match the declared sha256 digest")
    return errors, data


def create_podx(manifest: Mapping[str, Any], assets: Mapping[str, bytes]) -> bytes:
    """Create a PODX v0.1 container and return its bytes.

    ``assets`` maps archive paths such as ``tracks/voice.opus`` to the stored
    bytes. The bytes are stored verbatim: nothing is transcoded or normalised.
    A track that declares a ``sha256`` or ``byte_length`` must match the asset
    it points at; a missing declaration is computed from the asset.
    """
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    if not isinstance(assets, Mapping):
        raise TypeError("assets must be a mapping")

    prepared: dict[str, bytes] = {}
    path_errors: list[str] = []
    for name, data in assets.items():
        if not isinstance(name, str) or not name:
            raise TypeError("asset names must be non-empty strings")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"asset {name!r} must be bytes")
        prepared[name] = bytes(data)
        if len(prepared[name]) > MAX_ASSET_BYTES:
            raise PodxFormatError(f"asset {name!r} exceeds the v0.1 asset size limit")
        path_errors.extend(f"asset {name!r}: {message}" for message in _path_errors(name, require_asset_root=False))

    manifest_obj, errors = _prepare_manifest(manifest, prepared, recompute=False)
    errors.extend(path_errors)
    errors.extend(_validate_manifest(manifest_obj))
    if errors:
        raise PodxValidationError(errors)

    manifest_bytes = canonical_json(manifest_obj)
    if not (1 <= len(manifest_bytes) <= MAX_MANIFEST_BYTES):
        raise PodxFormatError("Canonical manifest size is outside the v0.1 bounds")
    archive = _build_archive(prepared)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise PodxFormatError("Generated archive exceeds the v0.1 maximum size")
    return (
        MAGIC
        + struct.pack(">I", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", len(archive))
        + archive
    )


def pack_podx(source_dir: str | os.PathLike[str], manifest: Mapping[str, Any]) -> bytes:
    """Pack the assets named by a manifest into a PODX v0.1 container.

    Every track ``path`` is resolved below ``source_dir``; paths that escape
    the source directory are rejected. Only the assets declared by the
    manifest are packaged, and the manifest's ``sha256`` and ``byte_length``
    are rebuilt from the files on disk, so the packed manifest always records
    the real length and digest of every packaged asset.
    """
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    root = Path(source_dir)
    if not root.is_dir():
        raise PodxFormatError(f"Source directory {str(root)!r} does not exist")
    root = root.resolve()

    assets: dict[str, bytes] = {}
    errors: list[str] = []
    tracks = manifest.get("tracks")
    for index, track in enumerate(tracks if isinstance(tracks, list) else []):
        if not isinstance(track, Mapping):
            continue
        path = track.get("path")
        if not isinstance(path, str) or not path:
            continue
        candidate = (root / PurePosixPath(path)).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(f"tracks[{index}].path {path!r} escapes the source directory")
            continue
        try:
            size = candidate.stat().st_size
        except OSError as exc:
            errors.append(f"cannot read asset {path!r}: {exc}")
            continue
        if size > MAX_ASSET_BYTES:
            errors.append(f"asset {path!r} exceeds the v0.1 asset size limit")
            continue
        assets[path] = candidate.read_bytes()

    manifest_obj, prepare_errors = _prepare_manifest(manifest, assets, recompute=True)
    errors.extend(prepare_errors)
    if errors:
        raise PodxValidationError(errors)
    return create_podx(manifest_obj, assets)


def read_podx_manifest(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> dict[str, Any]:
    """Return the validated manifest of a PODX v0.1 container."""
    manifest, _archive_bytes = _parse_container(source)
    errors = _validate_manifest(manifest)
    if errors:
        raise PodxValidationError(errors)
    return manifest


def read_podx_asset(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    path: str,
) -> bytes:
    """Return the verified bytes of one archived asset.

    The declared length and SHA-256 digest are checked before the asset is
    returned.
    """
    manifest, archive_bytes = _parse_container(source)
    errors = _validate_manifest(manifest)
    if errors:
        raise PodxValidationError(errors)

    tracks = manifest.get("tracks")
    track = None
    for candidate in tracks if isinstance(tracks, list) else []:
        if isinstance(candidate, dict) and candidate.get("path") == path:
            track = candidate
            break
    if track is None:
        raise PodxFormatError(f"No track declares asset path {path!r}")

    with _open_archive(archive_bytes) as archive:
        member_errors, data = _read_member(archive, track)
        if member_errors:
            raise PodxFormatError("; ".join(member_errors))
        if data is None:
            raise PodxFormatError(f"Archive member {path!r} could not be read")
        return data


def validate_podx(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> list[str]:
    """Return every validation error of a PODX v0.1 container.

    An empty list means the container is valid.
    """
    try:
        manifest, archive_bytes = _parse_container(source)
    except ContainerError as exc:
        return [str(exc)]

    errors = _validate_manifest(manifest)
    try:
        archive = _open_archive(archive_bytes)
    except PodxFormatError as exc:
        errors.append(str(exc))
        return errors

    with archive:
        errors.extend(zip_safety_errors(archive, ZIP_LIMITS))
        tracks = manifest.get("tracks")
        for track in tracks if isinstance(tracks, list) else []:
            if not isinstance(track, dict):
                continue
            member_errors, _data = _read_member(archive, track)
            errors.extend(member_errors)
    return errors


def inspect_podx(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> dict[str, Any]:
    """Return a summary of a PODX v0.1 container.

    The summary describes the framing and the manifest; it does not read or
    decode any media payload.
    """
    manifest, archive_bytes = _parse_container(source)

    tracks = manifest.get("tracks")
    tracks = tracks if isinstance(tracks, list) else []
    transcript = manifest.get("transcript")
    words = transcript.get("words") if isinstance(transcript, dict) else None
    words = words if isinstance(words, list) else []
    chapters = manifest.get("chapters")
    chapters = chapters if isinstance(chapters, list) else []
    speakers = manifest.get("speakers")
    speakers = speakers if isinstance(speakers, list) else []

    entries: int | None = None
    uncompressed: int | None = None
    try:
        with _open_archive(archive_bytes) as archive:
            infos = archive.infolist()
            entries = len(infos)
            uncompressed = sum(info.file_size for info in infos)
    except PodxError:
        entries = None
        uncompressed = None

    codecs = sorted(
        {
            track["codec"]
            for track in tracks
            if isinstance(track, dict) and isinstance(track.get("codec"), str)
        }
    )

    return {
        "format": manifest.get("format"),
        "format_version": manifest.get("format_version"),
        "title": manifest.get("title"),
        "timebase_hz": manifest.get("timebase_hz"),
        "duration_ticks": manifest.get("duration_ticks"),
        "duration_seconds": _ticks_to_seconds(manifest.get("duration_ticks")),
        "track_count": len(tracks),
        "transcript_word_count": len(words),
        "chapter_count": len(chapters),
        "speaker_count": len(speakers),
        "codecs": codecs,
        "archive": {
            "entries": entries,
            "uncompressed_bytes": uncompressed,
            "compressed_bytes": len(archive_bytes),
        },
        "tracks": [_track_summary(track) for track in tracks if isinstance(track, dict)],
    }


def list_tracks_podx(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
) -> list[dict[str, Any]]:
    """Return one summary per declared track of a PODX v0.1 container."""
    manifest, _archive_bytes = _parse_container(source)
    tracks = manifest.get("tracks")
    if not isinstance(tracks, list):
        return []
    return [_track_summary(track) for track in tracks if isinstance(track, dict)]


def extract_podx(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> list[str]:
    """Extract the verified assets of a PODX v0.1 container into a directory.

    The manifest is written next to the assets as ``manifest.json``. Existing
    files are never overwritten, and the archive is checked for unsafe paths,
    sizes, and compression ratios first. The returned list holds every file
    written, the archive members and the manifest.
    """
    manifest, archive_bytes = _parse_container(source)
    errors = _validate_manifest(manifest)
    if errors:
        raise PodxValidationError(errors)

    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)

    with _open_archive(archive_bytes) as archive:
        safety_errors = zip_safety_errors(archive, ZIP_LIMITS)
        if safety_errors:
            raise PodxFormatError("Archive is unsafe: " + "; ".join(safety_errors))

        tracks = manifest.get("tracks")
        for track in tracks if isinstance(tracks, list) else []:
            if not isinstance(track, dict):
                continue
            member_errors, _data = _read_member(archive, track)
            if member_errors:
                raise PodxFormatError("; ".join(member_errors))

        manifest_path = root / MANIFEST_FILENAME
        if manifest_path.exists():
            raise PodxFormatError(f"Refusing to overwrite existing file {MANIFEST_FILENAME!r}")

        try:
            extracted = extract_zip_safely(archive, root)
        except FormatError as exc:
            raise PodxFormatError(str(exc)) from exc

        atomic_write_bytes(manifest_path, canonical_json(manifest) + b"\n")

    return sorted([*extracted, MANIFEST_FILENAME])
