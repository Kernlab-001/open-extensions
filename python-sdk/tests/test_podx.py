"""Tests for the PODX v0.1 reference implementation.

The v0.1 container never parses a media payload: assets are opaque bytes that
are only checked by length, ZIP CRC, and SHA-256 digest. The fixtures below
therefore use deterministic pseudo-random bytes standing in for encoded audio,
which also keeps the archive compression-ratio guard well inside its limit
(repeating placeholder text would compress far beyond it).

No binary fixtures are committed and the tests never touch the network.
"""
from __future__ import annotations

import hashlib
import io
import json
import random
import struct
import zipfile

import pytest

from open_extensions.podx import (
    FORMAT_VERSION,
    MAGIC,
    TIMEBASE_HZ,
    PodxError,
    PodxFormatError,
    PodxValidationError,
    create_podx,
    extract_podx,
    inspect_podx,
    list_tracks_podx,
    pack_podx,
    read_podx_asset,
    read_podx_manifest,
    validate_podx,
)

VOICE_BYTES = random.Random(101).randbytes(4096)
MUSIC_BYTES = random.Random(202).randbytes(8192)

ASSETS = {
    "tracks/voice.opus": VOICE_BYTES,
    "tracks/music.flac": MUSIC_BYTES,
}


def _canonical(value: object) -> bytes:
    """Return the canonical JSON encoding used by the container."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _archive_bytes(members: dict[str, bytes]) -> bytes:
    """Build a deterministic ZIP archive, mirroring the encoder profile."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name])
    return buffer.getvalue()


def _frame(manifest: object, archive: bytes) -> bytes:
    """Frame a manifest and an archive into a container, bypassing the encoder."""
    manifest_bytes = _canonical(manifest)
    return (
        MAGIC
        + struct.pack(">I", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", len(archive))
        + archive
    )


def _mark_encrypted(archive: bytes) -> bytes:
    """Return the archive with the encryption flag set on its first entry."""
    data = bytearray(archive)
    end_of_central = data.rfind(b"PK\x05\x06")
    central = struct.unpack("<I", data[end_of_central + 16 : end_of_central + 20])[0]
    data[6:8] = struct.pack("<H", 0x1)  # local file header flags
    data[central + 8 : central + 10] = struct.pack("<H", 0x1)  # central directory flags
    return bytes(data)


def _manifest() -> dict:
    """Return a valid manifest for the fixture assets."""
    return {
        "format": "podx",
        "format_version": FORMAT_VERSION,
        "title": "Episode 1",
        "timebase_hz": TIMEBASE_HZ,
        "duration_ticks": 96000,
        "tracks": [
            {
                "id": "voice-1",
                "kind": "voice",
                "path": "tracks/voice.opus",
                "media_type": "audio/opus",
                "codec": "opus-ogg",
                "sample_rate_hz": 48000,
                "channels": 1,
                "start_tick": 0,
                "duration_ticks": 96000,
                "sha256": hashlib.sha256(VOICE_BYTES).hexdigest(),
                "byte_length": len(VOICE_BYTES),
                "gain_db": -3.0,
                "language": "en-US",
            },
            {
                "id": "music-1",
                "kind": "music",
                "path": "tracks/music.flac",
                "media_type": "audio/flac",
                "codec": "flac",
                "sample_rate_hz": 48000,
                "channels": 2,
                "start_tick": 0,
                "duration_ticks": 96000,
                "sha256": hashlib.sha256(MUSIC_BYTES).hexdigest(),
                "byte_length": len(MUSIC_BYTES),
            },
        ],
        "transcript": {
            "words": [
                {
                    "start_tick": 0,
                    "end_tick": 24000,
                    "text": "Hello",
                    "track_id": "voice-1",
                    "speaker_id": "spk-1",
                    "confidence_ppm": 990000,
                },
                {
                    "start_tick": 24000,
                    "end_tick": 48000,
                    "text": "world",
                    "track_id": "voice-1",
                    "speaker_id": "spk-1",
                },
            ]
        },
        "chapters": [
            {"id": "intro", "title": "Intro", "start_tick": 0, "end_tick": 48000},
            {
                "id": "outro",
                "title": "Outro",
                "start_tick": 48000,
                "end_tick": 96000,
                "description": "Closing remarks",
            },
        ],
        "speakers": [{"id": "spk-1", "label": "Host", "locale": "en-US"}],
    }


def _container() -> bytes:
    """Return a valid container built from the fixture manifest and assets."""
    return create_podx(_manifest(), ASSETS)


def _errors(manifest: dict, archive: bytes | None = None) -> list[str]:
    """Return the validation errors of a hand-built container."""
    if archive is None:
        archive = _archive_bytes(ASSETS)
    return validate_podx(_frame(manifest, archive))


# --- round trips ------------------------------------------------------------


def test_create_read_manifest_round_trip():
    blob = _container()
    assert blob.startswith(MAGIC)
    assert read_podx_manifest(blob) == _manifest()
    assert validate_podx(blob) == []


def test_asset_bytes_round_trip_exactly():
    blob = _container()
    assert read_podx_asset(blob, "tracks/voice.opus") == VOICE_BYTES
    assert read_podx_asset(blob, "tracks/music.flac") == MUSIC_BYTES


def test_container_is_deterministic():
    assert _container() == _container()


def test_archive_entries_are_sorted_and_stamped():
    blob = _container()
    manifest_length = struct.unpack(">I", blob[8:12])[0]
    archive = blob[12 + manifest_length + 8 :]
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        infos = opened.infolist()
        names = [info.filename for info in infos]
        assert names == sorted(names)
        assert names == ["tracks/music.flac", "tracks/voice.opus"]
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in infos)
        assert all(info.compress_type == zipfile.ZIP_DEFLATED for info in infos)
        assert all(not (info.flag_bits & 0x1) for info in infos)


def test_pack_podx_reads_assets_from_a_directory(tmp_path):
    source = tmp_path / "source"
    (source / "tracks").mkdir(parents=True)
    (source / "tracks" / "voice.opus").write_bytes(VOICE_BYTES)
    (source / "tracks" / "music.flac").write_bytes(MUSIC_BYTES)
    assert pack_podx(source, _manifest()) == _container()


def test_pack_podx_recomputes_the_declared_digests(tmp_path):
    source = tmp_path / "source"
    (source / "tracks").mkdir(parents=True)
    (source / "tracks" / "voice.opus").write_bytes(VOICE_BYTES)
    (source / "tracks" / "music.flac").write_bytes(MUSIC_BYTES)
    manifest = _manifest()
    manifest["tracks"][0]["sha256"] = "0" * 64
    manifest["tracks"][1]["byte_length"] = 1
    packed = pack_podx(source, manifest)
    assert validate_podx(packed) == []
    packed_manifest = read_podx_manifest(packed)
    assert packed_manifest["tracks"][0]["sha256"] == hashlib.sha256(VOICE_BYTES).hexdigest()
    assert packed_manifest["tracks"][1]["byte_length"] == len(MUSIC_BYTES)


def test_pack_podx_reports_a_missing_asset(tmp_path):
    source = tmp_path / "source"
    (source / "tracks").mkdir(parents=True)
    (source / "tracks" / "voice.opus").write_bytes(VOICE_BYTES)
    with pytest.raises(PodxValidationError):
        pack_podx(source, _manifest())


def test_pack_podx_refuses_paths_outside_the_source_directory(tmp_path):
    manifest = _manifest()
    manifest["tracks"][0]["path"] = "../outside.opus"
    with pytest.raises(PodxError):
        pack_podx(tmp_path, manifest)


# --- framing ----------------------------------------------------------------


def test_wrong_magic_rejected():
    bad = b"NOTPODX!" + b"\x00" * 32
    assert validate_podx(bad)
    with pytest.raises(PodxFormatError):
        read_podx_manifest(bad)


def test_manifest_length_out_of_bounds_rejected():
    archive = _archive_bytes(ASSETS)
    empty = MAGIC + struct.pack(">I", 0) + b"" + struct.pack(">Q", len(archive)) + archive
    assert validate_podx(empty)
    oversized = (
        MAGIC
        + struct.pack(">I", 4 * 1024 * 1024 + 1)
        + b"{}"
        + struct.pack(">Q", len(archive))
        + archive
    )
    assert validate_podx(oversized)


def test_archive_length_mismatch_rejected():
    manifest_bytes = _canonical(_manifest())
    archive = _archive_bytes(ASSETS)
    too_long = (
        MAGIC
        + struct.pack(">I", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", len(archive) + 1)
        + archive
    )
    assert validate_podx(too_long)
    too_short = (
        MAGIC
        + struct.pack(">I", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", len(archive) - 1)
        + archive
    )
    assert validate_podx(too_short)


def test_trailing_bytes_rejected():
    assert validate_podx(_container() + b"garbage")


# --- manifest encoding ------------------------------------------------------


def test_duplicate_json_keys_rejected():
    duplicate = b'{"format":"podx","format":"podx","format_version":"0.1.0"}'
    archive = _archive_bytes(ASSETS)
    bad = MAGIC + struct.pack(">I", len(duplicate)) + duplicate + struct.pack(">Q", len(archive)) + archive
    errors = validate_podx(bad)
    assert any("duplicate" in error for error in errors)


def test_non_canonical_manifest_rejected():
    manifest_bytes = json.dumps(_manifest(), indent=2).encode("utf-8")
    archive = _archive_bytes(ASSETS)
    bad = MAGIC + struct.pack(">I", len(manifest_bytes)) + manifest_bytes + struct.pack(">Q", len(archive)) + archive
    errors = validate_podx(bad)
    assert any("canonical" in error for error in errors)


def test_unknown_root_field_rejected():
    manifest = _manifest()
    manifest["mystery"] = True
    errors = _errors(manifest)
    assert any("unknown root field" in error for error in errors)


# --- asset integrity --------------------------------------------------------


def test_sha256_mismatch_detected():
    manifest = _manifest()
    manifest["tracks"][0]["sha256"] = "0" * 64
    errors = _errors(manifest)
    assert any("sha256" in error for error in errors)


def test_byte_length_mismatch_detected():
    manifest = _manifest()
    manifest["tracks"][0]["byte_length"] = len(VOICE_BYTES) + 1
    errors = _errors(manifest)
    assert any("byte_length" in error for error in errors)


def test_missing_archive_member_detected():
    archive = _archive_bytes({"tracks/voice.opus": VOICE_BYTES})
    errors = _errors(_manifest(), archive)
    assert any("missing" in error and "tracks/music.flac" in error for error in errors)


def test_archive_path_traversal_rejected():
    archive = _archive_bytes({**ASSETS, "../evil.txt": b"evil"})
    errors = _errors(_manifest(), archive)
    assert any(".." in error and "escapes" in error for error in errors)


def test_encrypted_archive_rejected():
    archive = _mark_encrypted(_archive_bytes(ASSETS))
    errors = _errors(_manifest(), archive)
    assert any("encrypted" in error for error in errors)


def test_create_rejects_mismatching_declared_digest():
    manifest = _manifest()
    manifest["tracks"][0]["sha256"] = "0" * 64
    with pytest.raises(PodxValidationError):
        create_podx(manifest, ASSETS)


def test_create_rejects_missing_asset():
    with pytest.raises(PodxValidationError):
        create_podx(_manifest(), {"tracks/voice.opus": VOICE_BYTES})


# --- manifest model ---------------------------------------------------------


def test_unsupported_codec_rejected():
    manifest = _manifest()
    manifest["tracks"][0]["codec"] = "aac"
    errors = _errors(manifest)
    assert any("codec" in error and "aac" in error for error in errors)


def test_timebase_must_be_48000():
    manifest = _manifest()
    manifest["timebase_hz"] = 44100
    errors = _errors(manifest)
    assert any("timebase_hz" in error for error in errors)


def test_non_integer_ticks_rejected():
    manifest = _manifest()
    manifest["tracks"][0]["start_tick"] = 1.5
    errors = _errors(manifest)
    assert any("start_tick" in error for error in errors)


def test_non_integer_word_tick_rejected():
    manifest = _manifest()
    manifest["transcript"]["words"][0]["end_tick"] = 24000.5
    errors = _errors(manifest)
    assert any("end_tick" in error for error in errors)


def test_duplicate_track_ids_rejected():
    manifest = _manifest()
    manifest["tracks"][1]["id"] = manifest["tracks"][0]["id"]
    errors = _errors(manifest)
    assert any("unique" in error for error in errors)


def test_track_path_must_be_under_tracks():
    manifest = _manifest()
    manifest["tracks"][0]["path"] = "../evil.opus"
    errors = _errors(manifest)
    assert any("path" in error for error in errors)


def test_track_must_end_within_the_manifest_duration():
    manifest = _manifest()
    manifest["tracks"][0]["duration_ticks"] = 96000 + 48000
    errors = _errors(manifest)
    assert any("duration_ticks" in error for error in errors)


def test_overlapping_chapters_rejected():
    manifest = _manifest()
    manifest["chapters"][1]["start_tick"] = 24000
    errors = _errors(manifest)
    assert any("overlaps" in error for error in errors)


def test_out_of_order_chapters_rejected():
    manifest = _manifest()
    manifest["chapters"] = [
        {"id": "late", "title": "Late", "start_tick": 48000, "end_tick": 96000},
        {"id": "early", "title": "Early", "start_tick": 0, "end_tick": 48000},
    ]
    errors = _errors(manifest)
    assert any("chronological order" in error for error in errors)


def test_word_without_positive_duration_rejected():
    manifest = _manifest()
    manifest["transcript"]["words"][1]["end_tick"] = 24000
    errors = _errors(manifest)
    assert any("start_tick < end_tick" in error for error in errors)


def test_out_of_bounds_word_rejected():
    manifest = _manifest()
    manifest["transcript"]["words"][1]["end_tick"] = 96000 + 48000
    errors = _errors(manifest)
    assert any("duration_ticks" in error for error in errors)


def test_overlapping_words_rejected():
    manifest = _manifest()
    manifest["transcript"]["words"][1]["start_tick"] = 12000
    errors = _errors(manifest)
    assert any("overlaps" in error for error in errors)


def test_unknown_track_reference_rejected():
    manifest = _manifest()
    manifest["transcript"]["words"][0]["track_id"] = "track-404"
    errors = _errors(manifest)
    assert any("track_id" in error for error in errors)


def test_unknown_speaker_reference_rejected():
    manifest = _manifest()
    manifest["transcript"]["words"][0]["speaker_id"] = "spk-404"
    errors = _errors(manifest)
    assert any("speaker_id" in error for error in errors)


# --- extraction -------------------------------------------------------------


def test_extract_podx_extracts_assets(tmp_path):
    names = extract_podx(_container(), tmp_path)
    assert sorted(names) == ["manifest.json", "tracks/music.flac", "tracks/voice.opus"]
    assert (tmp_path / "tracks" / "voice.opus").read_bytes() == VOICE_BYTES
    assert (tmp_path / "tracks" / "music.flac").read_bytes() == MUSIC_BYTES
    assert json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8")) == _manifest()
    assert len(names) == len([path for path in tmp_path.rglob("*") if path.is_file()])


def test_extract_podx_refuses_to_overwrite(tmp_path):
    extract_podx(_container(), tmp_path)
    with pytest.raises(PodxFormatError):
        extract_podx(_container(), tmp_path)


def test_extract_podx_refuses_unsafe_archive(tmp_path):
    archive = _archive_bytes({**ASSETS, "../evil.txt": b"evil"})
    with pytest.raises(PodxFormatError):
        extract_podx(_frame(_manifest(), archive), tmp_path)
    assert list(tmp_path.rglob("*")) == []
    assert not (tmp_path.parent / "evil.txt").exists()


def test_container_can_be_read_from_a_path(tmp_path):
    path = tmp_path / "episode.podx"
    path.write_bytes(_container())
    assert read_podx_manifest(path) == _manifest()
    assert validate_podx(path) == []
    assert read_podx_asset(path, "tracks/voice.opus") == VOICE_BYTES
    assert inspect_podx(path)["track_count"] == 2
    assert len(list_tracks_podx(path)) == 2
    assert sorted(extract_podx(path, tmp_path / "out")) == [
        "manifest.json",
        "tracks/music.flac",
        "tracks/voice.opus",
    ]


# --- inspection -------------------------------------------------------------


def test_list_tracks_podx_returns_track_summaries():
    tracks = list_tracks_podx(_container())
    assert [track["id"] for track in tracks] == ["voice-1", "music-1"]
    assert tracks[0]["path"] == "tracks/voice.opus"
    assert tracks[0]["codec"] == "opus-ogg"
    assert tracks[0]["kind"] == "voice"
    assert tracks[0]["channels"] == 1
    assert tracks[0]["duration_ticks"] == 96000
    assert tracks[0]["duration_seconds"] == 2.0
    assert tracks[0]["byte_length"] == len(VOICE_BYTES)
    assert tracks[1]["codec"] == "flac"
    assert tracks[1]["sha256"] == hashlib.sha256(MUSIC_BYTES).hexdigest()


def test_inspect_podx_summarizes_the_container():
    info = inspect_podx(_container())
    assert info["format"] == "podx"
    assert info["format_version"] == FORMAT_VERSION
    assert info["title"] == "Episode 1"
    assert info["timebase_hz"] == TIMEBASE_HZ
    assert info["duration_seconds"] == 2.0
    assert info["track_count"] == 2
    assert info["transcript_word_count"] == 2
    assert info["chapter_count"] == 2
    assert info["speaker_count"] == 1
    assert info["codecs"] == ["flac", "opus-ogg"]
    assert info["archive"]["entries"] == 2
