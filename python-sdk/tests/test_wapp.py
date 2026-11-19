from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import sqlite3
import struct
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest

from open_extensions.wapp import (
    MAGIC,
    FORMAT_VERSION,
    WappError,
    WappFormatError,
    WappValidationError,
    create_wapp,
    extract_wapp,
    inspect_wapp,
    list_wapp,
    pack_wapp,
    read_wapp_manifest,
    serve_wapp,
    validate_wapp,
)

INDEX_HTML = b"<!doctype html><p>hi</p>"
ASSET_JS = b"console.log('hello');\n"
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"

CONTENT: dict[str, bytes] = {
    "app/index.html": INDEX_HTML,
    "app/assets/app.js": ASSET_JS,
}


def media_type(path: str) -> str:
    """Return a media type for a package path."""
    return {
        ".html": "text/html",
        ".js": "text/javascript",
        ".css": "text/css",
    }.get(Path(path).suffix.lower(), "application/octet-stream")


def file_entries(entries: dict[str, bytes]) -> list[dict[str, Any]]:
    """Return manifest file entries for a mapping of package content."""
    return [
        {
            "path": path,
            "byte_length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "media_type": media_type(path),
        }
        for path, data in sorted(entries.items())
    ]


def build_manifest(entries: dict[str, bytes], **overrides: Any) -> dict[str, Any]:
    """Return a valid v0.1 manifest for a mapping of package content."""
    manifest: dict[str, Any] = {
        "format": "wapp",
        "format_version": FORMAT_VERSION,
        "app_id": "com.example.demo",
        "name": "Demo App",
        "app_version": "1.0.0",
        "runtime_min": "0.1.0",
        "entrypoint": "app/index.html",
        "files": file_entries(entries),
        "permissions": [],
        "network": {"mode": "deny", "allowed_origins": []},
        "security": {
            "csp": CSP,
            "allow_inline_scripts": False,
            "allow_eval": False,
            "allow_popups": False,
            "external_navigation": "deny",
        },
    }
    manifest.update(overrides)
    return manifest


def build_archive(entries: dict[str, bytes]) -> bytes:
    """Return a deterministic ZIP archive for a mapping of package content."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
    return buffer.getvalue()


def canonical(value: Any) -> bytes:
    """Return the canonical JSON encoding of a value."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def frame(manifest: Any, entries: dict[str, bytes]) -> bytes:
    """Return a framed WAPP package without validating it."""
    raw = canonical(manifest)
    archive = build_archive(entries)
    return MAGIC + struct.pack(">I", len(raw)) + raw + struct.pack(">Q", len(archive)) + archive


def build_package(entries: dict[str, bytes] | None = None, **overrides: Any) -> bytes:
    """Return a valid WAPP package."""
    content = dict(CONTENT if entries is None else entries)
    return create_wapp(build_manifest(content, **overrides), content)


def errors_text(errors: list[str]) -> str:
    """Return the joined validation errors."""
    return "; ".join(errors)


# --- round trips ------------------------------------------------------------


def test_create_and_read_manifest_round_trip():
    manifest = build_manifest(CONTENT)
    blob = create_wapp(manifest, CONTENT)
    assert blob.startswith(MAGIC)
    assert read_wapp_manifest(blob) == manifest


def test_file_bytes_round_trip_exactly(tmp_path):
    blob = build_package()
    destination = tmp_path / "out"
    extracted = extract_wapp(blob, destination)
    assert extracted == sorted(CONTENT)
    for path, data in CONTENT.items():
        assert (destination / path).read_bytes() == data


def test_create_is_deterministic():
    manifest = build_manifest(CONTENT)
    assert create_wapp(manifest, CONTENT) == create_wapp(manifest, CONTENT)


def test_validate_accepts_a_valid_package():
    assert validate_wapp(build_package()) == []


def test_inspect_reports_the_manifest_summary():
    summary = inspect_wapp(build_package())
    assert summary["format"] == "wapp"
    assert summary["format_version"] == FORMAT_VERSION
    assert summary["app_id"] == "com.example.demo"
    assert summary["entrypoint"] == "app/index.html"
    assert summary["file_count"] == 2
    assert summary["permissions"] == []


def test_pack_wapp_hashes_the_project_directory(tmp_path):
    project = tmp_path / "project"
    (project / "app" / "assets").mkdir(parents=True)
    (project / "app" / "index.html").write_bytes(INDEX_HTML)
    (project / "app" / "assets" / "app.js").write_bytes(ASSET_JS)
    manifest = build_manifest(CONTENT)
    manifest.pop("files")
    blob = pack_wapp(project, manifest)
    package = read_wapp_manifest(blob)
    assert [entry["path"] for entry in package["files"]] == sorted(CONTENT)
    entries = {entry["path"]: entry for entry in package["files"]}
    assert entries["app/index.html"]["sha256"] == hashlib.sha256(INDEX_HTML).hexdigest()
    assert entries["app/index.html"]["byte_length"] == len(INDEX_HTML)
    assert validate_wapp(blob) == []


def test_pack_wapp_skips_files_outside_the_package_layout(tmp_path, capsys):
    project = tmp_path / "project"
    (project / "app").mkdir(parents=True)
    (project / "app" / "index.html").write_bytes(INDEX_HTML)
    (project / "manifest.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest({"app/index.html": INDEX_HTML})
    blob = pack_wapp(project, manifest)
    package = read_wapp_manifest(blob)
    assert [entry["path"] for entry in package["files"]] == ["app/index.html"]
    assert validate_wapp(blob) == []
    assert "manifest.json" in capsys.readouterr().err


def test_pack_wapp_rejects_a_missing_entrypoint(tmp_path):
    project = tmp_path / "project"
    (project / "app").mkdir(parents=True)
    (project / "app" / "other.html").write_bytes(INDEX_HTML)
    with pytest.raises(WappValidationError):
        pack_wapp(project, build_manifest(CONTENT))


# --- framing ----------------------------------------------------------------


def test_wrong_magic_rejected():
    blob = build_package()
    broken = b"XAPP\r\n\x1a\n" + blob[len(MAGIC) :]
    assert validate_wapp(broken)
    with pytest.raises(WappFormatError):
        read_wapp_manifest(broken)


def test_manifest_length_out_of_bounds_rejected():
    blob = build_package()
    for length in (0, 5 * 1024 * 1024):
        broken = blob[: len(MAGIC)] + struct.pack(">I", length) + blob[len(MAGIC) + 4 :]
        assert validate_wapp(broken)


def test_archive_length_mismatch_rejected():
    blob = build_package()
    offset = len(MAGIC) + 4 + struct.unpack(">I", blob[len(MAGIC) : len(MAGIC) + 4])[0]
    declared = struct.unpack(">Q", blob[offset : offset + 8])[0]
    for length in (declared + 16, declared - 16):
        broken = blob[:offset] + struct.pack(">Q", length) + blob[offset + 8 :]
        assert validate_wapp(broken)


def test_trailing_bytes_rejected():
    assert validate_wapp(build_package() + b"garbage")


def test_duplicate_json_keys_rejected():
    raw = b'{"format":"wapp","format":"wapp"}'
    archive = build_archive(CONTENT)
    blob = MAGIC + struct.pack(">I", len(raw)) + raw + struct.pack(">Q", len(archive)) + archive
    assert validate_wapp(blob)
    with pytest.raises(WappFormatError):
        read_wapp_manifest(blob)


def test_non_canonical_manifest_rejected():
    manifest = build_manifest(CONTENT)
    raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    archive = build_archive(CONTENT)
    blob = MAGIC + struct.pack(">I", len(raw)) + raw + struct.pack(">Q", len(archive)) + archive
    assert validate_wapp(blob)
    with pytest.raises(WappFormatError):
        read_wapp_manifest(blob)


def test_unsupported_version_rejected():
    manifest = build_manifest(CONTENT, format_version="9.9.9")
    blob = frame(manifest, CONTENT)
    assert validate_wapp(blob)


def test_missing_file_reports_an_error_instead_of_raising(tmp_path):
    errors = validate_wapp(tmp_path / "absent.wapp")
    assert errors
    with pytest.raises(WappFormatError):
        read_wapp_manifest(tmp_path / "absent.wapp")


def test_corrupt_archive_reports_an_error():
    manifest = build_manifest(CONTENT)
    raw = canonical(manifest)
    blob = MAGIC + struct.pack(">I", len(raw)) + raw + struct.pack(">Q", 4) + b"junk"
    assert validate_wapp(blob)


def test_validation_error_carries_the_error_list():
    manifest = build_manifest(CONTENT)
    manifest["security"]["allow_eval"] = True
    with pytest.raises(WappValidationError) as excinfo:
        create_wapp(manifest, CONTENT)
    assert excinfo.value.errors
    assert str(excinfo.value)


# --- manifest and archive consistency ---------------------------------------


def test_sha256_mismatch_detected():
    manifest = build_manifest(CONTENT)
    manifest["files"][0]["sha256"] = "0" * 64
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("sha256" in error for error in errors)


def test_byte_length_mismatch_detected():
    manifest = build_manifest(CONTENT)
    manifest["files"][0]["byte_length"] = 999
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("byte_length" in error for error in errors)


def test_missing_file_detected():
    manifest = build_manifest(CONTENT)
    manifest["files"].append(
        {
            "path": "app/missing.html",
            "byte_length": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
            "media_type": "text/html",
        }
    )
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("missing from the archive" in error for error in errors)


def test_unlisted_archive_member_detected():
    entries = dict(CONTENT)
    entries["app/smuggled.txt"] = b"smuggled"
    manifest = build_manifest(CONTENT)
    errors = validate_wapp(frame(manifest, entries))
    assert any("not listed in the manifest" in error for error in errors)


def test_create_rejects_a_manifest_that_does_not_match_the_content():
    manifest = build_manifest(CONTENT)
    manifest["files"][0]["sha256"] = "0" * 64
    with pytest.raises(WappValidationError) as excinfo:
        create_wapp(manifest, CONTENT)
    assert any("sha256" in error for error in excinfo.value.errors)


def test_entrypoint_below_app_rejected():
    manifest = build_manifest(CONTENT, entrypoint="assets/app.js")
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("below 'app/'" in error for error in errors)
    with pytest.raises(WappValidationError):
        create_wapp(manifest, CONTENT)


def test_entrypoint_missing_from_the_archive_detected():
    entries = {"app/assets/app.js": ASSET_JS}
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("entrypoint" in error for error in errors)


def test_archive_path_traversal_rejected():
    entries = dict(CONTENT)
    entries["../evil.txt"] = b"evil"
    manifest = build_manifest(CONTENT)
    errors = validate_wapp(frame(manifest, entries))
    assert any(".." in error or "escapes the archive root" in error for error in errors)


def test_archive_member_outside_the_layout_rejected():
    entries = dict(CONTENT)
    entries["evil.txt"] = b"evil"
    manifest = build_manifest(CONTENT)
    errors = validate_wapp(frame(manifest, entries))
    assert any("outside the required" in error for error in errors)


# --- network policy ---------------------------------------------------------


def test_http_origin_rejected():
    manifest = build_manifest(CONTENT, network={"mode": "allowlist", "allowed_origins": ["http://example.com"]})
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("https scheme" in error for error in errors)


def test_wildcard_origin_rejected():
    manifest = build_manifest(CONTENT, network={"mode": "allowlist", "allowed_origins": ["https://*.example.com"]})
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("wildcard" in error for error in errors)


def test_bare_host_origin_rejected():
    manifest = build_manifest(CONTENT, network={"mode": "allowlist", "allowed_origins": ["https://localhost"]})
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("bare host" in error for error in errors)


def test_origin_with_a_path_rejected():
    manifest = build_manifest(CONTENT, network={"mode": "allowlist", "allowed_origins": ["https://example.com/api"]})
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("exact origin" in error for error in errors)


def test_declared_https_origin_is_accepted():
    manifest = build_manifest(CONTENT, network={"mode": "allowlist", "allowed_origins": ["https://example.com"]})
    assert validate_wapp(frame(manifest, CONTENT)) == []


def test_deny_mode_with_origins_rejected():
    manifest = build_manifest(CONTENT, network={"mode": "deny", "allowed_origins": ["https://example.com"]})
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("'deny'" in error for error in errors)


# --- content security policy ------------------------------------------------


def test_unsafe_eval_csp_rejected():
    manifest = build_manifest(CONTENT)
    manifest["security"]["csp"] = "default-src 'none'; script-src 'self' 'unsafe-eval'"
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("'unsafe-eval'" in error for error in errors)


def test_unsafe_inline_csp_rejected():
    manifest = build_manifest(CONTENT)
    manifest["security"]["csp"] = "default-src 'none'; script-src 'self' 'unsafe-inline'"
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("'unsafe-inline'" in error for error in errors)


def test_csp_without_default_src_none_rejected():
    manifest = build_manifest(CONTENT)
    manifest["security"]["csp"] = "script-src 'self'"
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("default-src" in error for error in errors)


def test_remote_script_source_rejected():
    manifest = build_manifest(CONTENT)
    manifest["security"]["csp"] = "default-src 'none'; script-src 'self' https://cdn.example.com"
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("script-src" in error for error in errors)


def test_connect_src_must_match_the_network_allowlist():
    manifest = build_manifest(CONTENT)
    manifest["security"]["csp"] = "default-src 'none'; connect-src 'self' https://other.example.com"
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("connect-src" in error for error in errors)


def test_allow_eval_and_inline_scripts_rejected():
    manifest = build_manifest(CONTENT)
    manifest["security"]["allow_eval"] = True
    manifest["security"]["allow_inline_scripts"] = True
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("allow_eval" in error for error in errors)
    assert any("allow_inline_scripts" in error for error in errors)


# --- permission model -------------------------------------------------------


def test_unknown_permission_rejected():
    manifest = build_manifest(CONTENT, permissions=["filesystem.read"])
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("permission vocabulary" in error for error in errors)


def test_duplicate_permission_rejected():
    manifest = build_manifest(CONTENT, permissions=["camera", "camera"])
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("more than once" in error for error in errors)


def test_popups_cannot_be_declared():
    manifest = build_manifest(CONTENT)
    manifest["security"]["allow_popups"] = True
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("allow_popups" in error for error in errors)


def test_external_navigation_must_be_denied():
    manifest = build_manifest(CONTENT)
    manifest["security"]["external_navigation"] = "confirm"
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("external_navigation" in error for error in errors)


def test_unrequested_camera_capability_detected():
    entries = dict(CONTENT)
    entries["app/assets/app.js"] = b"navigator.mediaDevices.getUserMedia({video:true});\n"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("camera/microphone capture" in error for error in errors)


def test_declared_camera_capability_is_accepted():
    entries = dict(CONTENT)
    entries["app/assets/app.js"] = b"navigator.mediaDevices.getUserMedia({video:true});\n"
    manifest = build_manifest(entries, permissions=["camera"])
    assert validate_wapp(frame(manifest, entries)) == []


def test_file_chooser_capability_cannot_be_declared():
    entries = dict(CONTENT)
    entries["app/index.html"] = b'<input type="file" id="picker">'
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("file chooser" in error for error in errors)


def test_native_filesystem_capability_cannot_be_declared():
    entries = dict(CONTENT)
    entries["app/assets/app.js"] = b"const fs = require('fs');\n"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("native filesystem access" in error for error in errors)


def test_popup_capability_cannot_be_declared():
    entries = dict(CONTENT)
    entries["app/assets/app.js"] = b"window.open('https://example.com');\n"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("popups" in error for error in errors)


def test_unquoted_file_input_detected():
    entries = dict(CONTENT)
    entries["app/index.html"] = b"<input type=file id=picker>"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("file chooser" in error for error in errors)


def test_javascript_download_property_detected():
    entries = dict(CONTENT)
    entries["app/assets/app.js"] = b"anchor.download = 'report.txt';\n"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("downloads" in error for error in errors)


def test_esm_filesystem_import_detected():
    entries = dict(CONTENT)
    entries["app/assets/app.js"] = b"import fs from 'fs';\n"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("native filesystem access" in error for error in errors)


def test_typescript_asset_is_scanned():
    entries = dict(CONTENT)
    entries["app/assets/app.ts"] = b"navigator.geolocation.getCurrentPosition(() => {});\n"
    manifest = build_manifest(entries)
    errors = validate_wapp(frame(manifest, entries))
    assert any("geolocation" in error for error in errors)


def test_storage_permission_requires_a_storage_block():
    manifest = build_manifest(CONTENT, permissions=["storage.sqlite"])
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("storage block" in error for error in errors)


def test_storage_block_requires_the_storage_permission():
    manifest = build_manifest(CONTENT)
    manifest["storage"] = {"database_id": "demo", "seed_path": "storage/seed.sqlite", "schema_version": "1"}
    errors = validate_wapp(frame(manifest, CONTENT))
    assert any("storage.sqlite" in error for error in errors)


# --- seed database ----------------------------------------------------------


def make_seed() -> bytes:
    """Return the bytes of a valid SQLite seed database."""
    with tempfile.TemporaryDirectory() as workspace:
        path = Path(workspace) / "seed.sqlite"
        connection = sqlite3.connect(str(path))
        connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
        connection.execute("INSERT INTO notes (body) VALUES ('hello')")
        connection.commit()
        connection.close()
        return path.read_bytes()


def test_valid_seed_database_is_accepted():
    entries = dict(CONTENT)
    entries["storage/seed.sqlite"] = make_seed()
    manifest = build_manifest(entries, permissions=["storage.sqlite"])
    manifest["storage"] = {"database_id": "demo", "seed_path": "storage/seed.sqlite", "schema_version": "1"}
    assert validate_wapp(frame(manifest, entries)) == []


def test_corrupt_seed_database_detected():
    entries = dict(CONTENT)
    entries["storage/seed.sqlite"] = b"this is not a sqlite database"
    manifest = build_manifest(entries, permissions=["storage.sqlite"])
    manifest["storage"] = {"database_id": "demo", "seed_path": "storage/seed.sqlite", "schema_version": "1"}
    errors = validate_wapp(frame(manifest, entries))
    assert any("integrity check" in error for error in errors)


# --- extraction and listing -------------------------------------------------


def test_extract_wapp_refuses_to_overwrite_an_existing_file(tmp_path):
    blob = build_package()
    destination = tmp_path / "out"
    extracted = extract_wapp(blob, destination)
    assert extracted == sorted(CONTENT)
    with pytest.raises(WappFormatError):
        extract_wapp(blob, destination)


def test_list_wapp_returns_the_expected_file_summaries():
    summaries = list_wapp(build_package())
    assert [item["path"] for item in summaries] == sorted(CONTENT)
    for item in summaries:
        assert item["byte_length"] == len(CONTENT[item["path"]])
        assert item["sha256"] == hashlib.sha256(CONTENT[item["path"]]).hexdigest()
        assert item["media_type"] == media_type(item["path"])


# --- development inspection server -------------------------------------------


def wait_for_url(buffer: io.StringIO, failures: list[BaseException]) -> str:
    """Return the URL the development server printed, or fail the test."""
    deadline = time.monotonic() + 15.0
    pattern = re.compile(r"http://127\.0\.0\.1:(\d+)/")
    while time.monotonic() < deadline:
        if failures:
            raise failures[0]
        match = pattern.search(buffer.getvalue())
        if match:
            return f"http://127.0.0.1:{match.group(1)}/"
        time.sleep(0.05)
    raise AssertionError(f"the server did not report a URL: {buffer.getvalue()!r}")


def test_serve_wapp_serves_the_index_and_one_asset():
    blob = build_package()
    stop = threading.Event()
    failures: list[BaseException] = []
    buffer = io.StringIO()

    def run() -> None:
        try:
            serve_wapp(blob, port=0, stop_event=stop)
        except BaseException as exc:  # pragma: no cover - reported through the test
            failures.append(exc)

    with contextlib.redirect_stdout(buffer):
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            url = wait_for_url(buffer, failures)
            with urllib.request.urlopen(url, timeout=15) as response:
                assert response.status == 200
                assert response.headers["Content-Security-Policy"] == CSP
                assert response.headers["X-Content-Type-Options"] == "nosniff"
                assert response.read() == INDEX_HTML
            with urllib.request.urlopen(f"{url}assets/app.js", timeout=15) as response:
                assert response.read() == ASSET_JS
        finally:
            stop.set()
            thread.join(timeout=15)
    assert not thread.is_alive()
    assert not failures


def test_serve_wapp_refuses_a_path_outside_the_app_directory():
    blob = build_package()
    stop = threading.Event()
    failures: list[BaseException] = []
    buffer = io.StringIO()

    def run() -> None:
        try:
            serve_wapp(blob, port=0, stop_event=stop)
        except BaseException as exc:  # pragma: no cover - reported through the test
            failures.append(exc)

    with contextlib.redirect_stdout(buffer):
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            url = wait_for_url(buffer, failures)
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                urllib.request.urlopen(f"{url}../../etc/passwd", timeout=15)
            assert excinfo.value.code in (403, 404)
        finally:
            stop.set()
            thread.join(timeout=15)
    assert not thread.is_alive()


def test_serve_wapp_refuses_an_invalid_package():
    manifest = build_manifest(CONTENT)
    manifest["security"]["csp"] = "script-src 'self'"
    with pytest.raises(WappValidationError):
        serve_wapp(frame(manifest, CONTENT))
