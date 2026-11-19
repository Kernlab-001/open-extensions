from __future__ import annotations

import json
import struct

import pytest

from open_extensions.memx import (
    MAGIC,
    MemxAuthenticationError,
    MemxFormatError,
    MemxPayloadError,
    MemxValidationError,
    create_memx,
    inspect_memx,
    read_memx,
    validate_memx,
)


PAYLOAD = {
    "memx_version": "0.1.0",
    "exported_at": "2026-11-19T12:00:00Z",
    "source": {"application": "example-app", "model": "example-model"},
    "profiles": [
        {
            "id": "default",
            "label": "Default profile",
            "preferences": {"response_style": "clear and concise", "language": "en"},
            "coding_profiles": {
                "python": {
                    "style_guide": "Use type hints and focused functions.",
                    "formatting": {"line_length": 100},
                    "examples": ["def add(a: int, b: int) -> int: return a + b"],
                }
            },
            "context_items": [
                {
                    "id": "project-1",
                    "kind": "project",
                    "content": "Example project context; replace with user-approved content.",
                    "updated_at": "2026-11-19T12:00:00Z",
                    "tags": ["example", "project"],
                }
            ],
        }
    ],
    "extensions": {},
}


def test_round_trip_and_validation():
    blob = create_memx(PAYLOAD, "correct horse battery staple")
    assert blob.startswith(MAGIC)
    assert read_memx(blob, "correct horse battery staple") == PAYLOAD
    assert validate_memx(blob) == []
    assert validate_memx(blob, "correct horse battery staple") == []


def test_inspect_does_not_expose_payload_or_password():
    blob = create_memx(PAYLOAD, "a different good passphrase")
    assert b"response_style" not in blob
    assert b"Example project context" not in blob
    header = inspect_memx(blob)
    assert header["format"] == "memx"
    assert "nonce" in header
    assert "preferences" not in json.dumps(header)
    assert "salt" in header["kdf"]
    assert "_decoded_salt" not in header


def test_wrong_password_fails_authentication():
    blob = create_memx(PAYLOAD, "correct password")
    with pytest.raises(MemxAuthenticationError):
        read_memx(blob, "wrong password")
    assert validate_memx(blob, "wrong password")


def test_ciphertext_tampering_fails_authentication():
    blob = bytearray(create_memx(PAYLOAD, "correct password"))
    blob[-1] ^= 0x01
    with pytest.raises(MemxAuthenticationError):
        read_memx(bytes(blob), "correct password")


def test_header_tampering_is_authenticated():
    blob = create_memx(PAYLOAD, "correct password")
    header_len = struct.unpack(">I", blob[8:12])[0]
    header_start = 12
    header_end = header_start + header_len
    header = json.loads(blob[header_start:header_end])
    old_nonce = header["nonce"]
    header["nonce"] = ("A" if old_nonce[0] != "A" else "B") + old_nonce[1:]
    changed_header = json.dumps(header, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tampered = MAGIC + struct.pack(">I", len(changed_header)) + changed_header + blob[header_end:]
    # The framing/header remain valid, but the altered header is part of GCM AAD.
    assert validate_memx(tampered) == []
    with pytest.raises(MemxAuthenticationError):
        read_memx(tampered, "correct password")


def test_trailing_bytes_rejected():
    blob = create_memx(PAYLOAD, "correct password") + b"garbage"
    assert validate_memx(blob)


def test_bad_magic_rejected():
    assert validate_memx(b"NOTMEMX!" + b"\x00\x00\x00\x02{}")


def test_invalid_payload_rejected_before_encryption():
    invalid = dict(PAYLOAD)
    invalid["memx_version"] = "9.9.9"
    with pytest.raises(MemxValidationError):
        create_memx(invalid, "password")


def test_fixed_kdf_profile_cannot_be_overridden():
    blob = create_memx(PAYLOAD, "correct password")
    assert validate_memx(blob) == []
    tampered = blob.replace(b'"memory_kib":65536', b'"memory_kib":75536', 1)
    assert tampered != blob
    assert validate_memx(tampered)


def test_container_length_prefix_is_exact():
    blob = create_memx(PAYLOAD, "correct password")
    header_len = struct.unpack(">I", blob[8:12])[0]
    assert header_len > 0
    assert validate_memx(blob) == []
