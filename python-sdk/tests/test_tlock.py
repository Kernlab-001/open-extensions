from __future__ import annotations

import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from open_extensions import _hpke
from open_extensions._container import canonical_json, loads_strict
from open_extensions.tlock import (
    FORMAT_VERSION,
    GRANT_PROTOCOL,
    HPKE_INFO,
    MAGIC,
    TlockAuthenticationError,
    TlockFormatError,
    TlockPolicyError,
    TlockValidationError,
    check_policy,
    create_tlock,
    inspect_tlock,
    open_tlock_passkey,
    open_tlock_server,
    read_tlock,
    unwrap_recipient_key,
    validate_tlock,
    verify_grant,
    wrap_recipient_key,
)

PRF_OUTPUT = bytes(range(32))
CREDENTIAL_HASH = "A" * 43  # base64url of 32 bytes
POLICY = {"enforcement": "advisory-local", "policy_id": "policy-1"}


def _recipients() -> list[dict]:
    return [
        {
            "recipient_id": "alice",
            "credential_id_hash": CREDENTIAL_HASH,
            "prf_output": PRF_OUTPUT,
        }
    ]


def _key_access() -> dict:
    return {"mode": "passkey-local", "recipients": _recipients()}


def _make_file(payload: bytes = b"secret contents") -> bytes:
    return create_tlock(payload, policy=POLICY, key_access=_key_access())


# --- RFC 9180 test vectors -------------------------------------------------

# RFC 9180 Appendix A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
RFC_A1 = {
    "skEm": "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
    "pkEm": "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    "skRm": "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    "pkRm": "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    "enc": "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    "shared_secret": "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    "key_schedule_context": (
        "00725611c9d98c07c03f60095cd32d400d8347d45ed670"
        "97bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f3052352"
        "6106f637abb05449"
    ),
    "secret": "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397",
    "key": "4531685d41d65f03dc48f6b8302c05b0",
    "base_nonce": "56d890e5accaaf011cff4b7d",
    "exporter_secret": "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "aad": "436f756e742d30",
    "ct": (
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
        "6d8770ac83d07bea87e13c512a"
    ),
}


def test_rfc9180_kem_shared_secret():
    private = X25519PrivateKey.from_private_bytes(bytes.fromhex(RFC_A1["skRm"]))
    assert _hpke.dhkem_decap(bytes.fromhex(RFC_A1["enc"]), private) == bytes.fromhex(
        RFC_A1["shared_secret"]
    )


def test_rfc9180_key_schedule():
    shared_secret = bytes.fromhex(RFC_A1["shared_secret"])
    info = bytes.fromhex(RFC_A1["info"])
    key, base_nonce, exporter_secret = _hpke.key_schedule(
        shared_secret, info, aead_id=_hpke.AEAD_ID_AES128_GCM
    )
    assert key == bytes.fromhex(RFC_A1["key"])
    assert base_nonce == bytes.fromhex(RFC_A1["base_nonce"])
    assert exporter_secret == bytes.fromhex(RFC_A1["exporter_secret"])


def test_rfc9180_key_schedule_context_and_secret():
    shared_secret = bytes.fromhex(RFC_A1["shared_secret"])
    info = bytes.fromhex(RFC_A1["info"])
    suite_id = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0001).to_bytes(2, "big")
    psk_id_hash = _hpke.labeled_extract(b"", b"psk_id_hash", b"", suite_id)
    info_hash = _hpke.labeled_extract(b"", b"info_hash", info, suite_id)
    context = bytes([0]) + psk_id_hash + info_hash
    assert context == bytes.fromhex(RFC_A1["key_schedule_context"])
    assert _hpke.labeled_extract(shared_secret, b"secret", b"", suite_id) == bytes.fromhex(
        RFC_A1["secret"]
    )


def test_rfc9180_aead_encryption():
    shared_secret = bytes.fromhex(RFC_A1["shared_secret"])
    info = bytes.fromhex(RFC_A1["info"])
    aad = bytes.fromhex(RFC_A1["aad"])
    plaintext = b"Beauty is truth, truth beauty"
    ciphertext = _hpke.seal(
        shared_secret, info, aad, plaintext, aead_id=_hpke.AEAD_ID_AES128_GCM
    )
    assert ciphertext == bytes.fromhex(RFC_A1["ct"])
    assert (
        _hpke.open_(
            shared_secret, info, aad, ciphertext, aead_id=_hpke.AEAD_ID_AES128_GCM
        )
        == plaintext
    )


def test_hpke_encap_decap_round_trip():
    private = X25519PrivateKey.generate()
    shared_secret, enc = _hpke.dhkem_encap(private.public_key())
    assert _hpke.dhkem_decap(enc, private) == shared_secret


# --- passkey-local ---------------------------------------------------------

def test_passkey_round_trip():
    container = _make_file(b"the payload")
    assert open_tlock_passkey(container, prf_output=PRF_OUTPUT, recipient_id="alice") == b"the payload"


def test_wrong_prf_output_is_rejected():
    container = _make_file()
    with pytest.raises(TlockAuthenticationError):
        open_tlock_passkey(container, prf_output=bytes(32), recipient_id="alice")


def test_unknown_recipient_is_rejected():
    container = _make_file()
    with pytest.raises(TlockFormatError):
        open_tlock_passkey(container, prf_output=PRF_OUTPUT, recipient_id="bob")


def test_tampered_payload_is_rejected():
    container = bytearray(_make_file())
    container[-1] ^= 0xFF
    with pytest.raises(TlockAuthenticationError):
        open_tlock_passkey(bytes(container), prf_output=PRF_OUTPUT, recipient_id="alice")


def test_tampered_header_is_rejected():
    container = bytearray(_make_file())
    index = container.find(b'"format"')
    container[index + 8] = ord("X")
    with pytest.raises((TlockAuthenticationError, TlockFormatError, TlockValidationError)):
        open_tlock_passkey(bytes(container), prf_output=PRF_OUTPUT, recipient_id="alice")


def test_envelope_binds_recipient_and_file():
    content_key = bytes(range(32))
    envelope = wrap_recipient_key(
        content_key,
        prf_output=PRF_OUTPUT,
        recipient_id="alice",
        credential_id_hash=CREDENTIAL_HASH,
        file_id="f" * 32,
        policy_id="policy-1",
    )
    recovered = unwrap_recipient_key(
        envelope,
        prf_output=PRF_OUTPUT,
        recipient_id="alice",
        file_id="f" * 32,
        policy_id="policy-1",
    )
    assert recovered == content_key
    with pytest.raises(TlockAuthenticationError):
        unwrap_recipient_key(
            envelope,
            prf_output=PRF_OUTPUT,
            recipient_id="mallory",
            file_id="f" * 32,
            policy_id="policy-1",
        )
    with pytest.raises(TlockAuthenticationError):
        unwrap_recipient_key(
            envelope,
            prf_output=PRF_OUTPUT,
            recipient_id="alice",
            file_id="f" * 32,
            policy_id="policy-2",
        )


def test_prf_output_is_never_stored():
    container = _make_file()
    assert PRF_OUTPUT not in container


def test_envelope_lengths_match_the_spec():
    container = _make_file()
    header = inspect_tlock(container)
    envelope = header["key_access"]
    assert isinstance(envelope, dict)
    # The summary hides envelope internals; read the raw header back instead.
    raw = container[len(MAGIC) + 4 :]
    length = struct.unpack(">I", container[len(MAGIC) : len(MAGIC) + 4])[0]
    document = loads_strict(container[len(MAGIC) + 4 : len(MAGIC) + 4 + length], "header")
    envelopes = document["key_access"]["recipient_envelopes"]
    assert len(envelopes) == 1
    assert len(envelopes[0]["prf_salt"]) == 43  # 32 bytes base64url
    assert len(envelopes[0]["wrap_nonce"]) == 16  # 12 bytes base64url
    assert len(envelopes[0]["wrapped_key"]) == 64  # 48 bytes base64url
    assert raw


# --- container validation --------------------------------------------------

def test_valid_file_has_no_errors():
    assert validate_tlock(_make_file()) == []


def test_invalid_magic_is_rejected():
    container = bytearray(_make_file())
    container[0:1] = b"X"
    errors = validate_tlock(bytes(container))
    assert errors and "magic" in errors[0].lower()


def test_trailing_bytes_are_rejected():
    container = _make_file() + b"extra"
    errors = validate_tlock(container)
    assert errors


def test_truncated_file_is_rejected():
    container = _make_file()
    errors = validate_tlock(container[:-5])
    assert errors


def test_duplicate_json_keys_in_header_are_rejected():
    raw = b'{"format":"tlock","format":"tlock"}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    errors = validate_tlock(container)
    assert errors


def test_non_canonical_header_is_rejected():
    raw = b'{"format": "tlock"}'
    container = MAGIC + struct.pack(">I", len(raw)) + raw
    errors = validate_tlock(container)
    assert errors and "canonical" in errors[0].lower()


def test_payload_digest_mismatch_is_detected():
    """A container whose header claims the wrong digest must be rejected.

    The header is the AEAD associated data, so the forged header is also
    re-encrypted here; otherwise the GCM tag would fail first and the
    digest check would never be reached.
    """
    content_key = bytes(range(32))
    payload = b"payload"
    container = create_tlock(
        payload,
        policy={"enforcement": "server", "policy_id": "p"},
        key_access={
            "mode": "server",
            "service_origin": "https://keys.example.com",
            "key_id": "k1",
        },
        content_key=content_key,
    )
    header = _read_header(container)
    header["payload_sha256"] = "0" * 64
    header_raw = canonical_json(header)
    aad = MAGIC + struct.pack(">I", len(header_raw)) + header_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = _b64_decode(header["nonce"])
    ciphertext = AESGCM(content_key).encrypt(nonce, payload, aad)
    forged = aad + ciphertext

    errors = validate_tlock(forged)
    assert errors == []  # structurally valid; the digest can only be checked with the key
    with pytest.raises(TlockAuthenticationError):
        read_tlock(forged, content_key)


def _b64_decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_passkey_mode_requires_advisory_enforcement():
    with pytest.raises(TlockValidationError):
        create_tlock(
            b"x",
            policy={"enforcement": "server", "policy_id": "p"},
            key_access=_key_access(),
        )


def test_server_mode_requires_server_enforcement():
    with pytest.raises(TlockValidationError):
        create_tlock(
            b"x",
            policy={"enforcement": "advisory-local", "policy_id": "p"},
            key_access={
                "mode": "server",
                "service_origin": "https://keys.example.com",
                "key_id": "k1",
            },
        )


def test_server_mode_creates_a_container():
    container = create_tlock(
        b"x",
        policy={"enforcement": "server", "policy_id": "p"},
        key_access={
            "mode": "server",
            "service_origin": "https://keys.example.com",
            "key_id": "k1",
        },
    )
    assert validate_tlock(container) == []
    header = inspect_tlock(container)
    assert header["key_access"]["grant_protocol"] == GRANT_PROTOCOL


def test_non_https_service_origin_is_rejected():
    with pytest.raises(TlockValidationError):
        create_tlock(
            b"x",
            policy={"enforcement": "server", "policy_id": "p"},
            key_access={
                "mode": "server",
                "service_origin": "http://keys.example.com",
                "key_id": "k1",
            },
        )


def _read_header(container: bytes) -> dict:
    length = struct.unpack(">I", container[len(MAGIC) : len(MAGIC) + 4])[0]
    return json.loads(container[len(MAGIC) + 4 : len(MAGIC) + 4 + length].decode("utf-8"))


# --- policy ----------------------------------------------------------------

def test_policy_expired_is_reported():
    container = create_tlock(
        b"x",
        policy={
            "enforcement": "advisory-local",
            "policy_id": "policy-1",
            "expires_at": "2020-01-01T00:00:00Z",
        },
        key_access=_key_access(),
    )
    header = _read_header(container)
    problems = check_policy(header, now="2099-01-01T00:00:00Z")
    assert any("expired" in problem for problem in problems)


def test_policy_not_yet_valid_is_reported():
    container = create_tlock(
        b"x",
        policy={
            "enforcement": "advisory-local",
            "policy_id": "policy-1",
            "not_before": "2099-01-01T00:00:00Z",
        },
        key_access=_key_access(),
    )
    header = _read_header(container)
    problems = check_policy(header, now="2020-01-01T00:00:00Z")
    assert any("not valid before" in problem for problem in problems)


def test_policy_check_is_always_advisory():
    container = create_tlock(
        b"x",
        policy={
            "enforcement": "advisory-local",
            "policy_id": "policy-1",
            "expires_at": "2020-01-01T00:00:00Z",
        },
        key_access=_key_access(),
    )
    header = _read_header(container)
    problems = check_policy(header, now="2099-01-01T00:00:00Z")
    assert any("advisory" in problem for problem in problems)


def test_policy_without_expiry_reports_no_problem():
    container = _make_file()
    header = _read_header(container)
    assert check_policy(header, now="2099-01-01T00:00:00Z") == []


# --- server-mode grant client ---------------------------------------------

def _build_grant(
    *,
    content_key: bytes,
    file_id: str,
    policy_id: str,
    recipient_id: str,
    signing_key: Ed25519PrivateKey,
    counter: int = 1,
    expires_at: str = "2099-01-01T00:00:00Z",
    grant_nonce: str = "n" * 32,
) -> tuple[dict, X25519PrivateKey]:
    """Act as the key service: encapsulate to the client and sign the grant."""
    ephemeral_client = X25519PrivateKey.generate()
    server_private = X25519PrivateKey.generate()
    dh = server_private.exchange(ephemeral_client.public_key())
    enc = server_private.public_key().public_bytes_raw()
    kem_context = enc + ephemeral_client.public_key().public_bytes_raw()
    shared_secret = _hpke._dhkem_extract_and_expand(dh, kem_context)
    aad = canonical_json(
        {
            "file_id": file_id,
            "grant_nonce": grant_nonce,
            "policy_id": policy_id,
            "recipient_id": recipient_id,
        }
    )
    envelope = _hpke.seal(shared_secret, HPKE_INFO, aad, content_key)
    signed = {
        "file_id": file_id,
        "policy_id": policy_id,
        "recipient_id": recipient_id,
        "counter": counter,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": expires_at,
        "grant_nonce": grant_nonce,
        "enc": _b64(enc),
        "wrapped_content_key": _b64(envelope),
    }
    signed["signature"] = _b64(signing_key.sign(canonical_json(signed)))
    return signed, ephemeral_client


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_server_mode_open_round_trip():
    signing_key = Ed25519PrivateKey.generate()
    signing_public = signing_key.public_key().public_bytes_raw()
    content_key = bytes(range(32))
    file_id = "file-id-0123456789abcdef"
    container = create_tlock(
        b"server payload",
        policy={"enforcement": "server", "policy_id": "policy-1"},
        key_access={
            "mode": "server",
            "service_origin": "https://keys.example.com",
            "key_id": "k1",
        },
        file_id=file_id,
        content_key=content_key,
    )
    grant, ephemeral_client = _build_grant(
        content_key=content_key,
        file_id=file_id,
        policy_id="policy-1",
        recipient_id="alice",
        signing_key=signing_key,
    )
    payload = open_tlock_server(
        container,
        grant=grant,
        ephemeral_private_key=ephemeral_client,
        server_signing_public_key=signing_public,
        recipient_id="alice",
    )
    assert payload == b"server payload"


def test_grant_with_bad_signature_is_rejected():
    signing_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    content_key = bytes(range(32))
    file_id = "file-id-0123456789abcdef"
    container = create_tlock(
        b"server payload",
        policy={"enforcement": "server", "policy_id": "policy-1"},
        key_access={
            "mode": "server",
            "service_origin": "https://keys.example.com",
            "key_id": "k1",
        },
        file_id=file_id,
        content_key=content_key,
    )
    grant, ephemeral_client = _build_grant(
        content_key=content_key,
        file_id=file_id,
        policy_id="policy-1",
        recipient_id="alice",
        signing_key=signing_key,
    )
    with pytest.raises(TlockAuthenticationError):
        open_tlock_server(
            container,
            grant=grant,
            ephemeral_private_key=ephemeral_client,
            server_signing_public_key=other_key.public_key().public_bytes_raw(),
            recipient_id="alice",
        )


def test_grant_bound_to_another_file_is_rejected():
    signing_key = Ed25519PrivateKey.generate()
    content_key = bytes(range(32))
    grant, _client = _build_grant(
        content_key=content_key,
        file_id="other-file-id-0123456789",
        policy_id="policy-1",
        recipient_id="alice",
        signing_key=signing_key,
    )
    with pytest.raises(TlockAuthenticationError):
        verify_grant(
            grant,
            server_signing_public_key=signing_key.public_key().public_bytes_raw(),
            expected_file_id="file-id-0123456789abcdef",
            expected_policy_id="policy-1",
            expected_recipient_id="alice",
        )


def test_expired_grant_is_rejected():
    signing_key = Ed25519PrivateKey.generate()
    content_key = bytes(range(32))
    grant, _client = _build_grant(
        content_key=content_key,
        file_id="file-id-0123456789abcdef",
        policy_id="policy-1",
        recipient_id="alice",
        signing_key=signing_key,
        expires_at="2020-01-01T00:00:00Z",
    )
    with pytest.raises(TlockPolicyError):
        verify_grant(
            grant,
            server_signing_public_key=signing_key.public_key().public_bytes_raw(),
            expected_file_id="file-id-0123456789abcdef",
            expected_policy_id="policy-1",
            expected_recipient_id="alice",
            now="2026-01-01T00:00:00Z",
        )


def test_grant_for_another_recipient_is_rejected():
    signing_key = Ed25519PrivateKey.generate()
    content_key = bytes(range(32))
    grant, _client = _build_grant(
        content_key=content_key,
        file_id="file-id-0123456789abcdef",
        policy_id="policy-1",
        recipient_id="mallory",
        signing_key=signing_key,
    )
    with pytest.raises(TlockAuthenticationError):
        verify_grant(
            grant,
            server_signing_public_key=signing_key.public_key().public_bytes_raw(),
            expected_file_id="file-id-0123456789abcdef",
            expected_policy_id="policy-1",
            expected_recipient_id="alice",
        )


def test_tampered_grant_body_is_rejected():
    signing_key = Ed25519PrivateKey.generate()
    content_key = bytes(range(32))
    grant, _client = _build_grant(
        content_key=content_key,
        file_id="file-id-0123456789abcdef",
        policy_id="policy-1",
        recipient_id="alice",
        signing_key=signing_key,
    )
    grant["counter"] = 99
    with pytest.raises(TlockAuthenticationError):
        verify_grant(
            grant,
            server_signing_public_key=signing_key.public_key().public_bytes_raw(),
            expected_file_id="file-id-0123456789abcdef",
            expected_policy_id="policy-1",
            expected_recipient_id="alice",
        )


def test_read_tlock_rejects_wrong_key():
    container = _make_file()
    with pytest.raises(TlockAuthenticationError):
        read_tlock(container, bytes(32))


def test_format_version_is_pinned():
    container = _make_file()
    header = _read_header(container)
    assert header["format_version"] == FORMAT_VERSION
    assert header["cipher"] == "AES-256-GCM"
    assert len(header["payload_sha256"]) == 64
    assert hashlib.sha256(b"secret contents").hexdigest() == header["payload_sha256"]
