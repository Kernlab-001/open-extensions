"""TLOCK v0.1 reference implementation.

``.tlock`` is an encrypted container that carries access-policy metadata:
not-before time, expiry time, an authorized recipient, and an optional
maximum number of successful opens. It is intended for controlled sharing,
not DRM, and not as a guarantee that an already-decrypted copy can be
recalled.

Two key-access profiles exist in v0.1:

``passkey-local``
    The content key is wrapped per recipient under a key derived from a
    WebAuthn PRF extension output. The expiry and open counter are
    **advisory only**: the recipient controls the device and can bypass the
    local policy code after obtaining the key.

``server``
    The content key is held by a trusted key-release service. The service
    enforces expiry and the open counter with its own clock and durable
    counters, and returns a signed grant. Even here, a recipient who obtains
    the content key can keep it or copy the plaintext, so a previously
    decrypted copy can never be revoked.

Implementation notes
--------------------
* The HPKE construction used by the ``server`` profile follows RFC 9180 in
  ``mode_base`` with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
  AES-256-GCM. It is validated against the RFC's own test vectors.
* The client-side grant protocol below is **provisional**. The specification
  lists "publish canonical request/response schemas and test vectors for the
  server grant protocol" as a release blocker, so the request and response
  shapes implemented here are this implementation's interpretation of the
  specification text and may change before v1.0.
* A WebAuthn ceremony cannot be performed from a command line. The
  ``passkey-local`` profile therefore takes the 32-byte PRF output as an
  input; in production it comes from the authenticator, not from the
  command line.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import urllib.error
import urllib.request
import uuid
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from . import _hpke
from ._container import (
    ContainerError,
    FormatError,
    ValidationError,
    b64url_decode,
    b64url_encode,
    canonical_json,
    parse_canonical_body,
    read_length_prefixed,
    read_source,
    schema_errors,
    timestamp_is_valid,
    utc_now,
)

MAGIC = b"TLOCK\r\n\x1a\n"  # 9 bytes
FORMAT_VERSION = "0.1.0"
GRANT_PROTOCOL = "open-extensions-tlock-grant-0.1"

# RFC 9180 "info" string for the content-key release.
HPKE_INFO = b"Open Extensions TLOCK 0.1 content-key-release"
# Key-wrap "info" prefix for the passkey-local envelope.
KEY_WRAP_INFO = b"Open Extensions TLOCK 0.1 key-wrap"

MAX_HEADER_LENGTH = 64 * 1024
MAX_PAYLOAD_LENGTH = 1024 * 1024 * 1024  # 1 GiB

CONTENT_KEY_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16
PRF_OUTPUT_LENGTH = 32
PRF_SALT_LENGTH = 32
WRAP_NONCE_LENGTH = 12
WRAPPED_KEY_LENGTH = CONTENT_KEY_LENGTH + TAG_LENGTH

MODE_SERVER = "server"
MODE_PASSKEY = "passkey-local"
ENFORCEMENT_SERVER = "server"
ENFORCEMENT_ADVISORY = "advisory-local"

_GRANT_SIGNED_FIELDS = (
    "file_id",
    "policy_id",
    "recipient_id",
    "counter",
    "issued_at",
    "expires_at",
    "grant_nonce",
    "enc",
    "wrapped_content_key",
)


class TlockError(ContainerError):
    """Base class for TLOCK errors."""


class TlockFormatError(TlockError, FormatError):
    """The container framing or header is invalid or unsupported."""


class TlockAuthenticationError(TlockError):
    """The key is wrong or authenticated data has been modified."""


class TlockPolicyError(TlockError):
    """The file's access policy forbids the requested operation."""


class TlockValidationError(TlockError):
    """The container does not satisfy the v0.1 data model."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# --- key wrapping ----------------------------------------------------------

def _key_wrap_info(file_id: str, recipient_id: str) -> bytes:
    return KEY_WRAP_INFO + b"\x00" + file_id.encode("utf-8") + b"\x00" + recipient_id.encode("utf-8")


def _key_wrap_aad(file_id: str, recipient_id: str, credential_id_hash: str, policy_id: str) -> bytes:
    return canonical_json(
        {
            "credential_id_hash": credential_id_hash,
            "file_id": file_id,
            "format": "tlock",
            "format_version": FORMAT_VERSION,
            "policy_id": policy_id,
            "recipient_id": recipient_id,
        }
    )


def wrap_recipient_key(
    content_key: bytes,
    *,
    prf_output: bytes,
    recipient_id: str,
    credential_id_hash: str,
    file_id: str,
    policy_id: str,
) -> dict[str, Any]:
    """Wrap a content key for one recipient using a WebAuthn PRF output.

    ``prf_output`` is the 32-byte output of the authenticator's PRF
    extension. It is never stored in the file.
    """
    if len(content_key) != CONTENT_KEY_LENGTH:
        raise TlockFormatError("Content key must be 32 bytes")
    if len(prf_output) != PRF_OUTPUT_LENGTH:
        raise TlockFormatError("PRF output must be 32 bytes")
    prf_salt = os.urandom(PRF_SALT_LENGTH)
    wrap_nonce = os.urandom(WRAP_NONCE_LENGTH)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=CONTENT_KEY_LENGTH,
        salt=prf_salt,
        info=_key_wrap_info(file_id, recipient_id),
    ).derive(prf_output)
    aad = _key_wrap_aad(file_id, recipient_id, credential_id_hash, policy_id)
    wrapped = AESGCM(wrapping_key).encrypt(wrap_nonce, content_key, aad)
    if len(wrapped) != WRAPPED_KEY_LENGTH:
        raise TlockError("Internal error: unexpected wrapped key length")
    return {
        "recipient_id": recipient_id,
        "credential_id_hash": credential_id_hash,
        "prf_salt": b64url_encode(prf_salt),
        "wrap_nonce": b64url_encode(wrap_nonce),
        "wrapped_key": b64url_encode(wrapped),
    }


def unwrap_recipient_key(
    envelope: Mapping[str, Any],
    *,
    prf_output: bytes,
    recipient_id: str,
    file_id: str,
    policy_id: str,
) -> bytes:
    """Recover a content key from a recipient envelope."""
    if len(prf_output) != PRF_OUTPUT_LENGTH:
        raise TlockFormatError("PRF output must be 32 bytes")
    prf_salt = b64url_decode(envelope.get("prf_salt"), "prf_salt", PRF_SALT_LENGTH)
    wrap_nonce = b64url_decode(envelope.get("wrap_nonce"), "wrap_nonce", WRAP_NONCE_LENGTH)
    wrapped = b64url_decode(envelope.get("wrapped_key"), "wrapped_key", WRAPPED_KEY_LENGTH)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=CONTENT_KEY_LENGTH,
        salt=prf_salt,
        info=_key_wrap_info(file_id, recipient_id),
    ).derive(prf_output)
    aad = _key_wrap_aad(file_id, recipient_id, envelope.get("credential_id_hash"), policy_id)
    try:
        return AESGCM(wrapping_key).decrypt(wrap_nonce, wrapped, aad)
    except InvalidTag as exc:
        raise TlockAuthenticationError(
            "Recipient key unwrap failed: wrong PRF output or modified file"
        ) from exc


# --- container -------------------------------------------------------------

def _parse_container(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    """Return (header, header_bytes, ciphertext, aad)."""
    raw = read_source(source, MAX_HEADER_LENGTH + MAX_PAYLOAD_LENGTH + TAG_LENGTH, "TLOCK file")
    try:
        header_raw, body_start = read_length_prefixed(
            raw,
            MAGIC,
            prefix_size=4,
            min_length=2,
            max_length=MAX_HEADER_LENGTH,
            label="TLOCK header",
        )
        header = parse_canonical_body(header_raw, "TLOCK header")
    except FormatError as exc:
        raise TlockFormatError(str(exc)) from exc
    ciphertext = raw[body_start:]
    aad = raw[:body_start]
    return header, header_raw, ciphertext, aad


def _validate_header(header: Mapping[str, Any]) -> list[str]:
    """Semantic validation of the header, in addition to the JSON Schema."""
    errors: list[str] = []
    errors.extend(schema_errors("tlock", header))

    if header.get("format") != "tlock":
        errors.append("format must equal 'tlock'")
    if header.get("format_version") != FORMAT_VERSION:
        errors.append(f"format_version must equal {FORMAT_VERSION}")
    if header.get("cipher") != "AES-256-GCM":
        errors.append("cipher must equal 'AES-256-GCM'")
    if not timestamp_is_valid(header.get("created_at")):
        errors.append("created_at must be an RFC 3339 UTC timestamp ending in Z")

    file_id = header.get("file_id")
    if not isinstance(file_id, str) or not (16 <= len(file_id) <= 128):
        errors.append("file_id must be a string of 16 to 128 characters")

    media_type = header.get("payload_media_type")
    if not isinstance(media_type, str) or not media_type:
        errors.append("payload_media_type must be a non-empty string")

    digest = header.get("payload_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        errors.append("payload_sha256 must be a lowercase hexadecimal SHA-256 digest")

    try:
        b64url_decode(header.get("nonce"), "nonce", NONCE_LENGTH)
    except FormatError as exc:
        errors.append(str(exc))

    length = header.get("ciphertext_length")
    if isinstance(length, bool) or not isinstance(length, int) or length < TAG_LENGTH + 1:
        errors.append("ciphertext_length must be an integer of at least 17")

    policy = header.get("policy")
    if not isinstance(policy, dict):
        errors.append("policy must be an object")
    else:
        enforcement = policy.get("enforcement")
        if enforcement not in (ENFORCEMENT_SERVER, ENFORCEMENT_ADVISORY):
            errors.append("policy.enforcement must be 'server' or 'advisory-local'")
        policy_id = policy.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id:
            errors.append("policy.policy_id must be a non-empty string")
        for field in ("not_before", "expires_at"):
            if field in policy and not timestamp_is_valid(policy.get(field)):
                errors.append(f"policy.{field} must be an RFC 3339 UTC timestamp ending in Z")
        if "not_before" in policy and "expires_at" in policy:
            if policy["not_before"] > policy["expires_at"]:
                errors.append("policy.not_before must not be later than policy.expires_at")
        max_opens = policy.get("max_authorized_opens")
        if max_opens is not None:
            if isinstance(max_opens, bool) or not isinstance(max_opens, int) or max_opens < 1:
                errors.append("policy.max_authorized_opens must be a positive integer")

    key_access = header.get("key_access")
    if not isinstance(key_access, dict):
        errors.append("key_access must be an object")
    else:
        mode = key_access.get("mode")
        if mode == MODE_SERVER:
            if enforcement_is(policy, ENFORCEMENT_ADVISORY):
                errors.append("policy.enforcement must be 'server' when key_access.mode is 'server'")
            origin = key_access.get("service_origin")
            if not isinstance(origin, str) or not origin.startswith("https://") or "/" in origin[len("https://"):]:
                errors.append("key_access.service_origin must be an https origin without a path")
            if not isinstance(key_access.get("key_id"), str) or not key_access.get("key_id"):
                errors.append("key_access.key_id must be a non-empty string")
            if key_access.get("grant_protocol") != GRANT_PROTOCOL:
                errors.append(f"key_access.grant_protocol must equal {GRANT_PROTOCOL}")
        elif mode == MODE_PASSKEY:
            if enforcement_is(policy, ENFORCEMENT_SERVER):
                errors.append(
                    "policy.enforcement must be 'advisory-local' when key_access.mode is 'passkey-local'"
                )
            envelopes = key_access.get("recipient_envelopes")
            if not isinstance(envelopes, list) or not envelopes:
                errors.append("key_access.recipient_envelopes must be a non-empty array")
            else:
                seen: set[str] = set()
                for index, envelope in enumerate(envelopes):
                    prefix = f"key_access.recipient_envelopes[{index}]"
                    if not isinstance(envelope, dict):
                        errors.append(f"{prefix} must be an object")
                        continue
                    recipient_id = envelope.get("recipient_id")
                    if not isinstance(recipient_id, str) or not recipient_id:
                        errors.append(f"{prefix}.recipient_id must be a non-empty string")
                    elif recipient_id in seen:
                        errors.append(f"{prefix}.recipient_id must be unique")
                    else:
                        seen.add(recipient_id)
                    for field, expected_length in (
                        ("credential_id_hash", 32),
                        ("prf_salt", PRF_SALT_LENGTH),
                        ("wrap_nonce", WRAP_NONCE_LENGTH),
                        ("wrapped_key", WRAPPED_KEY_LENGTH),
                    ):
                        try:
                            b64url_decode(envelope.get(field), f"{prefix}.{field}", expected_length)
                        except FormatError as exc:
                            errors.append(str(exc))
        else:
            errors.append("key_access.mode must be 'server' or 'passkey-local'")
    return errors


def enforcement_is(policy: Any, expected: str) -> bool:
    """Return True when the policy declares the given enforcement mode."""
    return isinstance(policy, dict) and policy.get("enforcement") == expected


def create_tlock(
    payload: bytes,
    *,
    policy: Mapping[str, Any],
    key_access: Mapping[str, Any],
    payload_media_type: str = "application/octet-stream",
    file_id: str | None = None,
    content_key: bytes | None = None,
) -> bytes:
    """Create a TLOCK container and return its bytes.

    ``key_access`` selects the profile:

    * ``{"mode": "server", "service_origin": ..., "key_id": ...}``
    * ``{"mode": "passkey-local", "recipients": [{"recipient_id": ...,
      "credential_id_hash": ..., "prf_output": b"<32 bytes>"}, ...]}``

    The ``server`` profile requires the caller to register ``content_key``
    with the key service. When ``content_key`` is omitted a fresh key is
    generated; in the ``passkey-local`` profile it never leaves the process.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) > MAX_PAYLOAD_LENGTH:
        raise TlockFormatError("Payload exceeds the v0.1 maximum size")

    mode = key_access.get("mode")
    if mode not in (MODE_SERVER, MODE_PASSKEY):
        raise TlockFormatError("key_access.mode must be 'server' or 'passkey-local'")

    if content_key is None:
        content_key = os.urandom(CONTENT_KEY_LENGTH)
    if len(content_key) != CONTENT_KEY_LENGTH:
        raise TlockFormatError("Content key must be 32 bytes")

    resolved_file_id = file_id or uuid.uuid4().hex
    if not (16 <= len(resolved_file_id) <= 128):
        raise TlockFormatError("file_id must be between 16 and 128 characters")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        raise TlockFormatError("policy.policy_id must be a non-empty string")

    if mode == MODE_SERVER:
        resolved_key_access = {
            "mode": MODE_SERVER,
            "service_origin": key_access.get("service_origin"),
            "key_id": key_access.get("key_id"),
            "grant_protocol": GRANT_PROTOCOL,
        }
    else:
        recipients = key_access.get("recipients")
        if not isinstance(recipients, list) or not recipients:
            raise TlockFormatError("key_access.recipients must be a non-empty array")
        envelopes = []
        for recipient in recipients:
            if not isinstance(recipient, Mapping):
                raise TlockFormatError("Each recipient must be an object")
            envelopes.append(
                wrap_recipient_key(
                    content_key,
                    prf_output=recipient.get("prf_output"),
                    recipient_id=recipient.get("recipient_id"),
                    credential_id_hash=recipient.get("credential_id_hash"),
                    file_id=resolved_file_id,
                    policy_id=policy_id,
                )
            )
        resolved_key_access = {
            "mode": MODE_PASSKEY,
            "recipient_envelopes": envelopes,
        }

    header: dict[str, Any] = {
        "format": "tlock",
        "format_version": FORMAT_VERSION,
        "file_id": resolved_file_id,
        "created_at": utc_now(),
        "cipher": "AES-256-GCM",
        "nonce": b64url_encode(os.urandom(NONCE_LENGTH)),
        "ciphertext_length": len(payload) + TAG_LENGTH,
        "payload_media_type": payload_media_type,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "policy": dict(policy),
        "key_access": resolved_key_access,
    }
    errors = _validate_header(header)
    if errors:
        raise TlockValidationError(errors)

    header_raw = canonical_json(header)
    if len(header_raw) > MAX_HEADER_LENGTH:
        raise TlockFormatError("Generated header exceeds the v0.1 maximum")
    prefix = MAGIC + struct.pack(">I", len(header_raw))
    aad = prefix + header_raw
    nonce = b64url_decode(header["nonce"], "nonce", NONCE_LENGTH)
    ciphertext = AESGCM(content_key).encrypt(nonce, payload, aad)
    if len(ciphertext) != header["ciphertext_length"]:
        raise TlockError("Internal error: unexpected AES-GCM output length")
    return aad + ciphertext


def read_tlock(source: bytes | bytearray | memoryview | str | os.PathLike[str], content_key: bytes) -> bytes:
    """Authenticate, decrypt and return the payload bytes."""
    header, _header_raw, ciphertext, aad = _parse_container(source)
    errors = _validate_header(header)
    if errors:
        raise TlockValidationError(errors)
    if len(ciphertext) != header["ciphertext_length"]:
        raise TlockFormatError("ciphertext_length does not match the actual container size")
    nonce = b64url_decode(header["nonce"], "nonce", NONCE_LENGTH)
    try:
        payload = AESGCM(content_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise TlockAuthenticationError("Authentication failed: wrong key or modified file") from exc
    if hashlib.sha256(payload).hexdigest() != header["payload_sha256"]:
        raise TlockAuthenticationError("Decrypted payload digest does not match the header")
    return payload


def open_tlock_passkey(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    prf_output: bytes,
    recipient_id: str,
) -> bytes:
    """Open a passkey-local TLOCK file using a WebAuthn PRF output."""
    header, _header_raw, _ciphertext, _aad = _parse_container(source)
    errors = _validate_header(header)
    if errors:
        raise TlockValidationError(errors)
    key_access = header["key_access"]
    if key_access.get("mode") != MODE_PASSKEY:
        raise TlockFormatError("File does not use the passkey-local profile")
    envelopes = key_access.get("recipient_envelopes", [])
    envelope = next((e for e in envelopes if e.get("recipient_id") == recipient_id), None)
    if envelope is None:
        raise TlockFormatError(f"No recipient envelope for {recipient_id!r}")
    content_key = unwrap_recipient_key(
        envelope,
        prf_output=prf_output,
        recipient_id=recipient_id,
        file_id=header["file_id"],
        policy_id=header["policy"]["policy_id"],
    )
    return read_tlock(source, content_key)


def validate_tlock(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> list[str]:
    """Return validation errors for a TLOCK container.

    This checks framing, the header profile and the length fields. It cannot
    decrypt or authenticate the payload without a key.
    """
    try:
        header, _header_raw, ciphertext, _aad = _parse_container(source)
        errors = _validate_header(header)
        if errors:
            return errors
        if len(ciphertext) != header["ciphertext_length"]:
            return ["ciphertext_length does not match the actual container size"]
        return []
    except ContainerError as exc:
        if isinstance(exc, ValidationError):
            return list(exc.errors)
        return [str(exc)]


def inspect_tlock(source: bytes | bytearray | memoryview | str | os.PathLike[str]) -> dict[str, Any]:
    """Return the unauthenticated, non-secret header for inspection.

    The header is authenticated by the AEAD but is not encrypted, so it is
    visible to anyone holding the file. Policy metadata is therefore
    observable.
    """
    header, _header_raw, _ciphertext, _aad = _parse_container(source)
    summary = dict(header)
    key_access = summary.get("key_access")
    if isinstance(key_access, dict) and key_access.get("mode") == MODE_PASSKEY:
        envelopes = key_access.get("recipient_envelopes", [])
        summary["key_access"] = {
            "mode": MODE_PASSKEY,
            "recipient_ids": [e.get("recipient_id") for e in envelopes if isinstance(e, dict)],
        }
    summary["enforcement_note"] = (
        "Offline policy checks are advisory; a recipient who controls the device can bypass them."
    )
    return summary


def check_policy(header: Mapping[str, Any], *, now: str | None = None) -> list[str]:
    """Return the policy problems that apply to the current time.

    The checks are advisory. They cannot enforce anything against a recipient
    who controls the device or can roll back the clock.
    """
    problems: list[str] = []
    policy = header.get("policy")
    if not isinstance(policy, dict):
        return ["policy is missing"]
    moment = now or utc_now()
    if not timestamp_is_valid(moment):
        problems.append("current time is not a valid UTC timestamp")
        return problems
    not_before = policy.get("not_before")
    expires_at = policy.get("expires_at")
    if isinstance(not_before, str) and moment < not_before:
        problems.append(f"file is not valid before {not_before}")
    if isinstance(expires_at, str) and moment > expires_at:
        problems.append(f"file expired at {expires_at}")
    if problems:
        problems.append(
            "This is an advisory local check only; the file format cannot enforce expiry."
        )
    return problems


# --- server-mode client ----------------------------------------------------

def build_grant_request(
    *,
    file_id: str,
    policy_id: str,
    recipient_id: str,
    ephemeral_public_key: bytes,
) -> dict[str, Any]:
    """Build the request body for a key-release grant.

    The request shape is provisional: the specification lists publishing the
    canonical grant protocol schemas as a release blocker.
    """
    return {
        "grant_protocol": GRANT_PROTOCOL,
        "file_id": file_id,
        "policy_id": policy_id,
        "recipient_id": recipient_id,
        "ephemeral_public_key": b64url_encode(ephemeral_public_key),
    }


def verify_grant(
    grant: Mapping[str, Any],
    *,
    server_signing_public_key: bytes,
    expected_file_id: str,
    expected_policy_id: str,
    expected_recipient_id: str,
    now: str | None = None,
) -> dict[str, Any]:
    """Verify a signed grant and its bindings, returning the signed fields.

    The signature is a detached Ed25519 signature over the canonical JSON of
    every grant field except ``signature`` itself.
    """
    if not isinstance(grant, Mapping):
        raise TlockFormatError("Grant must be an object")
    signature_b64 = grant.get("signature")
    if not isinstance(signature_b64, str):
        raise TlockFormatError("Grant is missing its signature")
    signature = b64url_decode(signature_b64, "grant.signature", 64)

    signed = {key: value for key, value in grant.items() if key != "signature"}
    missing = [field for field in _GRANT_SIGNED_FIELDS if field not in signed]
    if missing:
        raise TlockFormatError(f"Grant is missing signed field(s): {', '.join(missing)}")

    try:
        Ed25519PublicKey.from_public_bytes(server_signing_public_key).verify(
            signature, canonical_json(signed)
        )
    except (InvalidSignature, ValueError) as exc:
        raise TlockAuthenticationError("Grant signature verification failed") from exc

    if signed["file_id"] != expected_file_id:
        raise TlockAuthenticationError("Grant is bound to a different file")
    if signed["policy_id"] != expected_policy_id:
        raise TlockAuthenticationError("Grant is bound to a different policy")
    if signed["recipient_id"] != expected_recipient_id:
        raise TlockAuthenticationError("Grant is bound to a different recipient")
    if not timestamp_is_valid(signed.get("expires_at")):
        raise TlockFormatError("Grant expires_at must be an RFC 3339 UTC timestamp ending in Z")
    moment = now or utc_now()
    if moment > signed["expires_at"]:
        raise TlockPolicyError("Grant has expired")
    return dict(signed)


def open_grant_envelope(
    grant: Mapping[str, Any],
    *,
    ephemeral_private_key: X25519PrivateKey,
) -> bytes:
    """Open the HPKE envelope in a grant and return the content key.

    ``enc`` carries the RFC 9180 KEM encapsulated key produced by the
    service, and ``wrapped_content_key`` carries the HPKE ciphertext holding
    the content key.
    """
    enc = b64url_decode(grant.get("enc"), "grant.enc", 32)
    envelope = b64url_decode(grant.get("wrapped_content_key"), "grant.wrapped_content_key")

    shared_secret = _hpke.dhkem_decap(enc, ephemeral_private_key)
    aad = canonical_json(
        {
            "file_id": grant.get("file_id"),
            "grant_nonce": grant.get("grant_nonce"),
            "policy_id": grant.get("policy_id"),
            "recipient_id": grant.get("recipient_id"),
        }
    )
    try:
        content_key = _hpke.open_(shared_secret, HPKE_INFO, aad, envelope)
    except _hpke.HpkeError as exc:
        raise TlockAuthenticationError("HPKE envelope could not be opened") from exc
    if len(content_key) != CONTENT_KEY_LENGTH:
        raise TlockAuthenticationError("HPKE envelope did not contain a 32-byte content key")
    return content_key


def open_tlock_server(
    source: bytes | bytearray | memoryview | str | os.PathLike[str],
    *,
    grant: Mapping[str, Any],
    ephemeral_private_key: X25519PrivateKey,
    server_signing_public_key: bytes,
    recipient_id: str,
    now: str | None = None,
) -> bytes:
    """Open a server-mode TLOCK file using a verified grant."""
    header, _header_raw, _ciphertext, _aad = _parse_container(source)
    errors = _validate_header(header)
    if errors:
        raise TlockValidationError(errors)
    signed = verify_grant(
        grant,
        server_signing_public_key=server_signing_public_key,
        expected_file_id=header["file_id"],
        expected_policy_id=header["policy"]["policy_id"],
        expected_recipient_id=recipient_id,
        now=now,
    )
    content_key = open_grant_envelope(signed, ephemeral_private_key=ephemeral_private_key)
    return read_tlock(source, content_key)


def register_content_key(
    *,
    service_origin: str,
    key_id: str,
    content_key: bytes,
    file_id: str,
    policy_id: str,
    timeout: float = 10.0,
) -> None:
    """Register a content key with a key-release service.

    The endpoint shape is provisional for the same reason as the grant
    protocol. The service is responsible for durable storage and for
    enforcing the policy when it later releases the key.
    """
    body = json.dumps(
        {
            "key_id": key_id,
            "content_key": b64url_encode(content_key),
            "file_id": file_id,
            "policy_id": policy_id,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{service_origin.rstrip('/')}/v1/keys",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status not in (200, 201, 204):
                raise TlockError(f"Key service returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise TlockError(f"Cannot reach the key service: {exc.reason}") from exc


def request_grant(
    *,
    service_origin: str,
    file_id: str,
    policy_id: str,
    recipient_id: str,
    ephemeral_public_key: bytes,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Request a signed grant from a key-release service."""
    body = json.dumps(
        build_grant_request(
            file_id=file_id,
            policy_id=policy_id,
            recipient_id=recipient_id,
            ephemeral_public_key=ephemeral_public_key,
        )
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{service_origin.rstrip('/')}/v1/grants",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise TlockError(f"Cannot reach the key service: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise TlockFormatError(f"Key service returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TlockFormatError("Key service returned a non-object grant")
    return payload
