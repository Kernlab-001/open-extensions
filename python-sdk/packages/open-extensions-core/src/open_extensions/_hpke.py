"""Minimal HPKE (RFC 9180) implementation for the TLOCK key-release protocol.

Only the ciphersuite named by the TLOCK v0.1 specification is implemented:
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, in ``mode_base``.

The code follows RFC 9180 literally, including the domain-separation labels
``"HPKE-v1"``, ``"eae_prk"``, ``"shared_secret"``, ``"secret"``, ``"key"``,
``"base_nonce"`` and ``"exp"``. It is checked against the Appendix A test
vectors in ``tests/test_tlock.py``.

No third-party HPKE library is used; only ``cryptography`` primitives.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Algorithm identifiers from RFC 9180 section 7.
KEM_ID = 0x0020  # DHKEM(X25519, HKDF-SHA256)
KDF_ID = 0x0001  # HKDF-SHA256
AEAD_ID_AES128_GCM = 0x0001
AEAD_ID_AES256_GCM = 0x0002

MODE_BASE = 0x00

# "KEM" || I2OSP(kem_id, 2)
KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
# "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
_HPKE_SUITE_PREFIX = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big")

_HASH_LEN = 32  # Nh for HKDF-SHA256
_NSECRET = 32  # Nsecret for DHKEM(X25519, HKDF-SHA256)
_NN = 12  # Nn for AES-GCM
_NT = 16  # Nt for AES-GCM
_AEAD_KEY_LEN = {
    AEAD_ID_AES128_GCM: 16,
    AEAD_ID_AES256_GCM: 32,
}


class HpkeError(Exception):
    """An HPKE operation failed."""


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with HMAC-SHA256.

    An empty salt is equivalent to ``HashLen`` zero bytes because HMAC pads
    a short key with zeros, so the empty salt is normalized here rather than
    being rejected by the HMAC implementation.
    """
    key = salt if salt else b"\x00" * _HASH_LEN
    digest = hmac.HMAC(key, hashes.SHA256())
    digest.update(ikm)
    return digest.finalize()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with HMAC-SHA256."""
    if length > 255 * _HASH_LEN:
        raise HpkeError("HKDF output length is too large")
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        digest = hmac.HMAC(prk, hashes.SHA256())
        digest.update(block + info + bytes([counter]))
        block = digest.finalize()
        output += block
        counter += 1
    return output[:length]


def labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
    """RFC 9180 LabeledExtract."""
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, suite_id: bytes) -> bytes:
    """RFC 9180 LabeledExpand."""
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def _dhkem_extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    """RFC 9180 section 4.1 DHKEM ExtractAndExpand."""
    eae_prk = labeled_extract(b"", b"eae_prk", dh, KEM_SUITE_ID)
    return labeled_expand(eae_prk, b"shared_secret", kem_context, _NSECRET, KEM_SUITE_ID)


def _public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def dhkem_encap(recipient_public_key: X25519PublicKey) -> tuple[bytes, bytes]:
    """Encapsulate to a recipient public key, returning (shared_secret, enc)."""
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    dh = ephemeral_private.exchange(recipient_public_key)
    enc = _public_bytes(ephemeral_public)
    kem_context = enc + _public_bytes(recipient_public_key)
    return _dhkem_extract_and_expand(dh, kem_context), enc


def dhkem_decap(enc: bytes, recipient_private_key: X25519PrivateKey) -> bytes:
    """Decapsulate an encapsulated key, returning the KEM shared secret."""
    if len(enc) != 32:
        raise HpkeError("Encapsulated key must be 32 bytes")
    ephemeral_public = X25519PublicKey.from_public_bytes(enc)
    dh = recipient_private_key.exchange(ephemeral_public)
    kem_context = enc + _public_bytes(recipient_private_key.public_key())
    return _dhkem_extract_and_expand(dh, kem_context)


def key_schedule(
    shared_secret: bytes,
    info: bytes,
    *,
    aead_id: int = AEAD_ID_AES256_GCM,
    psk: bytes = b"",
    psk_id: bytes = b"",
) -> tuple[bytes, bytes, bytes]:
    """RFC 9180 section 5.1 KeySchedule in mode_base.

    Returns ``(key, base_nonce, exporter_secret)``.
    """
    if aead_id not in _AEAD_KEY_LEN:
        raise HpkeError(f"Unsupported AEAD identifier: {aead_id}")
    suite_id = _HPKE_SUITE_PREFIX + aead_id.to_bytes(2, "big")
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", psk_id, suite_id)
    info_hash = labeled_extract(b"", b"info_hash", info, suite_id)
    key_schedule_context = bytes([MODE_BASE]) + psk_id_hash + info_hash
    secret = labeled_extract(shared_secret, b"secret", psk, suite_id)
    key = labeled_expand(secret, b"key", key_schedule_context, _AEAD_KEY_LEN[aead_id], suite_id)
    base_nonce = labeled_expand(secret, b"base_nonce", key_schedule_context, _NN, suite_id)
    exporter_secret = labeled_expand(secret, b"exp", key_schedule_context, _HASH_LEN, suite_id)
    return key, base_nonce, exporter_secret


def _compute_nonce(base_nonce: bytes, seq: int) -> bytes:
    """RFC 9180 section 5.2 ComputeNonce: base_nonce XOR I2OSP(seq, Nn)."""
    if seq < 0:
        raise HpkeError("Sequence number must not be negative")
    padded = seq.to_bytes(len(base_nonce), "big")
    return bytes(a ^ b for a, b in zip(base_nonce, padded))


def seal(
    shared_secret: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
    *,
    aead_id: int = AEAD_ID_AES256_GCM,
) -> bytes:
    """Encrypt a single message with the HPKE base-mode context."""
    key, base_nonce, _ = key_schedule(shared_secret, info, aead_id=aead_id)
    return AESGCM(key).encrypt(_compute_nonce(base_nonce, 0), plaintext, aad)


def open_(
    shared_secret: bytes,
    info: bytes,
    aad: bytes,
    ciphertext: bytes,
    *,
    aead_id: int = AEAD_ID_AES256_GCM,
) -> bytes:
    """Decrypt a single message with the HPKE base-mode context."""
    key, base_nonce, _ = key_schedule(shared_secret, info, aead_id=aead_id)
    try:
        return AESGCM(key).decrypt(_compute_nonce(base_nonce, 0), ciphertext, aad)
    except InvalidTag as exc:
        raise HpkeError("HPKE authentication failed") from exc
