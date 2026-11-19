# Standards and implementation references

These references inform the draft wire formats. Open Extensions itself is not endorsed by these organizations.

## Cryptography

- [RFC 9106 — Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html). Defines Argon2id v1.3 and recommends a 64 MiB, three-pass, four-lane profile as a lower-memory recommendation. MEMX v0.1 adopts that profile for a widely implementable baseline.
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final). AES-GCM is the authenticated-encryption construction used by MEMX and the draft TLOCK payload profile. NIST has announced a revision; implementers should monitor updates.
- [RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869.html). Used in the proposed TLOCK passkey wrapping profile.
- [RFC 9180 — Hybrid Public Key Encryption (HPKE)](https://www.rfc-editor.org/rfc/rfc9180.html). The proposed TLOCK server-mode envelope uses an HPKE suite rather than a custom public-key wrapping protocol.
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/). Defines the WebAuthn PRF extension, which can provide credential-bound pseudorandom output for a key-derivation use case. Platform and authenticator support still needs runtime feature detection.

## Containers and schemas

- [PKWARE ZIP Application Note](https://www.pkware.com/documents/casestudies/APPNOTE.TXT). The draft PODX and WAPP package layouts use ZIP/ZIP64 for asset aggregation with stricter safety rules.
- [JSON Schema Draft 2020-12](https://json-schema.org/specification). Used for machine-readable manifest/payload schemas.
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html). Define normative requirement keywords used by the specifications.

## Runtime security

- [Microsoft WebView2 security guidance](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security). Web content hosted by a native app must be treated as untrusted; the host/runtime is responsible for restricting native capabilities and bridge access.

## Python implementation references

- [argon2-cffi API](https://argon2-cffi.readthedocs.io/en/stable/api.html), including `hash_secret_raw` and `Type.ID`.
- [Python cryptography AESGCM API](https://cryptography.io/en/latest/hazmat/primitives/aead/). Documents authenticated encryption with associated data and AES-GCM usage.

Before a stable 1.0 release, the project should pin specific standards revisions and library compatibility ranges, publish test vectors, and re-check all external references.
