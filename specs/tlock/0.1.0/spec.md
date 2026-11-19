# TLOCK file format specification — 0.1.0

Status: security design draft. No implementation is included. This format is not production-ready until the trust model, key service, and threat model receive independent cryptographic review.

## 1. Purpose and non-goals

`.tlock` is an encrypted container that carries access-policy metadata: not-before time, expiry time, authorized recipient, and an optional maximum successful-open count. It is intended for controlled sharing of files, not DRM or a guarantee that an already-decrypted copy can be recalled.

**Critical boundary:** a file format cannot enforce expiration or a view counter against a recipient who controls the device, can copy the ciphertext/key/plaintext, or can roll back local storage and the clock. Strong expiry and view-count enforcement require online authorization backed by a trusted service and durable counter state. Offline policy checks are explicitly advisory. Even online systems cannot erase a plaintext copy already made by a recipient.

## 2. Container layout

- 9-byte magic: `TLOCK 0D 0A 1A 0A`.
- 4-byte unsigned big-endian header length (2–64 KiB), immediately after the magic.
- Canonical UTF-8 JSON header.
- Remaining bytes: AES-256-GCM ciphertext plus a 16-byte tag.

No trailing bytes are allowed. The exact header bytes including the prefix are associated data for the content encryption. v0.1 payload size is capped at 1 GiB; implementations SHOULD use a streaming AEAD construction in a later version for very large files rather than buffering the entire payload in memory.

## 3. Header model

The header identifies `format`, `format_version`, `file_id`, `created_at`, `cipher`, `nonce`, `ciphertext_length`, `payload_media_type`, `payload_sha256`, `policy`, `key_access`, and optional `extensions`.

### 3.1 Policy

`policy` contains:

- `not_before`: optional UTC timestamp.
- `expires_at`: optional UTC timestamp.
- `max_authorized_opens`: optional positive integer.
- `enforcement`: `server` or `advisory-local`.
- `policy_id`: opaque identifier.

The policy metadata is visible but authenticated by AEAD. Policy timestamps use UTC; local timezone assumptions are forbidden.

### 3.2 Key access profiles

v0.1 defines two explicit modes:

1. **`server`** — the content key is held/wrapped by a trusted key-release service identified by `service_origin` and `key_id`. The service MUST authenticate the recipient, enforce a durable server-side counter and expiry using trusted server time, and issue a short-lived, file-bound key grant. The client MUST verify the service response signature and bind it to the file ID, recipient, policy ID, and a single grant nonce. The service MUST NOT release reusable long-lived plaintext keys to an untrusted client if strict enforcement is claimed. The service is a critical trusted component.
2. **`passkey-local`** — a recipient-specific content-key envelope is wrapped using a key derived from a WebAuthn PRF extension output via HKDF-SHA-256, then authenticated encryption. A PRF input/salt and credential reference are stored in the envelope; the raw PRF output is never stored. Passkey PRF is not supported by all authenticators/browsers. This mode protects local key access but its expiry/open counter is advisory because the recipient can bypass local policy code after obtaining the key.

A passkey is not itself a universal symmetric decryption key. Implementations must perform the WebAuthn ceremony and use a supported PRF result; password fallback is a separate, explicitly declared profile and is not part of v0.1.

## 4. Encryption and key-access profiles

The payload is encrypted with AES-256-GCM using a fresh random 32-byte content key, a fresh 12-byte nonce, and the exact header bytes (including framing prefix) as associated data. `payload_sha256` is the digest of the plaintext bytes and is checked after decryption. `ciphertext_length` counts ciphertext plus the 16-byte GCM tag.

### 4.1 `passkey-local` profile

Each recipient envelope contains `recipient_id`, `credential_id_hash`, `prf_salt`, `wrap_nonce`, and `wrapped_key`. `prf_salt` is 32 random bytes; `wrap_nonce` is 12 random bytes; `wrapped_key` is exactly 48 bytes (32-byte content key plus 16-byte tag), all encoded as unpadded base64url. The implementation performs a WebAuthn authentication ceremony requesting the PRF extension and obtains its 32-byte output. It derives a 32-byte wrapping key using HKDF-SHA-256 with the PRF output as input key material, `prf_salt` as salt, and `info = UTF8("Open Extensions TLOCK 0.1 key-wrap") || 0x00 || UTF8(file_id) || 0x00 || UTF8(recipient_id)`. The wrapping AAD is canonical JSON containing `format`, `format_version`, `file_id`, `recipient_id`, `credential_id_hash`, and `policy_id`. AES-256-GCM wraps the content key using `wrap_nonce` and this AAD. The PRF output MUST NOT be stored in the file. User agents/authenticators may not all support this extension.

In this mode `policy.enforcement` MUST be `advisory-local`. A local counter and clock are useful UX checks but can be altered or rolled back by the device owner; they are not strong policy enforcement.

### 4.2 `server` profile

The server holds the content key in a managed key store under `key_id`. `key_access` contains `service_origin`, `key_id`, and `grant_protocol: "open-extensions-tlock-grant-0.1"`; it does not contain the raw content key. The client generates a one-use ephemeral X25519 key pair and sends the public key with recipient authentication to the HTTPS service. After atomically checking the policy and incrementing the server-side authorization counter, the service returns an HPKE envelope to the ephemeral public key using RFC 9180 suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM. HPKE `info` is UTF-8 `Open Extensions TLOCK 0.1 content-key-release`; HPKE AAD is canonical JSON containing `file_id`, `policy_id`, `recipient_id`, and `grant_nonce`. The response contains a signed grant with `file_id`, `policy_id`, `recipient_id`, `counter`, `issued_at`, `expires_at`, `grant_nonce`, `enc`, and `wrapped_content_key`, plus a detached Ed25519 signature over canonical JSON of the grant fields excluding the signature. The server signing public key MUST be pinned through a separately trusted configuration channel. A client MUST verify the signature, file/policy/recipient binding, grant expiry, and nonce before opening the HPKE envelope.

In this mode `policy.enforcement` MUST be `server`. The service MUST use trusted server time and durable, transactional counters. `max_authorized_opens` counts successful key-release authorizations, not verified human views. A recipient who obtains the content key can retain it or copy plaintext; therefore even server mode cannot revoke a previously decrypted copy or absolutely prevent reuse of an extracted key. Strict policy describes server-controlled key release, not control over information after disclosure.

A passkey is not itself a universal symmetric decryption key. Implementations must perform the WebAuthn ceremony and use a supported PRF result; password fallback is not part of v0.1.

## 5. Build plan

**Encoder:** create a random file ID and content key; encrypt payload; hash plaintext; emit policy and header. For `passkey-local`, create each recipient envelope with the PRF/HKDF/AES-GCM construction. For `server`, register the content key with the selected key service and store only its key ID and service origin in the file.

**Decoder:** parse bounded framing; authenticate the header and payload; enforce the selected policy mode; run WebAuthn PRF or server authorization; verify wrapped-key/grant bindings; decrypt; verify plaintext digest; expose plaintext only after user approval.

**Validator:** schema and framing; ciphertext length; timestamp ordering; policy/key-access consistency; envelope lengths; recipient consistency; Ed25519 grant signature and binding checks; replay and counter tests. A validator without keys may only report structural validity.

**CLI:** `tlock create`, `tlock inspect`, `tlock validate`, `tlock open`, `tlock policy`, with key-service configuration kept outside the file. `open` MUST explain whether the selected policy is server-enforced key release or advisory-local behavior.

## 6. Security release blockers

- Publish canonical request/response schemas and test vectors for the server grant protocol.
- Define key rotation, revocation, recipient changes, passkey credential replacement/loss/sync, and service outage behavior.
- Complete threat modeling and an independent cryptographic review before publishing a stable version.
