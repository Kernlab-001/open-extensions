# MEMX file format specification — 0.1.0

Status: experimental draft; Python reference implementation included in this repository.

## 1. Purpose and threat model

`.memx` is a portable, password-encrypted container for user-controlled AI memory: response preferences, coding profiles, project context, and other explicitly selected context items. It is intended for user-mediated export/import between compatible assistants and local models.

The `.memx` file itself is **not human-readable plaintext**. Only the small container header is readable without a password. After successful decryption, the payload is UTF-8 canonical JSON and is therefore inspectable and portable. A separate unencrypted JSON export is possible but is outside the encrypted `.memx` file.

Threats addressed: offline theft of the file, accidental corruption, undetected ciphertext/header modification, malformed length fields, and oversized decompression. Not addressed: a compromised endpoint, malware that captures a password, weak user passwords, a model provider retaining information after import, or deliberate disclosure by the receiving application.

## 2. Binary layout

All integers are unsigned big-endian unless noted.

| Offset | Length | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | Magic | ASCII `MEMX`, then `0D 0A 1A 0A` |
| 8 | 4 | Header length | `uint32`; 2–16,384 bytes |
| 12 | N | Header | Canonical UTF-8 JSON object |
| 12+N | M | Ciphertext | AES-256-GCM ciphertext followed by 16-byte tag |

There is no footer and no permitted trailing data. `ciphertext_length` in the header MUST equal the exact number of bytes remaining. Maximum decrypted JSON payload is 16 MiB; maximum compressed data is 16 MiB + 64 KiB.

### 2.1 Header schema

The header MUST contain exactly these fields:

| Field | Type | Required value / meaning |
|---|---|---|
| `format` | string | `memx` |
| `format_version` | string | `0.1.0` |
| `cipher` | string | `AES-256-GCM` |
| `compression` | string | `zlib` |
| `payload_type` | string | `application/json; charset=utf-8` |
| `payload_schema` | string | `urn:open-extensions:spec:memx:0.1.0` |
| `created_at` | string | RFC 3339 UTC timestamp ending in `Z` |
| `payload_length` | integer | Length of canonical JSON before compression; 1–16 MiB |
| `ciphertext_length` | integer | Compressed bytes + 16-byte GCM tag |
| `nonce` | base64url string | 12 random bytes; no `=` padding |
| `kdf` | object | The fixed profile below plus a 16-byte salt |

`kdf` MUST contain exactly `algorithm`, `memory_kib`, `parallelism`, `time_cost`, `version`, `key_length`, and `salt`:

```json
{
  "algorithm": "Argon2id",
  "memory_kib": 65536,
  "parallelism": 4,
  "time_cost": 3,
  "version": 19,
  "key_length": 32,
  "salt": "<base64url-encoded 16 random bytes>"
}
```

The fixed profile is intentional: v0.1 readers MUST reject other KDF parameters rather than allowing an untrusted file to demand arbitrary CPU or memory. A future version may add negotiated profiles with explicit resource ceilings.

## 3. Cryptographic construction

1. Serialize the payload using canonical JSON as defined in `common/container-principles.md`.
2. Compress the serialized bytes with zlib/DEFLATE.
3. Generate a fresh 16-byte salt and 12-byte nonce from a cryptographically secure random generator.
4. Derive a 32-byte key with Argon2id v1.3 (`t=3`, `m=65,536 KiB`, `p=4`). The password is its exact UTF-8 byte sequence; v0.1 performs no Unicode normalization. Empty passwords are forbidden. Implementations SHOULD guide users toward long, unique passphrases.
5. Let `AAD` be the exact bytes from the beginning of the file through the end of the header, including magic and the four-byte header-length field.
6. Encrypt the compressed bytes with AES-256-GCM using the derived key, 12-byte nonce, and `AAD`. Store the ciphertext and 16-byte tag together.

The nonce MUST never be reused with the same derived key. Fresh random salt and nonce values MUST be generated for every new file. Header fields are authenticated because they are included in `AAD`; the encrypted payload is authenticated by GCM. No unauthenticated cleartext payload fields are permitted.

## 4. Payload schema

The normative JSON Schema is [schema.json](schema.json). The root object contains:

- `memx_version`: `0.1.0`.
- `exported_at`: UTC timestamp.
- `profiles`: 1–100 user-defined profiles.
- Optional `source`: application/model provenance; not a trust assertion.
- Optional `extensions`: namespaced extension data; never executable.

Each profile contains `id`, `label`, `preferences`, `coding_profiles`, and `context_items`. Context items have stable IDs, one of six kinds (`preference`, `project`, `fact`, `instruction`, `workflow`, `other`), content, update timestamp, and tags. Importers MUST show provenance and allow selective import; importing a `.memx` MUST NOT silently replace or elevate existing system/developer instructions.

## 5. Read, write, and validation behavior

A reader MUST validate framing and limits before KDF work. It MUST reject malformed base64url, unsupported fields/algorithms, a non-canonical header, trailing bytes, incorrect declared lengths, and any KDF profile other than the exact v0.1 profile. It MUST authenticate/decrypt before decompressing. It MUST cap decompression at `payload_length + 1`, require exact output length, reject truncated streams and trailing compressed data, parse duplicate-free JSON, require canonical payload bytes, and validate the schema.

A structural validator without a password can check magic, header syntax, profile, and lengths only. It MUST label its result as structural, not authenticated. Full validation requires a password and successful decryption, authentication, decompression, and schema validation.

## 6. Reference SDK profile

The repository's Python implementation provides `create_memx`, `read_memx`, `write_memx`, `inspect_memx`, and `validate_memx`. It uses `argon2-cffi` and `cryptography`. The CLI never accepts a password as a command-line argument; it prompts interactively to reduce shell-history/process-list exposure.

## 7. Security considerations

- The cleartext header exposes format version, creation time, payload size, KDF parameters, salt, and nonce. It does not expose profile names or context content.
- A human-readable JSON export is plaintext and must be handled accordingly.
- Password recovery is not provided. Loss of the password means loss of access.
- Python does not guarantee zeroization of immutable byte strings.
- AES-GCM and Argon2id are established primitives, but the Open Extensions implementation still requires independent review and cross-language test vectors before production use.
- The receiver model or provider may retain imported memory under its own policies; file encryption does not control downstream retention.
