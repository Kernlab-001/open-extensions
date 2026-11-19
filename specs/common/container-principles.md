# Common container and implementation principles

Status: normative for Open Extensions 0.1 proposals unless a format specification overrides it.

## 1. Requirement words

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as normative requirement terms. A `MUST` requirement is necessary for conformance. Any exception to a `SHOULD` requirement must be documented by an implementation.

## 2. Versioning and forward compatibility

- Every format has an independent semantic version in its header or root manifest.
- A reader MUST reject an unsupported major version. A reader MUST NOT silently reinterpret an unknown major version as the current version.
- Unknown optional extension data belongs under a namespaced `extensions` object. A reader MUST preserve extensions it does not understand when it performs a lossless rewrite, and MUST NOT execute them.
- A reader MUST reject unknown required capabilities rather than guessing.
- Schema changes that alter meaning, required fields, wire encoding, cryptographic profile, or event semantics require a new major version. Backward-compatible optional additions may use a minor version.
- SDK versions and file-format versions are separate. A Python SDK 0.1.2 may read a file-format 0.1.0.

## 3. Encoding

- JSON payloads MUST be UTF-8 without a byte-order mark.
- JSON objects MUST NOT contain duplicate keys, NaN, or Infinity.
- Where a format says `canonical JSON`, serialize UTF-8 with Unicode preserved, object keys sorted lexicographically, no insignificant whitespace, and no non-finite numbers.
- All timestamps MUST use RFC 3339 with an explicit UTC `Z` suffix unless a format explicitly defines another time base.
- Numeric quantities that need exact decimal arithmetic SHOULD be represented as decimal strings, not IEEE-754 binary floating-point values.
- Identifiers are opaque, case-sensitive strings. Consumers MUST NOT infer meaning from an identifier's spelling.

## 4. Defensive parsing

Every decoder MUST:

1. Check magic bytes and minimum length before parsing fields.
2. Apply upper bounds to header, manifest, archive, payload, and individual asset sizes before allocating or decompressing.
3. Reject length mismatches, trailing bytes where not explicitly permitted, duplicate JSON keys, unsupported algorithms, invalid encodings, and unknown required features.
4. Avoid path traversal, symlink extraction, archive bombs, decompression bombs, and unsafe deserialization.
5. Treat manifests, strings, filenames, formulas, embedded code, and external metadata as untrusted input.
6. Avoid executing a file merely because it has a Open Extensions extension.
7. Return actionable validation errors without exposing secrets or decrypted content in logs.

## 5. Archive conventions

Formats that embed a ZIP archive use the ZIP/ZIP64 record format, but MUST impose stricter profile rules than a general-purpose ZIP reader. Unless a spec says otherwise:

- ZIP encryption is forbidden; format-specific encryption must be used instead.
- Entry paths MUST be relative, normalized, UTF-8, and must not contain `..`, drive prefixes, UNC roots, or NUL bytes.
- Symlinks, device files, sockets, and other non-regular entries are forbidden.
- Implementations MUST verify declared lengths, CRCs, and manifest-provided SHA-256 digests before making assets available.
- Extraction MUST occur into an isolated temporary directory and MUST NOT overwrite existing files.
- Entry count, total uncompressed bytes, per-entry uncompressed bytes, and compression ratio MUST be bounded.

## 6. Security and privacy

- File formats are containers, not trust boundaries. Applications supply the policy enforcement, process isolation, key management, and UI.
- Encryption provides confidentiality only for data actually encrypted. Metadata in a cleartext header remains observable.
- A local-only format cannot guarantee revocation after a recipient has copied plaintext or keys. Specs must clearly state when a feature is advisory or depends on a trusted service/hardware.
- Cryptographic formats MUST use established libraries and standard algorithms. Do not design custom ciphers, KDFs, signatures, or key-wrapping primitives.
- Security-sensitive format changes require review, test vectors, a threat model, and a migration plan.

## 7. Conformance

Each format SHOULD ship:

- A machine-readable JSON Schema where JSON is used.
- Golden valid and invalid fixtures that contain no real personal data.
- A reference encoder, decoder, and validator.
- Cross-implementation round-trip tests.
- Fuzzing or property-based tests for parsers.
- A security considerations section and a list of known limitations.
