# Open Extensions implementation roadmap

This document turns each format specification into a build sequence. The four required implementation layers are kept separate: **encoder**, **decoder**, **validator**, and **CLI**. A CLI must call the same SDK code rather than reimplement parsing rules.

## 0. Shared foundation (before adding another encoder)

1. Freeze the common JSON, timestamp, versioning, and parser-limit rules in `specs/common/container-principles.md`.
2. Set up one conformance-fixture directory per format with valid, invalid, boundary-size, and tampered fixtures. No real personal or copyrighted material.
3. Add CI for unit tests, schema self-validation, package build, type checks, and fuzz/property tests.
4. Publish a format support matrix. Never label a format supported merely because `inspect` can read its magic bytes.
5. Require a compatibility note and migration path for every spec change.

## 1. `.memx` — implemented v0.1 baseline

**Encoder**
1. Accept the payload object and validate the complete data model.
2. Serialize canonical UTF-8 JSON; reject duplicate keys/non-finite numbers on file input.
3. Compress with zlib, generate a fresh salt and nonce, derive the Argon2id key, construct the header, and encrypt with AES-256-GCM using the exact framed header as AAD.
4. Write with an atomic file replacement and restrictive temporary-file permissions.

**Decoder**
1. Check magic, length bounds, canonical header, supported version, exact KDF profile, and ciphertext length before expensive work.
2. Derive key from the entered password and authenticate/decrypt the payload.
3. Decompress under an explicit output limit; require exact length and no trailing compressed bytes.
4. Parse canonical JSON, reject duplicate keys, validate the payload, and return the data without importing it into a model automatically.

**Validator**
1. Structural mode validates framing, header, KDF profile, lengths, and canonical encoding without a password.
2. Full mode repeats parsing and then authenticates, decrypts, decompresses, and validates the payload schema.
3. Add fuzzing around lengths, base64url, malformed JSON, wrong passwords, truncated inputs, and tampering.

**CLI**
1. `memx-create INPUT.json OUTPUT.memx` prompts twice for the password.
2. `memx-inspect FILE.memx` displays only the cleartext header.
3. `memx-validate FILE.memx` labels its result structural; `--verify` prompts for a password and performs full validation.
4. `memx-read FILE.memx --output OUTPUT.json` decrypts to a user-selected plaintext location.

**v0.1 status:** Python functions and four CLI verbs are implemented. Twelve unit tests pass in the current v0.1 test suite; the CLI create/verify/read flow is covered by the repository verification run. Next work: shared golden fixtures, independent second-language implementation, cross-language KDF/AEAD test vectors, fuzzing, and external security review.

## 2. `.stepx` — declarative instructions

**Encoder**
1. Build typed models for document metadata, yield, ingredients, steps, timers, requirements, and substitutions.
2. Normalize quantities to decimal strings; assign stable IDs; validate ingredient/step references.
3. Validate conditional clauses against the limited condition DSL. Do not accept script expressions.
4. Emit canonical JSON with the STEPX magic and body length.

**Decoder**
1. Validate magic and body length before parsing.
2. Reject duplicate keys, unknown required capabilities, and unsupported major versions.
3. Create immutable domain objects with ingredient and step references resolved.
4. Expose a deterministic decimal scaling function and tri-state condition evaluator (`true`, `false`, `unknown`). Unknown conditions must never silently activate a substitution.

**Validator**
1. Run JSON Schema validation.
2. Check uniqueness of ingredient/step IDs, valid references, unique positive step order, and timer bounds.
3. Check exact decimal syntax and positive base yield.
4. Check dependency cycles and unknown condition operators/variables.

**CLI**
1. `stepx validate` checks syntax and semantic constraints.
2. `stepx inspect` prints a summary without changing the file.
3. `stepx scale --yield N` previews scaled ingredient quantities without mutating the source.
4. `stepx render --format text|markdown` creates a readable view; a separate app may add interactive timers.

**Acceptance criteria:** Python and JS SDKs produce identical scaled quantities and condition results for shared fixtures; invalid references and unknown conditions fail closed.

## 3. `.podx` — multi-track interactive audio

**Encoder**
1. Choose a codec/transcoding policy and document dependency/licensing constraints before implementation.
2. Read source track metadata without altering audio; assign stable track IDs and offsets in the 48 kHz tick timebase.
3. Convert transcript timing to integer ticks and validate word/chapter ordering.
4. Hash each asset, write safe relative `tracks/` entries to ZIP/ZIP64, and frame the manifest/archive lengths.

**Decoder/player**
1. Parse bounded framing and validate the manifest before opening archive entries.
2. Verify ZIP entry paths, sizes, CRCs, and manifest SHA-256 digests without unsafe extraction.
3. Decode supported Opus/Ogg and FLAC assets; map timeline ticks to source samples using rational arithmetic.
4. Expose stem mute/solo/gain, transcript seek/highlight, and chapter seek APIs.

**Validator**
1. Validate manifest schema and unique IDs.
2. Check track offsets/durations, codec/sample-rate/channel bounds, and global duration.
3. Check transcript word ranges and chapter ordering/non-overlap.
4. Verify every archive asset against declared path, length, CRC, and SHA-256.

**CLI**
1. `podx inspect` summarizes tracks, duration, transcript, and chapters.
2. `podx validate` performs schema, semantic, and archive integrity checks.
3. `podx list-tracks` and `podx extract` list/extract only selected, verified assets.
4. Add `podx render --mix` only after decoder and codec dependencies are stable.

**Acceptance criteria:** at least two independent readers map all track/word/chapter positions to the same timeline; mutating any asset or manifest hash fails validation.

## 4. `.gridv` — append-only spreadsheet history

**Encoder**
1. Define workbook, sheet, row, column, and cell domain models with stable, never-reused IDs.
2. Convert edits into typed immutable events with contiguous sequence numbers and canonical JSON.
3. Hash-chain each event as `SHA-256(previous_hash || event_bytes)` and append a frame; never rewrite previous frames.
4. Implement deterministic checkpoint serialization and an exclusive writer lock.
5. Implement the pinned `nxf-formula-0.1` parser/evaluator before advertising formula recalculation.

**Decoder/replayer**
1. Parse header and bounded frames until EOF.
2. Verify the hash chain before applying each event.
3. Load the nearest verified checkpoint and replay to the requested sequence.
4. Reconstruct formulas using the exact formula profile; display formulas/cached values without recalculating when the profile is unsupported.
5. Produce structured diffs between two sequence numbers.

**Validator**
1. Check framing, canonical JSON, sequence continuity, and event hashes.
2. Validate operation-specific data and referential integrity for stable IDs.
3. Verify checkpoint digest/state sequence.
4. Parse formulas and reject unsupported/volatile/external functions.
5. Distinguish tamper evidence from authorship: a hash chain is not a signature.

**CLI**
1. `gridv init` creates the workbook header and first event.
2. `gridv validate` scans the complete chain and validates operations.
3. `gridv log` lists events; `gridv diff --from A --to B` compares reconstructed states.
4. `gridv checkout --seq N` exports a historical state without mutating the source.
5. `gridv export --format csv|xlsx` must report loss of history/formula semantics.
6. `gridv recover` writes a separate file containing the verified prefix; it never edits the damaged source.

**Acceptance criteria:** replay from start and replay from any valid checkpoint produce byte-equivalent canonical workbook state; event tampering is detected; two writers cannot silently interleave frames.

## 5. `.wapp` — offline web application package

**Encoder/packer**
1. Collect app entrypoint, assets, and optional SQLite seed database.
2. Generate a manifest with package identity, runtime minimum, file hashes, permission declarations, network allowlist, CSP, and database schema version.
3. Reject absolute paths, traversal, symlinks, undeclared external resources, unsafe inline/eval requirements, and unsupported permissions.
4. Write a bounded ZIP/ZIP64 archive and frame it with the manifest.

**Decoder/runtime loader**
1. Validate the container and every file hash before launch.
2. Mount the package read-only under a unique isolated origin; do not expose it through unrestricted `file://` access.
3. Start a sandboxed WebView/browser context with restrictive defaults and no elevated OS privileges.
4. Copy the optional seed database to a per-user writable location on first launch.
5. Expose only scoped, parameterized host APIs; validate every request and response; do not expose arbitrary filesystem or generic host objects.
6. Enforce navigation, downloads, popups, clipboard, camera, microphone, network, and SQLite permissions.

**Validator**
1. Check schema, IDs, runtime minimum, and permission consistency.
2. Check archive paths, hashes, lengths, compression limits, and SQLite integrity.
3. Check CSP and local asset references; fail closed on unsupported permissions.
4. Report that static validation does not prove the JavaScript is harmless.

**CLI**
1. `wapp pack` builds a `.wapp` package from a project directory.
2. `wapp validate` runs schema, archive, asset, CSP, and permission checks.
3. `wapp inspect` and `wapp list` show package metadata and files.
4. `wapp extract` extracts to a fresh safe directory.
5. `wapp run` launches only through the installed WAPP runtime; no direct execution from the packer/parser.

**Acceptance criteria:** runtime sandbox tests prove network-deny by default, no arbitrary file access, no privilege escalation, and per-install database isolation. The runtime must receive a dedicated security review.

## 6. `.tlock` — policy-bearing encrypted vault

**Encoder**
1. Generate a file ID, a fresh content key, a fresh content nonce, and a plaintext digest.
2. Encrypt payload with AES-256-GCM and authenticate the full header as AAD.
3. For local passkey mode, obtain a PRF output through WebAuthn, derive the wrapping key with the specified HKDF-SHA-256 context, and wrap the content key using AES-256-GCM.
4. For server mode, place the content key in a managed key store and write only the service origin/key ID to the file.
5. Validate that `policy.enforcement` matches the selected key-access mode.

**Decoder**
1. Parse bounds and validate header/policy before performing key operations.
2. For local mode, verify passkey credential identity, obtain PRF, unwrap, and label policy checks as advisory.
3. For server mode, request one-time authorization, verify the pinned Ed25519 service signature and all grant bindings, then open the HPKE envelope.
4. Decrypt only after authorization; verify plaintext digest; present a clear warning that a decrypted copy can be retained.

**Validator**
1. Validate canonical header, framing, nonce lengths, ciphertext length, timestamps, and policy consistency.
2. Validate passkey envelope lengths or server key-service fields.
3. Validate grant signature, recipient/file/policy binding, expiry, and one-time nonce for server-mode opens.
4. Treat offline structural validation as unauthenticated and not proof of policy enforcement.

**CLI**
1. `tlock create` chooses and labels `server` versus `passkey-local` mode.
2. `tlock inspect` shows policy metadata and enforcement mode without decrypting.
3. `tlock validate` supports structural and authenticated modes.
4. `tlock open` runs the recipient ceremony and explains policy limitations before displaying plaintext.
5. `tlock policy` shows authorization history when the service provides it.

**Acceptance criteria:** externally audited crypto profile, server request/response schema and test vectors, replay/counter/expiry tests, key rotation and recovery plan, and clear proof that the UX never calls advisory-local policy “tamper-proof.”

## Cross-format release gate

No format should be called stable until its schema, binary layout, implementation, negative test suite, independent reader, cross-language vectors, resource limits, security considerations, and migration story agree. A successful happy-path demo is not sufficient.
