# Security policy

## Scope and status

Open Extensions is experimental. Only the `.memx` v0.1 Python reference implementation is executable in this repository's initial release. It has not received an independent security audit. The other format specifications are drafts; `.tlock` contains explicit unresolved release blockers.

## Reporting a vulnerability

Do not publish exploit details in a public issue. Until a dedicated security contact is configured, open a private security advisory through the repository hosting provider (GitHub Security Advisories, when enabled) and include the affected commit/version, impact, reproduction steps, and any safe proof-of-concept. Do not attach real personal memory exports or passwords.

## Security-sensitive areas

- **MEMX:** password KDF profile, AES-GCM nonce handling, canonical JSON, compression limits, and secret exposure.
- **PODX/WAPP:** archive extraction, path traversal, oversized media, ZIP bombs, script execution, browser isolation, host bridge, SQLite access, and network permission enforcement.
- **STEPX:** untrusted instruction text, condition evaluator correctness, and resource limits.
- **TLOCK:** key wrapping, recipient authentication, trusted time, replay resistance, durable open counters, revocation, and the limits of post-decryption control.
- **GRIDV:** hash chain integrity, event parser bounds, formula determinism, and concurrent writer handling.

## Disclosure

Please allow maintainers to investigate and prepare a fix before publishing technical details. Coordinated disclosure timelines will be agreed with the reporter based on severity and maintainer capacity.

## Safe handling

Never send secrets, credentials, decrypted memory exports, or private user files in issue trackers or test fixtures. Do not treat file extensions or unverified manifests as trust indicators.
