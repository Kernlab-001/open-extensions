# Changelog

All notable changes to Open Extensions are recorded here. Format versions (for example, MEMX `0.1.0`) are independent of SDK/repository release versions.

## [0.2.0] - 2026-11-19

### Added
- The SDK is now published as eight distributions that share the `open_extensions` namespace package: `open-extensions` (all six formats), `open-extensions-core` (shared helpers and the command line), and one distribution per format (`open-extensions-memx`, `open-extensions-stepx`, `open-extensions-gridv`, `open-extensions-podx`, `open-extensions-wapp`, `open-extensions-tlock`). Install one format or all six with a single `pip install`.
- Every distribution provides a console script: `open-extensions` for the combined command, and `open-extensions-<format>` for a single format. The combined command adapts to whichever formats are installed.
- A PyPI publishing workflow that builds and publishes every distribution using Trusted Publishing (OIDC), so no long-lived token is stored in the repository.
- Executable Python v0.1 implementations for the five formats that previously had specifications only: `.stepx`, `.gridv`, `.podx`, `.wapp`, and `.tlock`.
- `.stepx`: create, read, validate, inspect, exact-decimal `scale`, and `render` as text or Markdown, plus a safe condition evaluator that reports an unsupplied variable as unknown rather than true.
- `.gridv`: workbook `init`, event `append`, `validate` with hash-chain and stable-ID integrity checks, `log`, `diff`, `checkout` state reconstruction, CSV `export`, and `recover` of the longest verified prefix into a new file.
- `.podx`: `pack`, `validate`, `inspect`, `list-tracks`, and path-safe `extract`, with per-track SHA-256 and length verification, ZIP safety rules, and deterministic archive output.
- `.wapp`: `pack`, `validate`, `inspect`, `list`, path-safe `extract`, and `run` as a local development inspection server that applies the declared Content Security Policy.
- `.tlock`: `create`, `open`, `validate`, `inspect`, and advisory `policy` checks, with the `passkey-local` key-wrap envelope and the `server`-profile client (ephemeral X25519, HPKE envelope opening, Ed25519 grant verification).
- An HPKE implementation following RFC 9180 `mode_base` with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, checked against the RFC's own Appendix A test vectors.
- A shared container module providing canonical JSON, bounded framing, defensive parsing, exact-decimal helpers, and ZIP archive-safety rules used by every format module.
- Namespaced CLI commands (`open-extensions <format> <command>`) for all six formats. The v0.1 flat verbs (`memx-create`, `memx-read`, `memx-validate`, `memx-inspect`) remain available as aliases.
- `jsonschema` moved from a development extra to a runtime dependency, because the validators now apply each format's JSON Schema.

### Changed
- **The flat import API is gone.** Because the distributions now share a namespace package, `open_extensions` must not contain an `__init__.py`, or it would become a regular package and hide the other distributions' modules. Import a format from its own module instead: `from open_extensions.memx import create_memx` rather than `from open_extensions import create_memx`.

### Limitations
- There is still no second-language implementation, so no format has been tested against an independent reader.
- `.wapp` has no runtime. The specification requires a separately installed, operating-system-registered component that provides WebView isolation and enforces the declared permission policy. The shipped server is for development inspection only and enforces nothing.
- `.tlock` has no key service. The `server` profile implements the client half only, and the grant request and response schemas remain an open release blocker in the specification, so the implemented protocol shape is provisional.
- `.gridv` does not evaluate formulas. The `nxf-formula-0.1` profile is pinned so that a reader never has to guess another spreadsheet program's semantics; formula source strings are stored and returned unchanged.
- `.podx` has no renderer, mixer, or player. The v0.1 specification excludes a `render` command until codec dependency and licensing policy is fixed.
- A WebAuthn ceremony cannot run from a command line, so the `.tlock` `passkey-local` profile takes the PRF output as an input rather than performing the ceremony.
- The format family is experimental and has not been adopted by an external standards body. No format has received an independent security audit or cross-language conformance review.

## [0.1.0] - 2026-11-19

### Added
- Initial monorepo structure for `.memx`, `.podx`, `.wapp`, `.stepx`, `.tlock`, and `.gridv`.
- Experimental 0.1.0 wire-format specifications and JSON Schemas for all six formats.
- Python reference implementation for MEMX 0.1.0: create, read, inspect, structural validation, and authenticated validation.
- `open-extensions` CLI commands for MEMX workflows.
- Synthetic MEMX example, Python unit tests, GitHub Actions CI, security policy, and contribution guidance.

### Limitations
- Only MEMX has an executable SDK implementation in this release.
- The other five formats are draft specifications and schemas, not interoperable production implementations.
- The format family is experimental and has not been adopted by an external standards body.
- MEMX has not received an independent security audit or cross-language conformance review.
