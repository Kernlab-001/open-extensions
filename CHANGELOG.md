# Changelog

All notable changes to Open Extensions are recorded here. Format versions (for example, MEMX `0.1.0`) are independent of SDK/repository release versions.

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
