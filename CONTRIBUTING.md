# Contributing to Open Extensions

Thanks for helping improve the specs and implementations. Open Extensions is an early proposal; clarity and compatibility matter more than adding features quickly. All participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening a pull request

1. Search existing issues and read the relevant format spec plus `specs/common/container-principles.md`.
2. Open an issue before changing binary framing, required fields, cryptographic profiles, formula semantics, or permission behavior.
3. State which format version the change affects and whether existing files remain readable.
4. Include a migration path for any incompatible change.

## Contribution areas

- Specification review and threat modeling.
- JSON Schema and positive/negative conformance fixtures.
- Python/JavaScript SDK implementations.
- CLI tools, test harnesses, parsers, fuzzing, and documentation.
- Cross-implementation tests using the same synthetic fixtures.

## Development: Python SDK

```bash
cd python-sdk
python -m venv .venv
# Activate the environment, then:
python -m pip install -e ".[dev]"
python -m pytest -q
```

Tests and fixtures must be deterministic where possible and must never contain real secrets or personal exports. Do not add passwords to command-line flags, logs, screenshots, or test names.

## Specification review checklist

- Is every field's type, unit, range, default, and required/optional status clear?
- Are the binary offsets, endianness, lengths, and maximum sizes exact?
- Are unsupported versions and unknown required features rejected?
- Are duplicate keys, malformed timestamps, path traversal, decompression bombs, and truncated files handled?
- Are the security claims achievable by the file format, or do they require a runtime/service?
- Are there positive, negative, and cross-language test vectors?

## Pull request expectations

A PR should contain a focused change, updated docs/schema, tests, and a short explanation of compatibility impact. Do not claim a format is production-ready solely because its happy-path example works.

## Code of conduct

Be respectful, specific, and constructive. Critique technical decisions rather than contributors. Harassment, threats, and discriminatory behavior are not acceptable.
