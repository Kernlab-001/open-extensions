# Open Extensions specifications

This directory is the normative home for the Open Extensions family. Each format is independently versioned. A format version identifies the container framing, schema, validation rules, and compatibility behavior—not merely the SDK release number.

| Extension | Spec | Primary payload | v0.1 status |
|---|---|---|---|
| `.memx` | [MEMX 0.1](memx/0.1.0/spec.md) | Password-encrypted AI memory JSON | Reference implementation included |
| `.podx` | [PODX 0.1](podx/0.1.0/spec.md) | Multi-track audio package + transcript + chapters | Specification draft |
| `.wapp` | [WAPP 0.1](wapp/0.1.0/spec.md) | Sandboxed offline web-app package | Specification draft |
| `.stepx` | [STEPX 0.1](stepx/0.1.0/spec.md) | Structured interactive instructions | Specification draft |
| `.tlock` | [TLOCK 0.1](tlock/0.1.0/spec.md) | Policy-bearing encrypted vault | Security design draft |
| `.gridv` | [GRIDV 0.1](gridv/0.1.0/spec.md) | Append-only spreadsheet event log | Specification draft |

Read [common/container-principles.md](common/container-principles.md) before implementing a new reader or writer. Key external standards and library references are collected in [REFERENCES.md](REFERENCES.md).

**Status warning:** a written specification is not evidence of interoperability, security, or production readiness. Until independent implementations and conformance fixtures exist, these are experimental Open Extensions proposals. Only `.memx` has executable code in this repository's initial milestone.
