# Open Extensions

**Six experimental file formats for portable memory, richer media, offline apps, interactive instructions, controlled sharing, and spreadsheet history.**

Open Extensions is an open-source proposal to make files carry more of the structure and behavior that modern applications currently scatter across sidecars, databases, cloud accounts, and application-specific exports.

> **Project status: early design / alpha.** The `.memx` v0.1 Python reference implementation is executable and tested. The other five formats have draft specifications only. None of the formats should be treated as a mature or independently audited standard yet.

## The six formats

| Extension | Goal | What the file carries | Current status |
|---|---|---|---|
| **`.memx`** | Portable AI memory | Encrypted user preferences, coding profiles, and selected context as a versioned JSON payload | Python SDK + CLI + tests for v0.1 |
| **`.podx`** | Multi-track interactive audio | Separate audio stems, word-level transcript timing, speaker metadata, and chapters | Draft spec |
| **`.wapp`** | Offline web-app capsule | HTML/CSS/JS/assets, declared permissions, and optional seed SQLite database | Draft spec; runtime is a separate required component |
| **`.stepx`** | Interactive instructions | Ingredients/parts, exact quantities, step dependencies, timers, and conditional substitutions | Draft spec |
| **`.tlock`** | Policy-bearing encrypted vault | Encrypted payload plus recipient and time/open policy metadata | Security design draft; key-envelope suite is a release blocker |
| **`.gridv`** | Time-travel spreadsheet | Append-only spreadsheet operation log, hash chain, checkpoints, and pinned formula profile | Draft spec |

The file extensions are proposals; this repository does not claim that the formats have been registered with IANA, adopted by platforms, or standardized by an external standards body.

**Repository name:** `open-extensions`. The Python distribution name is also `open-extensions`; its import namespace is `open_extensions`, and its installed CLI command is `open-extensions`.

## Why these workflows need better formats

The weakness is not that PDF, ZIP, MP3, XLSX, SQLite, or JSON are universally broken. They solve important problems and should remain usable. The gap is that common workflows often lose meaning when data is exported or moved between applications:

- AI preferences and context are fragmented across model vendors, chats, and local tools. A portable, user-controlled memory bundle can make migration and selective import easier.
- A single flattened audio file loses independent stem control; transcripts and chapters often live in separate sidecar files or platform metadata.
- A folder of web assets plus a local database is awkward to archive and distribute as one offline project. A package format can describe the app and its permissions, while a dedicated runtime enforces them.
- Recipes and DIY instructions are usually mostly prose, so ingredient scaling, timers, prerequisites, and substitutions are reimplemented by each application.
- Expiry and access-count requirements are separate from the content in ordinary encrypted files. A policy-aware envelope can describe them, while a trusted authorization system enforces strict policy.
- Ordinary spreadsheet exports preserve a current result far better than a complete, inspectable history of every edit and formula change.

Open Extensions is intended to **complement existing formats and runtimes**, not to force users to abandon mature tools. The bar for claiming a real improvement is interoperability, recoverability, security review, and working implementations—not a new extension name.

## Repository structure

```text
open-extensions/
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
├── specs/
│   ├── README.md
│   ├── common/container-principles.md
│   ├── memx/0.1.0/{spec.md,schema.json}
│   ├── podx/0.1.0/{spec.md,schema.json}
│   ├── wapp/0.1.0/{spec.md,schema.json}
│   ├── stepx/0.1.0/{spec.md,schema.json}
│   ├── tlock/0.1.0/{spec.md,schema.json}
│   └── gridv/0.1.0/{spec.md,schema.json}
├── python-sdk/
│   ├── pyproject.toml
│   ├── README.md
│   ├── src/open_extensions/{__init__.py,memx.py,cli.py}
│   └── tests/test_memx.py
├── js-sdk/                 # reserved for the interoperable JS implementation
├── cli/                    # cross-SDK CLI entry points and packaging notes
└── examples/               # synthetic, non-sensitive examples for each format
```

## Quick start: `.memx` v0.1

Requires Python 3.10+.

```bash
cd python-sdk
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .

# Encrypt a sample memory payload. The password is prompted interactively.
open-extensions memx-create ../examples/memx/minimal.json ./my-memory.memx

# Inspect visible, non-secret header metadata.
open-extensions memx-inspect ./my-memory.memx

# Check container framing only (not cryptographic integrity).
open-extensions memx-validate ./my-memory.memx

# Authenticate, decrypt, and validate the full payload.
open-extensions memx-validate --verify ./my-memory.memx

# Decrypt to a JSON file.
open-extensions memx-read ./my-memory.memx --output ./decrypted-memory.json
```

### Python API

```python
from open_extensions import create_memx, read_memx, validate_memx

blob = create_memx(payload, password="a-long-unique-passphrase")
restored_payload = read_memx(blob, password="a-long-unique-passphrase")
assert validate_memx(blob) == []
assert validate_memx(blob, password="a-long-unique-passphrase") == []
```

See [`python-sdk/README.md`](python-sdk/README.md) for installation, API details, and CLI behavior. See [`examples/memx/minimal.json`](examples/memx/minimal.json) for a synthetic payload.

## Format design principles

1. **Versioned, explicit schemas.** An extension alone is not a specification. Every format defines wire framing, versions, field meanings, and validation behavior.
2. **Readable where useful, encrypted where necessary.** `.memx` and `.tlock` encrypt their content; their headers expose only the metadata required to locate and validate the payload.
3. **Deterministic parsing.** Bounded lengths, canonical JSON where defined, exact timestamps/timebases, and rejection of unknown required features.
4. **No hidden execution.** A file is data. `.wapp` code runs only inside a separate runtime with enforceable permissions; `.stepx` conditions are declarative, not scripts.
5. **Portable semantics.** Timebases, codecs, formula profiles, scaling rules, and policy modes must be explicit.
6. **Honest security claims.** A container cannot enforce a sandbox, revoke plaintext, or make a local clock trustworthy. Those guarantees belong to runtimes and trusted services.
7. **Open implementations and test vectors.** Specs should not become stable until there are independent implementations and cross-language conformance tests.

## Build roadmap

| Milestone | Deliverable | Exit criteria |
|---|---|---|
| **0.1 — MEMX** | Python create/read/validate/inspect + CLI | Tests pass; schema and binary framing agree; golden fixtures and security review are added |
| **0.2 — STEPX** | Python + JS schema validators, decimal scaler, text renderer | Identical scaling and condition semantics across SDKs |
| **0.3 — PODX** | Pack/unpack, track metadata, transcript and chapter validation | Cross-player timeline conformance and media hash checks |
| **0.4 — GRIDV** | Event writer, replay engine, history diff, checkpoints | Deterministic replay and tamper-detection tests |
| **0.5 — WAPP** | Pack/validate tooling and a restricted desktop runtime | Threat model, runtime sandbox tests, permissions and SQLite bridge review |
| **0.6 — TLOCK** | Key service protocol, passkey profile, encrypted container | Standard key-envelope suite selected; external cryptographic audit; replay/expiry tests |

This ordering may change if implementation research reveals a better dependency sequence. `.tlock` is deliberately last because access-control claims need more than a file encoder.

## Contributing

Contributions are useful in several areas:

- Review the six specifications for ambiguous fields, unhandled edge cases, and unrealistic guarantees.
- Add JSON Schema and semantic conformance fixtures.
- Implement a second language SDK and test it against the same golden files.
- Add fuzzing, property-based tests, and malformed-file fixtures.
- Improve documentation, migration examples, and CLI usability.
- Prototype `.stepx` and `.gridv` before taking on the security-critical `.tlock` or runtime-heavy `.wapp` work.

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and follow the [`Code of Conduct`](CODE_OF_CONDUCT.md). Please open an issue before making a breaking change to a wire format.

## Standards and implementation references

The specifications build on external cryptographic, packaging, and schema references. See [`specs/REFERENCES.md`](specs/REFERENCES.md). These documents inform the proposals; they do not make Open Extensions an adopted standard.

## Security

Do not put real personal memories, credentials, or private documents in examples or test fixtures. Report vulnerabilities privately using the process in [`SECURITY.md`](SECURITY.md). `.memx` is an experimental reference implementation and has not received an independent security audit. `.tlock` is not implemented and its cryptographic key-envelope details are intentionally not finalized.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for the contents and limitations of each release.

## License

MIT. See [`LICENSE`](LICENSE).
