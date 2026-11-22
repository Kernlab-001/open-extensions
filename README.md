# Open Extensions

**Six experimental file formats for portable memory, richer media, offline apps, interactive instructions, controlled sharing, and spreadsheet history.**

Open Extensions is an open-source proposal to make files carry more of the structure and behavior that modern applications currently scatter across sidecars, databases, cloud accounts, and application-specific exports.

> **Project status: early design / alpha.** All six formats now have an executable Python v0.1 implementation with a test suite. There is still **no second-language implementation, no shared conformance vectors, and no independent security audit**, so none of these should be treated as a mature or interoperable standard yet. Two capabilities are deliberately absent and are explained below: `.wapp` has no runtime, and `.tlock` has no key service.

## The six formats

| Extension | Goal | What the file carries | Current status |
|---|---|---|---|
| **`.memx`** | Portable AI memory | Encrypted user preferences, coding profiles, and selected context as a versioned JSON payload | Python SDK + CLI + tests for v0.1 |
| **`.stepx`** | Interactive instructions | Ingredients/parts, exact quantities, step dependencies, timers, and conditional substitutions | Python SDK + CLI + tests for v0.1 |
| **`.gridv`** | Time-travel spreadsheet | Append-only spreadsheet operation log, hash chain, checkpoints, and pinned formula profile | Python SDK + CLI + tests for v0.1. The formula profile is *pinned*, not evaluated |
| **`.podx`** | Multi-track interactive audio | Separate audio stems, word-level transcript timing, speaker metadata, and chapters | Python SDK + CLI + tests for v0.1. No renderer or player — out of scope in v0.1 |
| **`.wapp`** | Offline web-app capsule | HTML/CSS/JS/assets, declared permissions, and optional seed SQLite database | Python SDK + CLI + tests for v0.1. **No runtime** — the CLI ships only a development inspection server |
| **`.tlock`** | Policy-bearing encrypted vault | Encrypted payload plus recipient and time/open policy metadata | Python SDK + CLI + tests for v0.1. `passkey-local` works offline; `server` needs a key service that does not exist yet |

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
│   ├── packages/
│   │   ├── open-extensions/          # meta distribution: all six formats
│   │   ├── open-extensions-core/     # shared helpers + the CLI
│   │   ├── open-extensions-memx/     # open_extensions/memx.py
│   │   ├── open-extensions-stepx/    # open_extensions/stepx.py
│   │   ├── open-extensions-gridv/    # open_extensions/gridv.py
│   │   ├── open-extensions-podx/     # open_extensions/podx.py
│   │   ├── open-extensions-wapp/     # open_extensions/wapp.py
│   │   └── open-extensions-tlock/    # open_extensions/tlock.py
│   ├── README.md
│   └── tests/
├── js-sdk/                 # reserved for the interoperable JS implementation
├── cli/                    # cross-SDK CLI entry points and packaging notes
└── examples/               # synthetic, non-sensitive examples for each format
```

Every distribution contributes to the shared `open_extensions` namespace package, so they can be installed together or one at a time.

## Installation

Requires **Python 3.10 or newer**.

> **Published to PyPI on release.** The `open-extensions` distribution installs every format; each format is also published on its own as `open-extensions-<format>`.

### Install from PyPI

Each format is published as its own distribution, and one meta distribution
installs all six. Pick whichever fits:

```bash
pip install open-extensions            # all six formats + the CLI
pip install open-extensions-memx       # only .memx
pip install open-extensions-stepx      # only .stepx
pip install open-extensions-gridv      # only .gridv
pip install open-extensions-podx       # only .podx
pip install open-extensions-wapp       # only .wapp
pip install open-extensions-tlock      # only .tlock
```

They all contribute to the same `open_extensions` namespace package, so they
can be mixed freely:

```bash
pip install open-extensions-memx open-extensions-stepx
```

Every distribution brings the `open-extensions` command, which adapts to
whichever formats are installed. A single-format install also gets its own
short command, for example `open-extensions-memx`.

Import a format from its own module:

```python
from open_extensions.memx import create_memx, read_memx
from open_extensions.stepx import create_stepx, scale_stepx
```

### A. Editable install from a clone

```bash
git clone https://github.com/Kernlab-001/open-extensions.git
cd open-extensions/python-sdk

python -m venv .venv
# Windows:        .venv\Scripts\activate
# macOS / Linux:  source .venv/bin/activate

for p in packages/*/; do python -m pip install --no-deps -e "$p"; done
python -m pip install jsonschema argon2-cffi cryptography pytest
```

Each distribution lives in its own directory under `python-sdk/packages/`.
`--no-deps` is needed because the per-format distributions depend on each
other and are not on PyPI yet.

Confirm it:

```bash
open-extensions --help
```

### B. Install straight from GitHub

```bash
python -m pip install "git+https://github.com/Kernlab-001/open-extensions.git#subdirectory=python-sdk/packages/open-extensions"
```

Each format can be installed the same way by pointing at its own directory,
for example `#subdirectory=python-sdk/packages/open-extensions-memx`.

### C. No install — run the launcher

From a clone, without modifying any environment:

```bash
# macOS / Linux
PYTHONPATH=python-sdk/packages/open-extensions-core/src:python-sdk/packages/open-extensions-memx/src \
  python cli/open-extensions.py --help

# Windows (PowerShell)
$env:PYTHONPATH = "python-sdk/packages/open-extensions-core/src;python-sdk/packages/open-extensions-memx/src"
python cli\open-extensions.py --help
```

On Windows, `cli\open-extensions.cmd` is an equivalent launcher. It uses whichever `python` comes first on your `PATH`, so it works once a venv containing the package is activated.

### Uninstall

```bash
python -m pip uninstall open-extensions            # the combined install
python -m pip uninstall open-extensions-memx       # or a single format
```

This removes the commands and the importable modules. Your `.memx` files and
any other data you created are **not** touched.

To see what is currently installed:

```bash
python -m pip list | grep open-extensions
```

If you installed into a dedicated virtual environment, deleting the environment is the most complete removal:

```bash
# Windows (cmd):        rmdir /s /q .venv
# Windows (PowerShell): Remove-Item -Recurse -Force .venv
# macOS / Linux:        rm -rf .venv
```

Two cleanup notes:

- An editable install leaves a `python-sdk/src/open_extensions.egg-info/` directory in your checkout. It is already covered by `.gitignore`, so it never shows up in `git status`, and it is safe to delete.
- `pip uninstall` does not remove the dependencies (`argon2-cffi`, `cryptography`). Remove them with `python -m pip uninstall argon2-cffi cryptography` only if nothing else on your machine depends on them.

## Command-line interface

Commands are namespaced by format. After installing (see [Installation](#installation) above):

```bash
open-extensions --help
open-extensions memx --help
```

| Format | Commands |
|---|---|
| `.memx` | `create`, `read`, `validate [--verify]`, `inspect` |
| `.stepx` | `create`, `validate`, `inspect`, `scale --yield N`, `render --format text\|markdown` |
| `.gridv` | `init`, `append --event`, `validate`, `inspect`, `log`, `diff --from --to`, `checkout --seq`, `export`, `recover` |
| `.podx` | `pack --manifest`, `validate`, `inspect`, `list-tracks`, `extract` |
| `.wapp` | `pack --manifest`, `validate`, `inspect`, `list`, `extract`, `run` |
| `.tlock` | `create --mode`, `open --mode`, `validate`, `inspect`, `policy` |

The v0.1 flat verbs (`memx-create`, `memx-read`, `memx-validate`, `memx-inspect`) still work as aliases.

## Quick start: every format, runnable

The SDK ships a set of synthetic example files for every format. Copy them
into a working directory first, then run the commands below there:

```bash
open-extensions examples memx --write .
open-extensions examples stepx --write .
open-extensions examples gridv --write .
open-extensions examples podx --write .
open-extensions examples wapp --write .
open-extensions examples tlock --write .
```

`open-extensions examples <format>` without `--write` prints the paths of the
bundled files instead of copying them.

Every command below is a **single line**, so it works unchanged in bash,
PowerShell and cmd. Do not use a trailing `\` to continue a line: that is a
bash convention, and PowerShell uses a backtick (`` ` ``) instead.

### `.memx` — portable AI memory

```bash
open-extensions memx create memx/minimal.json my-memory.memx
open-extensions memx inspect my-memory.memx
open-extensions memx validate my-memory.memx
open-extensions memx validate --verify my-memory.memx
open-extensions memx read my-memory.memx --output decrypted-memory.json
```

`memx create` and `memx read` prompt for the password interactively.

### `.stepx` — structured instructions

```bash
open-extensions stepx create stepx/pancakes.json recipe.stepx
open-extensions stepx validate recipe.stepx
open-extensions stepx inspect recipe.stepx
open-extensions stepx scale recipe.stepx --yield 10 --output recipe-10.stepx
open-extensions stepx render recipe.stepx --format markdown
```

### `.gridv` — append-only workbook history

```bash
open-extensions gridv init my-workbook --state gridv/initial-state.json -o book.gridv
open-extensions gridv append book.gridv --event gridv/cell-event.json
open-extensions gridv validate book.gridv
open-extensions gridv inspect book.gridv
open-extensions gridv log book.gridv
open-extensions gridv diff book.gridv --from 0 --to 2
open-extensions gridv checkout book.gridv --seq 2
open-extensions gridv export book.gridv -o book.csv
open-extensions gridv recover book.gridv -o recovered.gridv
```

### `.podx` — multi-track audio with transcripts

```bash
open-extensions podx pack podx --manifest podx/manifest.json -o session.podx
open-extensions podx validate session.podx
open-extensions podx inspect session.podx
open-extensions podx list-tracks session.podx
open-extensions podx extract session.podx podx-extracted
```

### `.wapp` — offline web app package

```bash
open-extensions wapp pack wapp --manifest wapp/manifest.json -o app.wapp
open-extensions wapp validate app.wapp
open-extensions wapp inspect app.wapp
open-extensions wapp list app.wapp
open-extensions wapp extract app.wapp wapp-extracted
open-extensions wapp run app.wapp
```

`wapp run` starts a local development inspection server on the loopback
interface. It is **not** a security-enforcing runtime.

### `.tlock` — encrypted container with policy metadata

```bash
open-extensions tlock create tlock/payload.txt secret.tlock --policy tlock/policy.json --mode passkey-local --recipient alice --credential-id-hash AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --prf-output-file tlock/prf-output.b64
open-extensions tlock validate secret.tlock
open-extensions tlock inspect secret.tlock
open-extensions tlock policy secret.tlock
open-extensions tlock open secret.tlock --mode passkey-local --recipient alice --prf-output-file tlock/prf-output.b64
```

The bundled `tlock/prf-output.b64` is a **synthetic stand-in** for a WebAuthn
PRF output. In real use it comes from the authenticator, and it should never
be passed on the command line. Use `--prf-output-file` or `--prf-output-env`.

### What is deliberately not implemented

These gaps are in the specifications, not oversights in the code:

- **`.gridv` does not evaluate formulas.** The file pins the `nxf-formula-0.1` profile so that a reader never has to guess what another spreadsheet program meant. This implementation stores and returns formula *source strings*. A reader that does not implement the profile may show source formulas and cached values but must not claim to have recalculated them.
- **`.podx` has no renderer or player.** The v0.1 specification excludes a `render` command until codec dependency and licensing policy is fixed.
- **`.wapp` has no runtime.** The specification requires a separately installed, operating-system-registered runtime that provides WebView isolation and enforces the declared permission policy. This repository ships a **development inspection server** that serves the package over loopback with the declared CSP. It does **not** enforce permissions, and the packaged JavaScript is untrusted.
- **`.tlock` has no key service.** The `passkey-local` profile works entirely offline and is fully implemented. The `server` profile implements the client half — ephemeral X25519, HPKE envelope opening, and Ed25519 grant verification — but there is no server to talk to, and the grant request/response schemas remain a published release blocker in the specification.
- **A WebAuthn ceremony cannot run from a command line.** The `passkey-local` profile takes the 32-byte PRF output as an input, normally obtained from the authenticator.

### Python API

```python
from open_extensions import create_memx, read_memx, validate_memx

blob = create_memx(payload, password="a-long-unique-passphrase")
restored_payload = read_memx(blob, password="a-long-unique-passphrase")
assert validate_memx(blob) == []
assert validate_memx(blob, password="a-long-unique-passphrase") == []
```

See [`python-sdk/README.md`](python-sdk/README.md) for installation, API details, and CLI behavior. See [`examples/memx/minimal.json`](examples/memx/minimal.json) for a synthetic payload.

Each format has its own module with the same shape — create, read, validate, inspect:

```python
from open_extensions import (
    create_memx, read_memx, validate_memx,        # .memx
    create_stepx, read_stepx, scale_stepx,         # .stepx
    create_gridv, append_gridv_event, checkout_gridv,  # .gridv
    create_podx, pack_podx, list_tracks_podx,      # .podx
    create_wapp, pack_wapp, validate_wapp,         # .wapp
    create_tlock, open_tlock_passkey,              # .tlock
)
```

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
