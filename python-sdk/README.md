# Open Extensions Python SDK

Python reference implementation for Open Extensions **v0.1**. All six formats
are implemented.

## Distributions

The SDK is published as eight distributions that share the `open_extensions`
namespace package. They can be installed together or one at a time.

| Distribution | Provides | Command |
|---|---|---|
| `open-extensions` | all six formats (a dependency aggregator) | `open-extensions` |
| `open-extensions-core` | shared helpers and the command line | `open-extensions` |
| `open-extensions-memx` | `.memx` | `open-extensions-memx` |
| `open-extensions-stepx` | `.stepx` | `open-extensions-stepx` |
| `open-extensions-gridv` | `.gridv` | `open-extensions-gridv` |
| `open-extensions-podx` | `.podx` | `open-extensions-podx` |
| `open-extensions-wapp` | `.wapp` | `open-extensions-wapp` |
| `open-extensions-tlock` | `.tlock` | `open-extensions-tlock` |

## Install

```bash
pip install open-extensions            # all six formats + the CLI
pip install open-extensions-memx       # only .memx
pip install open-extensions-stepx      # only .stepx
```

They can be mixed, because each one contributes to the same namespace:

```bash
pip install open-extensions-memx open-extensions-stepx
```

From a clone:

```bash
cd python-sdk
for p in packages/*/; do python -m pip install --no-deps -e "$p"; done
python -m pip install jsonschema argon2-cffi cryptography pytest
```

`--no-deps` is required for a clone install because the per-format
distributions depend on each other and are not on PyPI yet.

For install-from-GitHub, no-install, and uninstall instructions, see
[Installation](../README.md#installation) in the root README.

## Uninstall

```bash
python -m pip uninstall open-extensions        # the combined install
python -m pip uninstall open-extensions-memx   # or a single format
```

This removes the commands and the importable modules. Deleting the virtual
environment (`rmdir /s /q .venv` on Windows, `rm -rf .venv` on macOS/Linux)
removes it completely, including the `argon2-cffi`, `cryptography` and
`jsonschema` dependencies.

## CLI

Commands are namespaced by format. The `open-extensions` command adapts to
whichever formats are installed:

```bash
open-extensions memx create ../examples/memx/minimal.json ./private-memory.memx
open-extensions memx inspect ./private-memory.memx
open-extensions memx validate ./private-memory.memx
open-extensions memx validate --verify ./private-memory.memx
open-extensions memx read ./private-memory.memx --output ./decrypted.json

open-extensions stepx create ./recipe.json ./recipe.stepx
open-extensions stepx scale ./recipe.stepx --yield 10
open-extensions stepx render ./recipe.stepx --format markdown

open-extensions gridv init my-workbook --state ./initial.json -o ./book.gridv
open-extensions gridv append ./book.gridv --event ./event.json
open-extensions gridv checkout ./book.gridv --seq 12
open-extensions gridv export ./book.gridv -o ./book.csv

open-extensions podx pack ./stems --manifest ./manifest.json -o ./session.podx
open-extensions podx list-tracks ./session.podx

open-extensions wapp pack ./site --manifest ./manifest.json -o ./app.wapp
open-extensions wapp validate ./app.wapp

open-extensions tlock create ./payload.bin ./secret.tlock --policy ./policy.json \
  --mode passkey-local --recipient alice --credential-id-hash <base64url> \
  --prf-output-file ./prf.b64
```

The v0.1 flat verbs (`memx-create`, `memx-read`, `memx-validate`,
`memx-inspect`) remain available as aliases.

Passwords are requested interactively and are not accepted as command-line
arguments. Structural validation cannot authenticate encrypted contents; use
`--verify` for full verification.

## Python API

Each format is imported from its own module:

```python
from open_extensions.memx import create_memx, read_memx, validate_memx

blob = create_memx(payload, password="use-a-long-unique-passphrase")
restored = read_memx(blob, password="use-a-long-unique-passphrase")
assert validate_memx(blob) == []
assert validate_memx(blob, password="use-a-long-unique-passphrase") == []
```

```python
from open_extensions.stepx import create_stepx, scale_stepx
from open_extensions.gridv import create_gridv, checkout_gridv
from open_extensions.podx import create_podx, list_tracks_podx
from open_extensions.wapp import create_wapp, validate_wapp
from open_extensions.tlock import create_tlock, open_tlock_passkey
```

`create_memx` returns bytes. `write_memx(path, payload, password)` writes
atomically. See `tests/` for executable examples.

## Security notes

- Never commit real memory exports, passwords, or decrypted fixtures.
- Headers are visible; payload content is encrypted and authenticated.
- Use a high-entropy, unique passphrase and keep a separate backup.
- Python cannot guarantee zeroization of immutable password/key byte strings.
- `.wapp` validation is not a security audit of arbitrary JavaScript, and the
  `wapp run` server is a development inspection server, not an enforcing
  runtime.
- `.tlock` expiry and open-count policy are advisory in the `passkey-local`
  profile; a recipient who controls the device can bypass them.
- This is a reference implementation, not a third-party security audit.
