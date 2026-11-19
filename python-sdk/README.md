# Open Extensions Python SDK

Python reference implementation for Open Extensions **v0.1**, currently implementing `.memx` only.

## Install

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e .
```

The package is not published to PyPI, so `pip install open-extensions` does not work. For install-from-GitHub, no-install, and uninstall instructions, see [Installation and uninstall](../README.md#installation) in the root README.

## Uninstall

```bash
python -m pip uninstall open-extensions
```

This removes the `open-extensions` command and the `open_extensions` package. Deleting the virtual environment (`rmdir /s /q .venv` on Windows, `rm -rf .venv` on macOS/Linux) removes it completely, including the `argon2-cffi` and `cryptography` dependencies.

## CLI

```bash
open-extensions memx-create ../examples/memx/minimal.json ./private-memory.memx
open-extensions memx-inspect ./private-memory.memx
open-extensions memx-validate ./private-memory.memx
open-extensions memx-validate --verify ./private-memory.memx
open-extensions memx-read ./private-memory.memx --output ./decrypted.json
```

Passwords are requested interactively and are not accepted as command-line arguments. Structural validation cannot authenticate encrypted contents; use `--verify` for full verification.

## Python API

```python
from open_extensions import create_memx, read_memx, validate_memx

blob = create_memx(payload, password="use-a-long-unique-passphrase")
restored = read_memx(blob, password="use-a-long-unique-passphrase")
assert validate_memx(blob) == []
assert validate_memx(blob, password="use-a-long-unique-passphrase") == []
```

`create_memx` returns bytes. `write_memx(path, payload, password)` writes atomically. See `tests/` for executable examples.

## Security notes

- Never commit real memory exports, passwords, or decrypted fixtures.
- The header is visible; payload content is encrypted and authenticated.
- Use a high-entropy, unique passphrase and keep a separate backup.
- Python cannot guarantee zeroization of immutable password/key byte strings.
- This is a reference implementation, not a third-party security audit.
