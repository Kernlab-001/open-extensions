# CLI workspace

The CLI ships in the `open-extensions-core` distribution as the
`open-extensions` command. Install it with `pip install open-extensions`, or
install it from a clone:

```bash
cd python-sdk
for p in packages/*/; do python -m pip install --no-deps -e "$p"; done
```

Format-specific commands are namespaced:

```bash
open-extensions memx create payload.json memory.memx
open-extensions stepx validate recipe.stepx
open-extensions gridv checkout book.gridv --seq 12
```

Each format distribution also provides its own short command, for example
`open-extensions-memx`, which is the same CLI restricted to that format.

The v0.1 flat verbs (`memx-create`, `memx-read`, `memx-validate`,
`memx-inspect`) remain available as aliases so existing scripts keep working.

The `cli/open-extensions.py` and `cli/open-extensions.cmd` files in this
directory are convenience launchers for running straight from a checkout
without installing anything. They need the `open_extensions` namespace on
`PYTHONPATH`; see the no-install instructions in the root README.
