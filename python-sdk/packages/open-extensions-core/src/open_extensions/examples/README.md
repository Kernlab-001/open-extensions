# Examples

All examples must be synthetic and safe to publish. Do not commit a real
`.memx` or `.tlock` file, passwords, private user context, or media without
rights to distribute it.

These files are also bundled inside the `open-extensions-core` package, so
`open-extensions examples <format> --write .` copies them into a working
directory and the documented commands can be run there unchanged.

| Directory | Example files | Command to try it |
|---|---|---|
| `memx/` | `minimal.json` | `open-extensions memx create memx/minimal.json my-memory.memx` |
| `stepx/` | `pancakes.json` | `open-extensions stepx create stepx/pancakes.json recipe.stepx` |
| `gridv/` | `initial-state.json`, `cell-event.json` | `open-extensions gridv init demo --state gridv/initial-state.json -o book.gridv` |
| `podx/` | `manifest.json`, `tracks/` | `open-extensions podx pack podx --manifest podx/manifest.json -o session.podx` |
| `wapp/` | `manifest.json`, `app/` | `open-extensions wapp pack wapp --manifest wapp/manifest.json -o app.wapp` |
| `tlock/` | `policy.json`, `payload.txt`, `prf-output.b64`, `credential-id-hash.b64` | `open-extensions tlock create tlock/payload.txt secret.tlock --policy tlock/policy.json --mode passkey-local --recipient alice --credential-id-hash AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --prf-output-file tlock/prf-output.b64` |
