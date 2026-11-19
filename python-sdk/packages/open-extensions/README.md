# open-extensions

Every Open Extensions file format in one install: .memx, .stepx, .gridv, .podx, .wapp and .tlock

This distribution installs every Open Extensions format at once. It ships no
code of its own: it depends on `open-extensions-memx`, `open-extensions-stepx`,
`open-extensions-gridv`, `open-extensions-podx`, `open-extensions-wapp` and
`open-extensions-tlock`, which all contribute to the shared
`open_extensions` namespace package, so they can be installed together or on
their own.

```bash
pip install open-extensions
```

See the [repository](https://github.com/Kernlab-001/open-extensions) for the
specifications, the other distributions, and the full documentation.
