# CLI workspace

The initial CLI is shipped by the Python package as the `open-extensions` command. Install it from `python-sdk/` with `python -m pip install -e .`.

Future format-specific commands should be namespaced (`open-extensions memx ...`, `open-extensions podx ...`) once multiple SDKs and plugins exist. The initial v0.1 executable uses explicit verbs (`memx-create`, `memx-read`, `memx-validate`, `memx-inspect`) to keep the command surface stable while only one format is implemented.
