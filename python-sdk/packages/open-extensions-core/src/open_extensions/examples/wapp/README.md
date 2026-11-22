# WAPP example

`manifest.json` describes a two-file offline app with no permissions and a
deny-by-default network policy. `app/index.html` and `app/style.css` are the
files it references.

```bash
open-extensions wapp pack wapp --manifest wapp/manifest.json -o app.wapp
open-extensions wapp validate app.wapp
open-extensions wapp run app.wapp
```

`wapp run` serves the package on the loopback interface for development
inspection. It is not a security-enforcing runtime.
