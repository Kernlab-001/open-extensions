# WAPP file format specification — 0.1.0

Status: experimental draft. No runtime or encoder/decoder is included yet.

## 1. Purpose and execution model

`.wapp` is a single-file **package** for an offline web application: HTML, CSS, JavaScript, static assets, a manifest, and optionally a seed SQLite database. It is not a native executable. Double-click opening requires a separately installed WAPP runtime registered with the operating system. A random browser cannot safely be assumed to understand the format or provide SQLite integration.

The runtime is part of the security boundary. It must create an isolated WebView/browser context, enforce the declared capability policy, and mediate database access through a narrow host API. The package itself cannot sandbox code.

## 2. Container layout

All integers are unsigned big-endian.

| Order | Length | Field |
|---|---:|---|
| 1 | 8 bytes | Magic `WAPP 0D 0A 1A 0A` |
| 2 | 4 bytes | Manifest length (1–4 MiB) |
| 3 | N bytes | Canonical UTF-8 JSON manifest |
| 4 | 8 bytes | ZIP/ZIP64 archive length |
| 5 | M bytes | ZIP archive containing `app/` files and optional `storage/seed.sqlite` |

No trailing data is allowed. ZIP encryption is forbidden. Every listed file has an exact path, length, and SHA-256 digest in the manifest. All archive safety requirements in `common/container-principles.md` apply.

## 3. Manifest and package structure

The manifest identifies `format`, `format_version`, `app_id`, `name`, `app_version`, `runtime_min`, `entrypoint`, `files`, `permissions`, `network`, `security`, and optional `storage`/`extensions`.

Required archive layout:

```text
app/index.html
app/assets/...       # referenced local CSS, JS, images, fonts, etc.
storage/seed.sqlite  # optional, read-only seed database
```

`entrypoint` MUST be a path below `app/`. The runtime MUST serve the package from a unique, non-network origin or equivalent isolated origin model; it MUST NOT simply expose the package through unrestricted `file://` access.

## 4. Permission and sandbox rules

- Default network policy is `deny`. An allowlist, if present, MUST contain exact `https` origins; wildcard hosts and implicit redirects are forbidden.
- The package MUST NOT obtain arbitrary native filesystem access. It may request only declared capabilities.
- SQLite access is exposed through a narrow, parameterized host bridge. Raw arbitrary SQL execution from untrusted page code is not the default API. Database identity and operations are scoped to the package installation.
- The seed database is immutable inside the package. On first launch, the runtime copies it to an application-owned per-user data directory; subsequent writes go to that copy.
- The runtime MUST disable unrequested camera, microphone, geolocation, clipboard, notification, downloads, popups, external protocol handlers, and file chooser access.
- The runtime MUST use the browser engine's renderer sandbox and run with ordinary user privileges, not administrator/root privileges. Host objects and message bridges must be minimized and validated.
- `security.csp` MUST specify a restrictive Content Security Policy. `default-src 'none'` is the baseline; only same-package script/style/image/connect sources and individually declared network origins may be allowed. `eval`, remote scripts, and inline scripts are disabled in the default profile.
- The runtime MUST validate the manifest and package hashes before first launch and display the publisher/trust state. Unsigned packages are untrusted, not implicitly safe.

## 5. Build plan

**Encoder/packer:** collect a web project; create a manifest; validate entrypoint, permission declarations, asset references, CSP; hash files; optionally verify and include a SQLite seed; produce the framed ZIP package.

**Decoder/runtime loader:** parse bounded framing; validate ZIP paths and hashes; mount content read-only under an isolated origin; create per-install data storage; instantiate WebView; apply permission/CSP policy; expose narrow APIs.

**Validator:** static manifest/schema checks, archive checks, forbidden capability checks, CSP checks, local-reference checks, optional static linting, SQLite integrity check, and policy consistency checks. Validation is not a security audit of arbitrary JavaScript.

**CLI:** `wapp pack`, `wapp validate`, `wapp inspect`, `wapp list`, `wapp extract`, and `wapp run`. `run` MUST require the trusted WAPP runtime; it must not execute arbitrary files directly from the CLI parser.

## 6. Known limitations

- A `.wapp` file cannot provide a cross-platform browser engine or SQLite by itself.
- A package can request permissions, but only the runtime can enforce them.
- SQLite is a storage engine, not a synchronization protocol. Multi-device sync needs a separate design.
- A package can contain malicious JavaScript. Static checks are not sufficient; runtime isolation and safe bridge design are mandatory.
