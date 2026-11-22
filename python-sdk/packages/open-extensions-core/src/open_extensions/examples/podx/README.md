# PODX example

`manifest.json` describes two tracks and a one-word transcript.

`tracks/dialogue.opus` and `tracks/music.flac` are **placeholder bytes, not
real audio**. The v0.1 format does not parse or decode media, so the
packager stores the assets and verifies their length and SHA-256 digest
against the manifest. Replace them with real stems to test a real session.

```bash
open-extensions podx pack podx --manifest podx/manifest.json -o session.podx
open-extensions podx list-tracks session.podx
```
