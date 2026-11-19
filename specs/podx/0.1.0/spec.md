# PODX file format specification — 0.1.0

Status: experimental draft. No encoder/decoder is included yet.

## 1. Purpose

`.podx` packages separately addressable audio tracks (dialogue/voice, music, sound effects, ambience, or other stems), a shared timebase, word-aligned transcripts, speaker metadata, and chapter navigation into one portable file. Playback, mixing, transcript highlighting, and chapter clicks are application behavior; a container alone does not create a player.

## 2. Container layout

All integers are unsigned big-endian.

| Order | Length | Field |
|---|---:|---|
| 1 | 8 bytes | Magic `PODX 0D 0A 1A 0A` |
| 2 | 4 bytes | Manifest JSON length (1–4 MiB) |
| 3 | N bytes | Canonical UTF-8 manifest JSON |
| 4 | 8 bytes | ZIP archive length (`uint64`) |
| 5 | M bytes | ZIP/ZIP64 archive containing the audio assets |

No trailing data is allowed. ZIP encryption is forbidden. Each media asset is stored at a relative path under `tracks/`; the manifest carries its SHA-256 digest, byte length, codec, channels, sample rate, and timeline offset. ZIP paths, asset bounds, CRCs, and digests MUST be checked before playback.

## 3. Manifest model

The manifest has `format: "podx"`, `format_version: "0.1.0"`, a title, `timebase_hz`, `duration_ticks`, `tracks`, `transcript`, `chapters`, and optional `extensions`.

- `timebase_hz` MUST be `48000` in v0.1. All timestamps are integer ticks in this shared timebase; floats are forbidden.
- A track has a unique `id`, `kind`, `path`, `media_type`, `codec`, `sample_rate_hz`, `channels`, `start_tick`, `duration_ticks`, `sha256`, `byte_length`, and optional `gain_db`/`language`.
- v0.1 readers MUST support Opus in Ogg and FLAC assets. Other codecs may be represented only behind an explicit required capability and MUST NOT be silently decoded as another codec.
- `transcript.words` is a chronological array. Each word has `start_tick`, `end_tick`, `text`, and optional `track_id`, `speaker_id`, and confidence in integer parts-per-million. `0 <= start_tick < end_tick <= duration_ticks`.
- A chapter has a unique `id`, `title`, `start_tick`, `end_tick`, and optional description. Chapters MUST be ordered and MUST NOT overlap unless a future manifest capability explicitly permits overlap. Clicking a chapter seeks to its `start_tick`.
- Speaker records map stable `speaker_id` values to optional labels and locale hints. A label is display metadata, not verified identity.

A detailed JSON Schema is supplied in `schema.json`.

## 4. Audio semantics

Track offsets and durations are timeline ticks, not necessarily source sample indices. A decoder maps timeline tick `t` to source sample position using the track sample rate and offset, with rational arithmetic and a documented rounding policy. Resampling and mixing are playback-engine responsibilities. No codec-specific metadata may override the manifest timeline silently.

A renderer SHOULD allow muting/soloing each track and MUST preserve the source track assets during a lossless round-trip. Transcript word timing is approximate media metadata; it is not a guarantee of phonetic alignment precision.

## 5. Implementation plan

**Encoder:** inspect source media metadata; normalize to a declared supported codec only when asked; copy or transcode each stem; compute SHA-256/byte length; generate the 48 kHz manifest; write deterministic ZIP entries; then frame the manifest and archive lengths.

**Decoder/player:** validate framing and archive limits; validate every asset hash; expose a track graph; implement timeline-to-sample mapping; mix tracks; expose transcript seeking and chapter navigation.

**Validator:** JSON Schema + semantic checks for unique IDs, monotonic word times, chapter ordering, supported codec declarations, path safety, ZIP checksums, declared file sizes, and global duration bounds.

**CLI:** `podx inspect`, `podx validate`, `podx list-tracks`, `podx extract`, and eventually `podx render --track/--mix`. Extraction MUST be path-safe and bounded. A `render` command is not part of the v0.1 spec until codec dependency/licensing policy is fixed.

## 6. Known limitations

- The format defines a package, not a universal streaming protocol or player.
- A codec's availability and licensing vary by platform. Implementations must document codec dependencies.
- Word-level transcript timestamps can be inaccurate and should be user-editable.
