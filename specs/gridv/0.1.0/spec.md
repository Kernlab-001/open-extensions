# GRIDV file format specification — 0.1.0

Status: experimental draft. No encoder/decoder is included yet.

## 1. Purpose

`.gridv` is an append-only spreadsheet history container. It records workbook operations as ordered events so an application can reconstruct a prior state, inspect edits, and scrub backward/forward in time. It is an event log, not a promise that any spreadsheet formula or macro from another program will behave identically.

## 2. Container layout

- 9-byte magic: `GRIDV 0D 0A 1A 0A`.
- 4-byte unsigned big-endian header length (2–64 KiB), immediately after the magic.
- Canonical UTF-8 JSON header.
- Zero or more frames until EOF. Each frame is:
  - 4-byte unsigned big-endian event JSON length (2 bytes–64 MiB).
  - Canonical UTF-8 JSON event bytes.
  - 32-byte event hash.

A truncated final frame is invalid. A recovery utility may copy out the last verified prefix, but MUST write a separate recovered file and mark it as recovered; it MUST NOT silently truncate the source.

## 3. Header

The header contains `format: "gridv"`, `format_version: "0.1.0"`, `workbook_id`, `created_at`, `formula_profile: "nxf-formula-0.1"`, `time_zone: "UTC"`, `initial_state_hash`, and optional `extensions`. The first event is `workbook.create`, with sequence number 1. Its data includes the initial sheets, stable row/column/cell IDs, workbook settings, and initial state hash.

## 4. Event record and hash chain

Each event JSON object contains exactly:

- `seq`: positive contiguous integer beginning at 1.
- `event_id`: unique opaque string.
- `recorded_at`: RFC 3339 UTC timestamp.
- `actor_id`: opaque actor identifier.
- `op`: an operation name.
- `data`: operation-specific JSON object.

Let `H0` be 32 zero bytes. For event `i`, `Hi = SHA-256(H(i-1) || event_json_bytes)`. The frame stores `event_json_bytes || Hi`. The event JSON bytes use canonical JSON. This hash chain detects event deletion, reordering, and modification in the verified prefix; it does not authenticate who authored an event unless events are additionally signed by an external identity mechanism. A complete file's final chain hash is the log tip.

## 5. v0.1 event operations

Required operations:

- `workbook.create`: initial workbook state and initial sheet definitions.
- `sheet.add`, `sheet.remove`, `sheet.rename`.
- `row.insert`, `row.delete`, `column.insert`, `column.delete`.
- `cell.set`: literal cell value and type.
- `formula.set`: formula expression and formula profile.
- `style.set`: bounded cell/range style attributes.
- `checkpoint`: full materialized workbook state, the sequence it represents, and its SHA-256 digest.

Rows, columns, sheets, and cells use stable opaque IDs. Position is a property of the reconstructed state; IDs must not be re-used after deletion. Formula references resolve to stable cell identities when a formula is committed. A row/column insertion or deletion event MUST include any required formula-reference rewrites as an ordered list of `{cell_id, old_formula, new_formula}` records, so replay is deterministic and every formula change remains visible in history. A change is appended as a new event, never by mutating an old frame. v0.1 writers MUST serialize writes through one exclusive writer lock. Multi-writer branches/merge semantics are deferred.

Cell values use typed JSON objects: `{ "type": "string", "value": "..." }`, `{ "type": "decimal", "value": "12.50" }`, `{ "type": "boolean", "value": true }`, `{ "type": "date", "value": "YYYY-MM-DD" }`, or `{ "type": "empty" }`. Decimal values are strings. Formulas are stored as source strings in `formula.set` events and must conform to the formula profile.

## 6. Formula profile and deterministic replay

`nxf-formula-0.1` is a deliberately small, deterministic formula subset. Formulas begin with `=` and support parentheses; unary `+`/`-`; `^`; `*`, `/`; `+`, `-`; `&` concatenation; comparisons `=`, `<>`, `<`, `<=`, `>`, `>=`; A1 cell references; rectangular A1 ranges; and the functions `SUM`, `MIN`, `MAX`, `COUNT`, `COUNTA`, `AVERAGE`, `IF`, `AND`, `OR`, `NOT`, `ABS`, `ROUND`, `LEFT`, `RIGHT`, `LEN`, and `CONCAT`. Function names are case-insensitive; argument separators are commas; decimal separator is `.`; string literals use double quotes with doubled quote escaping. Locale is fixed to `en-US`. Numeric calculations use decimal arithmetic with 34 significant digits and round-half-even; division results are rounded to that precision. A conforming engine MUST define deterministic error values for division by zero, invalid references, type mismatch, and unsupported functions.

Formula evaluation MUST be pure and deterministic. Functions dependent on wall-clock time, randomness, network, external workbooks, filesystem, user identity, or environment are forbidden. `NOW`, `TODAY`, `RAND`, external data fetch, workbook links, macros, and user-defined functions are not part of v0.1. Date cells are ISO calendar dates; v0.1 does not define date serial arithmetic or timezone conversion.

A workbook MUST identify its formula profile. If a reader does not implement that profile, it may display source formulas and cached values but MUST NOT claim to have recalculated them correctly. Replaying to a prior sequence reconstructs the formula text and cell contents as of that event; recalculation uses the same formula profile. A formula engine version change that can alter results requires a new profile ID and explicit migration.

## 7. Checkpoints and time travel

A checkpoint stores a full state snapshot at a sequence number and a digest of canonical snapshot bytes. Readers may load the nearest verified checkpoint at or before target sequence `N`, then replay events through `N`. Checkpoints are optional accelerators, not replacements for the event history. A checkpoint digest verifies snapshot integrity relative to its event, while the event hash chain verifies its position in the log.

## 8. Validation

A validator checks framing, lengths, canonical JSON, contiguous sequence numbers, unique IDs, operation schemas, stable-reference integrity, hash chain, checkpoint digests, formula profile support, and workbook structural constraints. A hash chain alone does not prove source authenticity; signed event records are a future extension.

## 9. Build plan

**Encoder:** define workbook domain model and stable ID allocation; translate UI operations into immutable event records; serialize canonical event frames; compute chain hashes; append checkpoints at configured intervals.

**Decoder/replayer:** scan bounded frames; verify each hash before applying its operation; reconstruct state at an arbitrary sequence; use checkpoints to accelerate replay; expose event diffs.

**Validator:** validate framing, canonical JSON, sequence continuity, hash chain, event schemas, references, snapshots, and formula profile.

**CLI:** `gridv init`, `gridv validate`, `gridv log`, `gridv diff --from --to`, `gridv checkout --seq`, `gridv export --format csv|xlsx`, and `gridv recover`. Exporters must label data loss when the target format cannot represent history or formulas.

## 10. Known limitations

- Full event history grows over time; retention, checkpoint frequency, and compaction need later specification.
- Hash chaining is tamper-evident, not tamper-proof against an attacker who can rewrite the entire file and recompute hashes. Signing/trusted attestations are not in v0.1.
- Formula compatibility is difficult. The file must pin formula semantics rather than assume all spreadsheet applications agree.
- A time-travel UI is an application feature, not something the file format can render by itself.
