# STEPX file format specification — 0.1.0

Status: experimental draft. No encoder/decoder is included yet.

## 1. Purpose

`.stepx` is a portable, structured instruction document for recipes, DIY projects, repair procedures, and other step-driven guides. It models quantities, yields, step timers, prerequisites, and conditional substitutions as data. It does not execute embedded scripts; v0.1 has no script field.

## 2. Container layout

- Bytes 0–8: 9-byte magic `STEPX 0D 0A 1A 0A`.
- Bytes 9–12: unsigned 32-bit big-endian JSON body length, 2 bytes to 8 MiB.
- Remaining bytes: exactly that many canonical UTF-8 JSON bytes.
- No trailing bytes are allowed. v0.1 carries no embedded media; images may be referenced by an application-level catalog in a later version, not fetched automatically by a reader.

## 3. Data model

The root object has `format: "stepx"`, `format_version: "0.1.0"`, `title`, `category`, `base_yield`, `yield_unit`, `ingredients`, `steps`, and optional `conditions`/`extensions`.

### 3.1 Quantities and scaling

Ingredient quantities MUST be decimal strings (examples: `"1"`, `"0.5"`, `"0.125"`) to avoid binary floating-point rounding. Each ingredient has a stable `id`, `name`, `quantity`, `unit`, and optional preparation note. `base_yield` is a positive decimal string. A consumer scaling to target yield `Y` computes `factor = Y / base_yield`, then scales ingredients marked `scale_mode: "linear"`. v0.1 also allows `scale_mode: "fixed"` for ingredients that should not change. Unit conversion is not implicit: grams, millilitres, teaspoons, and item counts are not interchangeable without a declared unit conversion profile.

### 3.2 Steps and timers

Each step has a unique `id`, integer `order`, `title`, `instruction`, optional `ingredient_refs`, optional `timer`, optional `requires`, and optional `substitutions`. A timer contains `duration_seconds` (integer, bounded), `label`, and `start_policy` (`manual` or `on_step_open`). The reader presents a timer; the file does not run a background process or guarantee timer accuracy when the application is suspended.

### 3.3 Conditions and substitutions

Substitution rules use a constrained declarative condition DSL, never JavaScript, Python, SQL, or shell. A condition is an array of clauses with `variable`, `operator`, and a JSON scalar `value`. v0.1 operators are `eq`, `neq`, `in`, and `not_in`; all clauses in a rule are ANDed. Variables are values supplied by the user/application, for example `diet`, `allergens`, `equipment`, or `region`. Unknown variables evaluate as `unknown`; a reader MUST NOT treat unknown as true. A substitution identifies the ingredient it replaces, a replacement ingredient, a reason, and an optional condition.

## 4. Validation

A validator checks framing, canonical JSON, schema, unique IDs, valid ingredient references, step order, timers, exact decimal syntax, and safe condition operators. It SHOULD detect cyclic prerequisites and substitutions. It MUST NOT execute text in an instruction field.

## 5. Build plan

**Encoder:** model recipe/project entities; normalize decimals and IDs; validate references and condition clauses; serialize canonical JSON with the magic and length prefix.

**Decoder:** parse bounded framing; reject duplicate keys and unsupported required features; return immutable domain objects; expose a safe condition evaluator and decimal scaling function.

**Validator:** schema plus semantic checks for references, order, decimal ranges, timer bounds, condition-variable allowlists, and cycles.

**CLI:** `stepx validate`, `stepx inspect`, `stepx scale --yield`, `stepx render --format text|markdown`, and eventually `stepx timer` in a companion UI. A terminal timer is a convenience feature, not a timing guarantee.

## 6. Known limitations

- Ingredient scaling is not a substitute for culinary, chemical, structural, or safety judgment. Some quantities do not scale linearly.
- v0.1 does not embed pictures, video, or executable actions.
- Condition variables are application-defined and must be visible to the user.
