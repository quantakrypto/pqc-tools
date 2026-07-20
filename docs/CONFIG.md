# `quantakrypto.config.json` — Configuration

**Status: IMPLEMENTED**. This document describes the
*optional* project configuration file that `qScan` and `@quantakrypto/core` consume.
core's `loadConfig` reads + validates the file; qScan applies it under the
precedence rule below. This page is both the spec and the reference; where the
implementation narrows a "proposed" detail (see notes inline), the behavior here
is authoritative.

## 1. Motivation

Today qScan is configured entirely by CLI flags ([qscan README](../packages/qscan/README.md)),
and `ScanOptions` carries a few options that are not yet wired. A committed config file lets a project encode its scan
policy once — include/exclude globs, size limits, the severity gate, which
detector families/languages to run, and a baseline path — so CI, the editor (MCP),
and local runs agree without repeating long flag lists.

## 2. Discovery

- File name: **`quantakrypto.config.json`**, discovered at the scan `root` (i.e.
  `<root>/quantakrypto.config.json`). An absent file is tolerated — the scan proceeds
  on flags + defaults. *(The implementation looks at the scan root directly
  rather than walking up the tree; root-relative discovery is simpler and
  auditable, and `--config` covers the "config lives elsewhere" case.)*
- A `--config <path>` flag overrides discovery and names the file explicitly; a
  missing explicitly-named file is a usage error (exit 2).
- `--no-config-file` disables discovery entirely. **Note the naming:** the file
  controls are `--config` / `--no-config-file`, deliberately distinct from the
  pre-existing `--no-config` flag, which toggles config/TLS *detector scanning*
  (a different concern). They do not collide.
- Exactly **one** config file applies per run; configs do **not** merge across
  directories (no cascading), to keep precedence simple and auditable.

## 3. Precedence

Effective options are resolved with a strict, documented order. **Flags beat
config; config beats defaults.** There is no environment-variable layer in this
spec.

```
CLI flags  >  quantakrypto.config.json  >  built-in defaults
(highest)                                      (lowest)
```

Resolution is **per-key**, not all-or-nothing: a flag overrides only the key it
sets, leaving other keys to come from config or defaults. List-valued keys
(`include`, `exclude`) follow the rule in §4.2 (flags *append* by default, with an
explicit replace form) — chosen so a config baseline of excludes is additive with
ad-hoc CLI excludes, which is the common case.

## 4. Schema

A single JSON object. All keys optional. Unknown keys are a **warning, not an
error** (forward compatibility), except a malformed *value* for a known key, which
is a usage error (exit 2). JSON only (no comments) so it parses with `JSON.parse`
under [ADR-0001](adr/0001-zero-runtime-dependencies.md)'s zero-dep rule.

```jsonc
{
  "$schema": "https://quantakrypto.com/schema/quantakrypto.config.v1.json",
  "version": 1,

  // ── file selection ──────────────────────────────────────────────
  "include": ["src/**", "packages/*/src/**"],   // patterns to scan (see §4.2)
  "exclude": ["**/vendor/**", "legacy/**"],      // patterns to skip (added to defaults)
  "noDefaultIgnores": false,                     // disable node_modules/.git/dist/… ignores
  "maxFileSize": 2097152,                         // bytes; default 2 MiB

  // ── what to scan ────────────────────────────────────────────────
  "detectors": {                                  // toggle detector families
    "node-crypto": true,
    "webcrypto": true,
    "crypto-libs": true,
    "jwt-jose": true,
    "tls-config": true,
    "pem-material": true,
    "dependencies": true
  },
  "languages": ["js", "ts"],                       // forward-looking; see §4.3

  // ── policy ──────────────────────────────────────────────────────
  "severityThreshold": "high",                     // gate: critical|high|medium|low|info
  "baseline": ".quantakrypto/baseline.json"              // path to a baseline file
}
```

### 4.1 Field reference

| Key | Type | Default | Maps to | Notes |
|---|---|---|---|---|
| `version` | int | `1` | — | Config schema version. Unknown future versions are a warning + best-effort. |
| `include` | string[] | (all scannable) | `ScanOptions.include` | Substring/prefix/glob patterns (§4.2). Empty/omitted = scan everything not excluded. |
| `exclude` | string[] | `[]` | `ScanOptions.exclude` | **Added to** the built-in default ignores unless `noDefaultIgnores`. |
| `noDefaultIgnores` | bool | `false` | `ScanOptions.noDefaultIgnores` | Disables `node_modules`/`.git`/`dist`/… defaults. |
| `maxFileSize` | int (bytes) | `2097152` | `ScanOptions.maxFileSize` | Files larger are skipped; the perf/security 2 MiB cap rationale applies. |
| `detectors.<family>` | bool | `true` | maps to `source`/`config`/`dependencies` scan toggles + per-family selection | Family names mirror `@quantakrypto/core`'s detector families and the `--no-source`/`--no-deps`/`--no-config` flags. Turning a family off is equivalent to its `--no-*` flag. |
| `disabledRules` | string[] | `[]` | `ScanOptions.disabledRules` | Rule ids to suppress (e.g. `"node-crypto-ecdh"`, `"tls-weak-cipher"`). Finer-grained than `detectors.<family>`. See the catalog via `qscan list_rules` / the MCP `list_rules` tool. Unknown ids are harmless (never match). |
| `languages` | string[] | (all built-in) | (forward-looking) | See §4.3 — has no effect until the detector-registry/plugin work lands. |
| `severityThreshold` | enum | `high` | `runQscan({severityThreshold})` | Drives the exit code. CLI `--severity-threshold` overrides. |
| `baseline` | string (path) | none | `runQscan({baseline})` | Relative to the config file's directory. CLI `--baseline` overrides. |

### 4.2 Pattern and list semantics

- Patterns support **globs** and plain matching: a pattern containing `*`, `?`,
  or `[…]` is matched as an anchored glob (`*` within a path segment, `**` across
  segments, `**/` an optional path prefix, e.g. `src/**`, `**/*.ts`,
  `**/vendor/**`); a pattern with no glob metacharacter keeps the historical
  substring / path-prefix semantics (`"src"` matches `src/a.ts`, `"secrets"`
  matches anywhere).
- **`exclude`** from config is **unioned** with built-in default ignores (unless
  `noDefaultIgnores: true`) and with any CLI `--ignore` flags (CLI appends).
- **`include`** from config sets the base inclusion set; CLI include flags (if
  added) append. An explicit replace form (`"include!"` / a `--include-only`
  flag) is reserved for a future revision and out of scope here.
- Exclude always wins over include when both match a path.

### 4.3 `languages` (forward-looking)

`languages` is specified now so the file format is stable, but it is **inert**
until makes detectors a real plugin point with a
declared `language`/`scope` per detector. Until then, detector selection is via
`detectors.<family>`. When the registry lands, `languages` filters the active
detector set by declared language (e.g. `["python","go"]`).

## 5. Interaction with baselines and CI

- `baseline` in the config is equivalent to passing `--baseline` (resolved
  relative to the config file's directory); `--write-baseline` remains CLI-only
  (it is an action, not config state).
- **Only the `qscan` CLI reads `quantakrypto.config.json`.** The
  [Action](../packages/action/README.md) calls `runQscan` with its own inputs and
  does **not** auto-discover a config file, and the **MCP server does not read one
  either**. This is deliberate, not a gap: both run over trees the operator may not
  control (an untrusted fork PR; a hosted workspace), and a discovered config is
  authored by whoever owns that tree — letting it change scan strictness there would
  be a scan-integrity bypass. Config-as-shared-policy is a *trusted-local-operator*
  feature.
- **Auto-discovered vs explicit trust (CLI).** Because an auto-discovered config can
  come from the scanned tree, the CLI **warns** for each policy-weakening key a
  discovered config applies (disabled rules, a raised severity-threshold, excludes,
  scope toggles, a size cap) and points at `--no-config-file` to ignore it. A config
  named explicitly with `--config <path>` is the operator's own choice and applies
  quietly. Use `--no-config-file` to scan an untrusted tree with zero config influence.

## 6. Validation

- Parse with `JSON.parse`; on syntax error, exit 2 with the file path and offset.
- Validate value *types* against this schema; an out-of-range enum or wrong type
  for a **known** key is a usage error (exit 2). Unknown **keys** warn and are
  ignored.
- The implementation should treat the parsed object as **untrusted input** in the
  same spirit as scanned manifests ([THREAT-MODEL](THREAT-MODEL.md) Q-09): no deep
  merge of parsed config into prototypes; membership-test keys only.

## 7. Out of scope (this spec)

- An env-var configuration layer.
- Cascading/merged configs across directories.
- A JSON Schema file artifact (the `$schema` URL above is a placeholder for when
  one is published).
- Per-rule severity overrides and CWE mapping config (would pair with CWE tagging).
