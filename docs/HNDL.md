# HNDL Exposure Model - Methodology

**Status: IMPLEMENTED** (roadmap initiative 2.a/2.b). This document specifies how
`@quantakrypto/core` and `qScan` turn a crypto finding plus a declared data map
(`hndl.yml`) into a single, contestable **exposure score**. It is published so the
score can be argued with, not treated as magic.

HNDL = "harvest now, decrypt later": an adversary records ciphertext today and
decrypts it once a cryptographically-relevant quantum computer (CRQC) exists. A
finding count answers "what is broken". An exposure score answers "how much does
it matter" - so a migration backlog can be ranked by real risk.

## 1. The formula

For each finding, exposure is the product of three factors, each normalised to
`0..1`, reported as an integer `0..100`:

```
exposure_score = round( 100 · V · S · M )
```

- **V - crypto-vulnerability**: how breakable, and how confidently detected, the
  crypto is.
- **S - data-sensitivity**: the declared sensitivity class of the data the finding
  sits next to.
- **M - Mosca-factor**: how much of the data's protection horizon extends *beyond*
  the quantum-threat horizon. This is Mosca's inequality made concrete.

A product (not a sum) is deliberate: an exposure needs all three to be non-trivial.
Perfectly-broken crypto over public data that nobody keeps is not an HNDL problem,
and the score says so (M or S drives it to ~0).

## 2. V - crypto-vulnerability

```
V = severityWeight(severity) · confidenceWeight(confidence) · (hndl ? 1 : NON_HNDL_DISCOUNT)
```

| severity | weight | | confidence | weight |
| --- | --- | --- | --- | --- |
| critical | 1.00 | | high | 1.00 |
| high | 0.80 | | medium | 0.85 |
| medium | 0.50 | | low | 0.60 |
| low | 0.25 | | | |
| info | 0.10 | | | |

`NON_HNDL_DISCOUNT = 0.15`. A finding with `hndl: false` (typically a **signature**:
ECDSA/EdDSA/RSA-PSS) is discounted hard, because a forged signature is a
future-integrity problem, not a retroactive-confidentiality one - you cannot break
a signature *today's captured data* was never protected by. Confidentiality
findings (KEM / key-exchange / TLS key agreement) carry `hndl: true` and keep full
weight.

## 3. S - data-sensitivity

The classification declared for the bound asset, mapped to a weight:

| classification | weight |
| --- | --- |
| public | 0.10 |
| internal | 0.40 |
| confidential | 0.70 |
| regulated | 1.00 |

The vocabulary matches the readiness model's data-protection (DPE) practice.
A finding that binds to **no** declared asset is scored with the map's
`defaults.classification` (default `internal`) and flagged `bound: false`, so a
fallback score is never mistaken for a declared one.

## 4. M - the Mosca-factor

Mosca's inequality: you have a problem when

```
X + Y > Z
```

where, in years:

- **X** = the data's protection requirement = `max(retention_years, secrecy_lifetime_years)`.
  Data captured today must stay confidential for X more years.
- **Y** = `migration_horizon_years`: how long your PQC migration takes. Until it
  finishes, new data keeps being harvested under vulnerable crypto.
- **Z** = `quantum_threat_years`: years until a CRQC is assumed to exist.

We normalise the magnitude of the breach into `0..1` as the fraction of the whole
protection horizon that falls *after* the threat arrives:

```
M = clamp( (X + Y − Z) / (X + Y), 0, 1 )
```

- `M = 0` when `Z ≥ X + Y` - the threat is beyond the entire horizon; no HNDL risk.
- `M = 1` when `Z = 0` - the threat is already here.
- `M > 0` is exactly Mosca's inequality being breached; `moscaMarginYears = X + Y − Z`
  is reported alongside so the raw years are visible.

Defaults: `quantum_threat_years = 15` (a defensible mid-point of the commonly-cited
Mosca / NIST window), `migration_horizon_years = 5`. Both are overridable per-org in
`hndl.yml` - the model is only as honest as those two numbers, so they are declared,
not hidden.

### Worked example

An RSA KMS key (`high` severity, `high` confidence, `hndl: true`) in `src/db/`,
bound to a `regulated` asset with `retention_years: 7`, `secrecy_lifetime_years: 25`,
under `quantum_threat_years: 10`, `migration_horizon_years: 5`:

```
V = 0.80 · 1.00 · 1        = 0.80
S = 1.00 (regulated)       = 1.00
X = max(7, 25)             = 25
M = (25 + 5 − 10)/(25 + 5) = 20/30 ≈ 0.667
exposure = round(100 · 0.80 · 1.00 · 0.667) = 53
```

The same finding over a `public`, 1-year-retention marketing asset scores **0**:
`X + Y = 6 < Z = 10`, so `M = 0`. The Mosca-factor, not the finding, is doing the
ranking.

## 5. Binding findings to assets

A finding binds to a declared asset when:

1. the finding's file matches one of the asset's `paths` globs (`**`, `*`, `?`), **and**
2. the asset either declares no `scopes`, or lists the finding's scope.

A finding's **scope** is `dependency` for manifest findings, otherwise the emitting
detector's scope (`config` for the KMS / secrets-at-rest / pgcrypto / broker /
JOSE-JWE join points, `source` for inline code). Config-scope detectors are the
natural crypto-to-data adjacency: they already know they sit next to data.

When **several** assets match, the **worst-case** (highest) exposure is taken and its
asset recorded. Risk ranking must not be diluted by an incidental low-sensitivity
overlap.

The whole computation is **additive**: it never mutates findings, never changes
finding identity or ordering, and never affects a scan's exit code.

## 6. `hndl.yml` schema

Hand-rolled, zero-dependency parsing (ADR-0001): no YAML library is pulled in. The
supported subset is block mappings/sequences, `# comments`, quoted scalars, and
inline-flow lists (`paths: ["a/**", "b/**"]`). Tabs are rejected.

```yaml
version: 1

horizon:
  quantum_threat_years: 15      # Z: years until a CRQC is assumed
  migration_horizon_years: 5    # Y: years to finish your PQC migration

defaults:
  classification: internal      # applied to findings that match no asset below

assets:
  - key: customer-pii           # stable id (the join key stored downstream)
    name: Customer PII store
    classification: regulated    # public | internal | confidential | regulated
    retention_years: 7
    secrecy_lifetime_years: 25
    paths:
      - "src/db/**"
      - "services/pii/**"
    scopes:                      # optional: source | config | dependency
      - config
```

Scaffold one from a scan with `qscan hndl init` - it seeds an asset stub per
directory that contains a data-adjacent (config-scope, HNDL) finding.

## 7. CLI surface

- `qscan ./ --hndl` - reads `hndl.yml` at the scan root, scores every finding and a
  repo summary, and adds the exposure fields to the `json` / `sarif` reports (and an
  exposure section to the human report). A missing / malformed `hndl.yml` is a loud
  error (exit 2); the user opted in.
- `qscan hndl init [path]` - scaffolds `hndl.yml` seeded with detected data-adjacent
  findings. Refuses to overwrite an existing file.

## 8. Output fields (for downstream ingest)

Per finding, under `findings[].exposure` (JSON) / result `properties` (SARIF):

| field | meaning |
| --- | --- |
| `fingerprint` | finding identity + join key (see §9) |
| `exposureScore` | 0..100 integer |
| `dataAsset` | bound asset `key`, or `null` when unbound |
| `rationale` | full breakdown: `vulnerability`, `sensitivity`, `mosca`, `classification`, `retentionYears`, `secrecyLifetimeYears`, `secrecyHorizonYears`, `quantumThreatYears`, `migrationHorizonYears`, `moscaMarginYears`, `moscaBreach`, `hndl`, `severity`, `confidence`, `scope`, `bound` |

Repo summary, under `hndl` (JSON) / run `properties.hndl` (SARIF): `modelVersion`,
`horizon`, `assets[]` rollups, and `summary` (`findingsScored`, `assetsDeclared`,
`assetsWithFindings`, `assetsOutlivingHorizon`, `moscaBreaches`, `maxExposure`,
`meanExposure`, `topExposures`).

The website ingest maps these onto its `data_asset` (key, classification,
retention_years, secrecy_lifetime_years) and `finding_exposure` (fingerprint,
data_asset_id, exposure_score, rationale) tables - see the implementation plan.

## 9. Fingerprint integration point

Exposures are keyed by finding fingerprint so the website can join them to
`posture_snapshot` rows. `findingFingerprint(f)` prefers a `finding.fingerprint`
field when a build supplies one (another workstream is adding it to core's `Finding`
type + reporters), and falls back to the canonical
`fingerprintFinding()` hash - `sha256(ruleId | file | normalizedSnippet)` - otherwise.
Today this code path uses the fallback. When `Finding.fingerprint` lands, exposure
keying switches to it transparently, with no caller change.

## 10. Calibration

The weight tables and the two horizon defaults are the model's tunable surface,
exported as constants (`SEVERITY_VULNERABILITY`, `CONFIDENCE_WEIGHT`,
`CLASSIFICATION_SENSITIVITY`, `NON_HNDL_DISCOUNT`, `DEFAULT_QUANTUM_THREAT_YEARS`,
`DEFAULT_MIGRATION_HORIZON_YEARS`). `HNDL_MODEL_VERSION` is stamped into every report;
bump it on any weight or formula change so historical scores remain interpretable.
Roadmap phase 2.d calibrates these against real design-partner data maps.
