# Crypto-Agility Manifest - Specification

**Status: IMPLEMENTED (MVP)** (roadmap frontier initiative 13). This document
specifies a small, versioned JSON document a project publishes so any agent,
scanner, or CI bot can read its cryptographic posture the way it already reads
`security.txt` or `robots.txt`.

AI coding agents and CI bots increasingly make dependency and cryptography choices,
but there is no standard place for them to learn a project's crypto posture, policy,
and migration deadlines. Today every integration is bespoke. The crypto-agility
manifest is a proposed, machine-readable convention for that place: a summary of a
repo or site's PQC posture, its CBOM summary, an optional attestation link, and its
migration policy.

The manifest is deliberately a **summary**, not a replacement for the full CBOM or
the readiness report. It is small enough to fetch and parse on every CI run and
answers three questions at a glance: how ready is this project, what quantum-broken
crypto is it still using, and by when has it committed to migrate.

## 1. The well-known URL convention

A site or repo publishes its manifest at:

```
https://<origin>/.well-known/crypto-agility.json
```

This follows RFC 8615 (well-known URIs), the same mechanism behind
`/.well-known/security.txt`. A consumer that knows only an origin can discover the
manifest without out-of-band configuration.

- **For a website / service**: serve the file at that path from the web root.
- **For a source repository**: commit the file at `.well-known/crypto-agility.json`
  at the repo root, and regenerate it in CI (see section 6).

The `Content-Type` should be `application/json`. The document is public by design:
it contains posture summary data, never secrets, snippets, or file contents.

## 2. Schema

The manifest is a single JSON object. `version` is an integer schema version;
consumers MUST branch on it and MUST reject a version they do not understand. All
fields below are **required** unless marked optional.

| Field | Type | Meaning |
|---|---|---|
| `version` | integer | Manifest schema version. `1` for this spec. |
| `manifestType` | `"crypto-agility"` | Discriminator so a consumer can tell this document apart from other JSON. |
| `generatedAt` | string (ISO 8601) | When the manifest was generated. Supplied by the generator's runtime clock. |
| `generator` | object | What produced the manifest: `{ name, version }`. |
| `subject` | object | What the manifest describes: `{ root, repository, commit }`. `repository` / `commit` are `null` when unknown. |
| `posture` | object | The distilled cryptographic posture (section 3). |
| `cbomSummary` | object | A compact summary of the CBOM (section 4). |
| `attestation` | object (optional) | `{ url }` - a link to a posture credential (section 5). Omitted when none is declared. |
| `policy` | object | The declared migration policy / deadlines (section 6). |

### 3. `posture`

| Field | Type | Meaning |
|---|---|---|
| `readinessScore` | number `0..100` | qScan's readiness score. `100` = no classical asymmetric crypto found. |
| `hybridKexInUse` | boolean \| null | Whether the project negotiates hybrid PQC key exchange. See the note below. |
| `quantumVulnerable.total` | number | Count of quantum-vulnerable findings. |
| `quantumVulnerable.bySeverity` | object | Counts keyed by `critical` / `high` / `medium` / `low` / `info` (all keys present). |
| `hndlExposedCount` | number | How many findings are exposed to harvest-now-decrypt-later. |

**On `hybridKexInUse`.** A static source scan cannot observe a negotiated TLS group,
so the emitter reports `null` ("not determined by this generator") by default. An
operator may assert it (`--hybrid-kex` / `--no-hybrid-kex`), and a live probe
(qProbe) or the website can fill it authoritatively. Consumers MUST treat `null` as
"unknown", distinct from `false`.

Every family qScan surfaces is classical public-key crypto and therefore
quantum-vulnerable by construction; `quantumVulnerable.total` equals the finding
count for that reason.

### 4. `cbomSummary`

A pointer to, and a digest of, the full CycloneDX CBOM (`qscan --cbom`).

| Field | Type | Meaning |
|---|---|---|
| `serialNumber` | string | The CycloneDX `serialNumber` (`urn:uuid:...`) of the full CBOM this summary was derived from. Deterministic for a given scan, so it links the manifest to a specific CBOM instance. |
| `assetCount` | number | Number of distinct `cryptographic-asset` components in the full CBOM. |
| `algorithmFamilies` | array | `{ family, count, quantumVulnerable }` per algorithm family in use, most-referenced first. |

The full CBOM is intentionally NOT inlined: the manifest stays small, and a consumer
that needs component-level detail fetches the CBOM itself.

### 5. `attestation` (optional)

```json
"attestation": { "url": "https://quantakrypto.com/attest/acme" }
```

An optional link to a machine-verifiable posture credential (for example a
quantakrypto attestation). The manifest records the URL **verbatim and never fetches
it** - qScan is offline by boundary (section 7). Verifying the credential behind the
link is a consumer-side / website-side step.

### 6. `policy`

The migration policy the project declares it is measured against.

| Field | Type | Meaning |
|---|---|---|
| `source` | string | Label for the policy source: a standard's name, or `operator-declared`. |
| `deprecateClassicalAfter` | number (year) | Year after which classical public-key crypto is deprecated. |
| `disallowClassicalAfter` | number (year) | Year after which it is disallowed. |
| `transitionDeadline` | string \| null | An operator-declared migration deadline (ISO date / year), or `null`. |
| `citation` | string | Citation for the deadlines. |

By default the emitter fills the deadlines from the NIST IR 8547 transition timeline
(deprecate after 2030, disallow after 2035). Supplying a crypto policy
(`--policy <file>`, the same file `--format evidence` accepts) re-labels `source` as
`operator-declared` and overlays the policy's `transitionDeadline`. CNSA 2.0
national-security milestones (2030 / 2033) are a valid operator-declared choice —
and the `--mandate cnsa-2.0` gate encodes CNSA's own 2030-deprecate / 2033-disallow
timeline (distinct from IR 8547's 2035), so the manifest and the gate agree on CNSA
if you declare 2033.

## 7. How to consume it (agents / CI)

1. Resolve the origin and fetch `https://<origin>/.well-known/crypto-agility.json`.
2. Parse the JSON and check `manifestType === "crypto-agility"` and `version === 1`.
   Reject an unknown `version`.
3. Read `posture.readinessScore` and `posture.quantumVulnerable` for a gate, e.g.
   fail a dependency-introduction bot if a candidate dependency's own manifest shows
   `critical > 0`, or warn when `readinessScore` is below a threshold.
4. Read `policy` to know the deadlines the project has committed to, and
   `attestation.url` to verify posture out-of-band if a credential is present.

A local (already-downloaded) manifest can be checked with the reference validator:

```
qscan crypto-agility validate ./path/to/crypto-agility.json
```

Exit `0` = valid, `1` = the file parsed but is not a conforming manifest (each
problem is printed), `2` = the file could not be read.

## 8. How to produce it (qScan)

```
# Write the manifest to the conventional path and regenerate it in CI:
qscan . --crypto-agility -o .well-known/crypto-agility.json

# Equivalent explicit subcommand:
qscan crypto-agility emit . -o .well-known/crypto-agility.json

# With an attestation link, a hybrid-KEX assertion, and an operator policy:
qscan crypto-agility emit . \
  --attestation https://quantakrypto.com/attest/acme \
  --hybrid-kex \
  --policy ./crypto-policy.json \
  -o .well-known/crypto-agility.json
```

Emitting is **additive**: it runs a scan and derives the manifest, but it **always
exits 0** and never consults the severity threshold - publishing a posture document
must not fail CI. The manifest's posture and CBOM summary are derived from the same
scan inventory and CBOM as `--format json` / `--cbom`, so they can never disagree
with the full outputs of the same scan.

## 9. Offline boundary

The qScan emitter and validator are strictly offline. The validator checks a
**local** file against this schema; it does not, and by design must not, fetch a
remote manifest or the `attestation.url`. Fetching, resolving, and validating a
**remote** manifest over the network (and verifying the credential behind the
attestation link) is a **website-side follow-up**, kept out of the scanner so the
tool never makes network calls on a user's behalf.

## 10. Example

```json
{
  "version": 1,
  "manifestType": "crypto-agility",
  "generatedAt": "2026-07-27T04:57:12.323Z",
  "generator": { "name": "qScan", "version": "0.9.0" },
  "subject": { "root": ".", "repository": null, "commit": null },
  "posture": {
    "readinessScore": 74,
    "hybridKexInUse": true,
    "quantumVulnerable": {
      "total": 2,
      "bySeverity": { "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0 }
    },
    "hndlExposedCount": 2
  },
  "cbomSummary": {
    "serialNumber": "urn:uuid:5834348b-e27b-4f71-8752-f0497d98166f",
    "assetCount": 2,
    "algorithmFamilies": [
      { "family": "ECDH", "count": 1, "quantumVulnerable": true },
      { "family": "RSA", "count": 1, "quantumVulnerable": true }
    ]
  },
  "attestation": { "url": "https://quantakrypto.com/attest/acme" },
  "policy": {
    "source": "NIST IR 8547 (transition to post-quantum cryptography standards)",
    "deprecateClassicalAfter": 2030,
    "disallowClassicalAfter": 2035,
    "transitionDeadline": null,
    "citation": "NIST IR 8547 (transition to post-quantum cryptography standards)"
  }
}
```

## 11. Versioning and follow-ups

`version` is the schema's contract. Additive, backward-compatible fields may be added
under `version: 1`; any breaking change bumps `version` and this document.

Planned follow-ups (not in this MVP):

- **Website-side remote validator**: fetch `https://<origin>/.well-known/crypto-agility.json`,
  validate it, and verify the `attestation.url` credential. Deliberately excluded
  from qScan (section 9).
- **MCP reader**: the quantakrypto MCP consuming a manifest so an agent can query a
  project's posture through the same transport it already uses for crypto context.
