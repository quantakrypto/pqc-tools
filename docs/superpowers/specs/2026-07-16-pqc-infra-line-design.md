# Design — the `pqc-infra` line: post-quantum readiness for infrastructure

**Date:** 2026-07-16
**Status:** Approved in shape (in-repo, reuse `@quantakrypto/core`); pending spec review
**Author:** (worktree `pqc-infra-line`)

## 1. Goal

`@quantakrypto/qscan` answers *"is my **code** quantum-safe?"* This line answers
*"is my **infrastructure** quantum-safe?"* — the crypto that lives in
infrastructure-as-code, CI/CD pipelines, secrets stores, data-at-rest / messaging
config, and on the wire between running systems.

The narrative anchor is **Harvest Now, Decrypt Later (HNDL)**: ciphertext and
long-lived keys captured today are decryptable once a cryptographically-relevant
quantum computer (CRQC) exists. For infrastructure, that risk has *already begun*
for anything recorded or persisted — "your 2019 backups are the breach of 2033."
The `hndl` boolean is already first-class in `core`'s `Finding` type, so this
scores naturally.

## 2. Non-goals

- **No modification of any existing package** (`core`, `qscan`, `mcp`, `sieve`,
  `action`, `agent`). A second agent is actively editing those. This line
  consumes `core` **as-is** through its locked public API and adds only new
  packages. The *only* shared-root edit is appending new entries to root
  `tsconfig.json` `references` (two lines per package) — resolved at merge time.
- **No crypto implementation.** Like the rest of the repo, we detect and report;
  we never perform or "fix" live crypto.
- **No cloud-provider SDKs / API calls** in the static engine. Config files, plan
  JSON, and exported inventories only. (The one networked package, `qprobe`, is
  isolated exactly like `@quantakrypto/agent`.)
- **Zero runtime dependencies** — Node built-ins + `@quantakrypto/*` only,
  enforced by the existing `scripts/check-zero-deps.mjs`.

## 3. Architecture

A new set of packages inside the existing monorepo, all built on `core`'s locked
contract (`Detector` / `RuleMeta` / `Finding` / `DetectorRegistry`, `buildInventory`
score, `toSarif` / `toJson` / `toCbom`, `severity*`, baseline, redactor, `walkFiles`,
CWE constants — all already exported from `packages/core/src/index.ts`).

```
packages/
├── infra-core/    @quantakrypto/infra-core   — infra detector contract helpers +
│                                                zero-dep YAML/JSON (+ later HCL-subset)
│                                                structural parsers. Depends on core.
├── qinfra/        @quantakrypto/qinfra        — CLI (bin: qinfra). Static detector packs:
│                                                iac · cicd · secrets · data
├── qprobe/        @quantakrypto/qprobe        — ⚠ the ONLY networked package: active
│                                                TLS/SSH/mail handshake probing. Hard-gated.
├── mcp-infra/     @quantakrypto/qinfra-mcp    — MCP server exposing infra tools to AI agents
└── action-infra/  @quantakrypto/qinfra-action — GitHub Action CI gate (fails on NEW findings)
```

**Why `infra-core` separate from `qinfra`:** the structural parsers (YAML/JSON,
later HCL subset) and the shared infra-detector helpers are reused by `qprobe`
(cert/PEM handling), `mcp-infra`, and `action-infra`. Keeping them in one small
library mirrors how `core` underpins every product shell in the parent repo.

### 3.1 The reuse boundary (what comes from `core`, unchanged)

| Concern | Source in `core` | Used how |
|---|---|---|
| Detector/Finding/RuleMeta contract | `types.js` (`export *`) | infra detectors implement `Detector` with `scope: "config"` |
| Registry / rule catalog | `DetectorRegistry`, `detectorScope` | `qinfra` builds its own registry of infra detectors |
| Readiness score | `buildInventory` | same math → comparable to qScan scores |
| Severity | `SEVERITY_ORDER`, `severityRank`, `meetsThreshold`, `sarifLevel` | thresholds + SARIF levels |
| Reporters | `toSarif`, `toJson`, `formatSummary` | identical output formats |
| CBOM | `toCbom`, `CycloneDxBom`, `CbomComponent` | CycloneDX 1.6 crypto assets |
| Baseline | `fingerprintFinding`, `applyBaseline`, … | "fail only on NEW findings" in CI |
| Redactor | `buildContext`, `renderPreflight` | never leak keys/secrets into output or LLM context |
| Walker | `walkFiles`, `isBinaryPath`, `isGeneratedPath` | file discovery |
| CWE | `CWE_BROKEN_CRYPTO`, `CWE_WEAK_STRENGTH`, `CWE_CERT_VALIDATION`, … | stamped on rules |

If a genuine gap in `core` appears (e.g. a `Finding.category` value or a CBOM
`assetType` we can't express), the fallback is to model it **within our packages**
and file a note for a later, coordinated `core` change — never an unilateral edit
while the other agent is in `core`.

### 3.2 The combined "code + infra" readiness score

Because both halves emit CycloneDX 1.6, a top-level report can join a qScan CBOM
and a qinfra CBOM via CycloneDX `bom-link`, producing a single organisation-wide
readiness posture over *code and infrastructure* — a differentiator no current
tool offers. This is a v0.2 reporting feature, not part of the MVP.

## 4. Detector packs (static engine — `qinfra`)

Each pack is a set of `Detector`s. Rules carry `RuleMeta` (id, severity, CWE,
remediation, `hndl`). Findings feed the shared reporters and score.

**`iac`** — Terraform/OpenTofu (`.tf.json` + `terraform show -json` plan first;
subset-HCL for `.tf` later), Kubernetes/Helm-rendered/Kustomize YAML, cert-manager
`Certificate`/`Issuer` key algorithms, cloud KMS key specs (RSA/ECC vs ML-DSA),
LB/API-GW/CloudFront TLS policies, service-mesh (Istio/Linkerd) mTLS floors,
CloudFormation/ARM/Bicep JSON. K8s `kubernetes.io/tls` secrets are base64-decoded
and handed to `core`'s **PEM classifier** (direct reuse).

**`cicd`** — GitHub Actions / GitLab CI / Jenkinsfile: cosign (key + keyless
Fulcio → ECDSA), GPG signing (RSA), SLSA provenance without a PQ-signature plan,
`jarsigner`/`codesign`, checked-in signing certs. The forward-looking analog of
HNDL: long-lived artifact signatures are forgeable once a CRQC exists.

**`secrets`** — SOPS (`.sops.yaml` + plaintext metadata blocks: `age1…` = X25519,
`pgp:` = RSA), sealed-secrets (RSA cert), `ansible-vault` headers, Vault
`pki`/`transit` key specs, K8s encryption-provider config. The purest HNDL story:
SOPS ciphertext committed to git is replicated, immortal, and retroactively
un-fixable (you can re-encrypt HEAD, not history).

**`data`** — JOSE/JWT/JWE (header decode only; distinguish **confidentiality**
`alg` like `RSA-OAEP`/`ECDH-ES` = HNDL-critical from **signature** `RS256`/`ES256`
= forgery-at-CRQC), JWKS (offline/file), SAML `SignatureMethod`, PASETO, DB
connection/TLS + TDE config (`sslmode`, cipher, TDE KEK algorithm), pgcrypto
public-key calls, Kafka/RabbitMQ/MQTT/NATS TLS + mechanism config, keystore
(JKS/PKCS12) and PEM inventory. TLS-PSK on IoT is surfaced as a rare **positive**
signal.

## 5. `qprobe` — the gated networked plane

The only package that opens sockets. Isolated exactly like `@quantakrypto/agent`.

- **Capabilities:** active TLS 1.3 handshake (via `node:tls` for negotiated
  suite + full DER cert chain, and a **hand-rolled raw ClientHello over
  `node:net`** advertising `X25519MLKEM768` (codepoint `0x11EC`) to detect
  PQC-hybrid support — Node's bundled OpenSSL can't negotiate it, so a byte-level
  ClientHello/ServerHello parser is required, in the same hand-rolled, **fuzzed**
  style as `core`'s existing parsers). SSH KEXINIT (cleartext, pre-encryption
  name-lists — `sntrup761x25519`, `mlkem768x25519`). SMTP STARTTLS + MTA-STS.
- **`engine disposes`:** reports the negotiated reality; never mutates an endpoint.
- **Hard gate (mandatory, first-class — not a footnote):**
  - `--i-own-this` ownership attestation (or an ownership-manifest file) required
    before any connection; **refuses CIDR/range sweeps** without attestation.
  - Per-host rate limiting; single benign handshake semantics.
  - A dedicated **`THREAT-MODEL.md`** section covering authorization scope,
    CFAA-style concerns, redaction of any captured material, and a default mode
    that consumes **externally-captured** input (pcap/JSON/cert dumps) for
    endpoints you don't own.
- **Zero-dep:** raw sockets via `node:net`/`node:tls`, cert parsing via
  `node:crypto` `X509Certificate`. No native code.

## 6. Parsers (zero-dep, fuzzed)

- **JSON** — `JSON.parse` (native). Terraform `.tf.json` + plan JSON, CloudFormation
  JSON, ARM, CDK synth, JWKS, JWT/JWE header decode (base64url).
- **YAML subset** — hand-rolled: block maps/sequences, scalars, multi-doc `---`.
  Anchors/aliases/complex tags → downgrade the finding to a warning with an
  "unresolved" note rather than guess. Reused across `iac`/`secrets`/`data`.
- **HCL subset (v0.2)** — blocks + attributes + literals (95% of crypto-relevant
  stanzas); unresolved expressions → warning. `.tf.json`/plan-JSON ship first so
  Terraform coverage does not block on full HCL2.
- **Binary headers (v0.2)** — JKS/PKCS12, LUKS2 JSON header, OpenPGP packet
  headers — all documented formats, dep-free.

Every hand-rolled parser gets a fuzz test, matching the repo's existing discipline.

## 7. Reporting & scoring

Identical to qScan: human text (TTY/`NO_COLOR`-aware), JSON, SARIF 2.1.0 (rules
from the catalog, CWE taxonomy), CBOM (CycloneDX 1.6 `cryptographic-asset`,
`related-crypto-material` for KEK/DEK hierarchies and certificate assets). Exit
codes mirror qScan (`OK:0`, `FINDINGS:1`, `ERROR:2`). Baseline-driven
"fail-only-on-new" for CI.

## 8. Testing

- `node:test` via `tsx`, per package, matching the repo.
- Fixture corpora per pack (real-world Terraform/K8s/CI/SOPS/JWT samples) with a
  precision/recall benchmark, mirroring qScan's `= 1.000` target.
- Fuzz tests for every hand-rolled parser and for `qprobe`'s ClientHello/ServerHello
  and KEXINIT byte parsers.
- `qprobe` gets negative tests proving it refuses to connect without attestation.

## 9. CLI / MCP / Action patterns (mirrored from parent)

- **`qinfra` CLI**: thin `cli.ts` (argv → `runQinfra` → print → exit code, never
  throws) over a programmatic `index.ts`; hand-rolled arg parser; config
  resolution flags > `quantakrypto.config.json` > defaults.
- **`qinfra-mcp`**: hand-rolled JSON-RPC/MCP `handle(message)` core with
  stdio + http transports; tools `scan_infra`, `inventory_infra_crypto`,
  `explain_finding`, `generate_infra_cbom`, `probe_endpoint` (probe gated + offline
  by default); host paths scrubbed from errors.
- **`qinfra-action`**: `action.yml` (node20, esbuild `dist/`), wraps the
  programmatic API, annotates diffs, fails only on new findings; outputs
  `findings-count`, `sarif-file`, `readiness-score`.

## 10. Phasing (all in this one repo / worktree)

1. **Phase 1 — static engine + packs.** `infra-core` + `qinfra` with `iac`
   (JSON/YAML-subset first), `cicd`, `secrets`, `data`. Full SARIF/JSON/CBOM/score,
   tests, docs. Zero authorization risk. **This is the working MVP.**
2. **Phase 2 — `qprobe`.** Gated active prober + `THREAT-MODEL.md`. Subset-HCL and
   binary-header parsers land here too.
3. **Phase 3 — `qinfra-mcp` + `qinfra-action`.** Agent + CI surfaces. Combined
   code+infra CBOM `bom-link` report.

## 11. Deliverables

- The new packages above, built + tested green, committed on branch
  `pqc-infra-line`, merged into `qproof-tools` `main` at the end (conflicts, if
  any, resolved then). **No push/publish without explicit confirmation.**
- Documentation: root README section, per-package READMEs, `qprobe`
  `THREAT-MODEL.md`, and `docs/` entries (an infra how-to + a roadmap update).
- A new **`/tools`-style page on quantakrypto.com** (the `qproof` Next.js app,
  `~/development/qproof`) presenting the infra line, matching the existing
  `src/app/[locale]/tools` conventions and i18n. Delivered as new content only.

## 12. Concurrency / conflict plan

- All work in the `pqc-infra-line` worktree (`~/development/qproof-tools-worktrees/pqc-infra-line`).
- Touch only new files; the single shared edit is root `tsconfig.json`
  `references` additions.
- The website page lives in a *different* repo (`qproof`) with no concurrent
  agent — lower risk; still additive-only.
- Merge to `qproof-tools` `main` at the very end; rebase/merge and resolve any
  conflicts from the other agent's committed work before integrating.

## 13. Locked decisions

- In-repo (not a separate `pqc-infra` repo); reuse `core` via workspace link.
- Everything phased in one repo; **`qprobe` included but hard-gated**.
- Zero runtime dependencies; no modification of existing packages.
- CLI named `qinfra`; the networked plane isolated as `qprobe`.
