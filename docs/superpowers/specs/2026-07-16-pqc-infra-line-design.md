# Design — infrastructure PQC readiness (in-core detectors + `qprobe`)

**Date:** 2026-07-16 (revised 2026-07-17 after reconciling with `main`)
**Status:** Approved — in-repo, reuse `@quantakrypto/core`, **detectors inside `core`** (the
established pattern: `detectors/terraform.ts`, `detectors/jwk.ts`) + one new gated
package `qprobe` for active probing.
**Branch:** `pqc-infra-line` (worktree)

## 1. Goal

`@quantakrypto/qscan` answers *"is my **code** quantum-safe?"* This work extends it
to *"is my **infrastructure** quantum-safe?"* — the classical crypto that lives in
infrastructure-as-code, CI/CD signing, secrets stores, data-at-rest / messaging
config, and on the wire between running systems.

Narrative anchor: **Harvest Now, Decrypt Later (HNDL)** — ciphertext and long-lived
keys captured today are decryptable once a CRQC exists; for infrastructure that
risk has *already begun* for anything persisted ("your 2019 backups are the breach
of 2033"). `core`'s `Finding.hndl` boolean already models this.

## 2. Architecture decision (revised)

The initial spec proposed a separate `qinfra` package line. On rebasing against
`main`, the second agent had already landed infra detection **as `core` detectors**
(`detectors/terraform.ts`, `detectors/jwk.ts`, each a `scope: "config"` `Detector`
registered in `builtinDetectors`, surfaced automatically by `qscan`, the Action and
MCP). We adopt that pattern — it is simpler, conflict-light (one new file per
surface), and lights up every existing product shell for free.

**So:**
- **File-based infra surfaces → new `packages/core/src/detectors/*.ts`**, matching
  `terraform.ts` exactly (precompiled regexes, `RuleMeta` consts, `eachMatch` +
  `findingFromRule`, gated by `appliesTo`). Each gets `packages/core/test/*.test.ts`.
  Registered by appending to `builtinDetectors` in `registry.ts` (the one shared
  edit; trivially mergeable).
- **Active network probing → one new package `@quantakrypto/qprobe`** — the only
  networked package, isolated exactly like `@quantakrypto/agent`, hard-gated.

**No modification of existing detectors or other packages.** New detector files +
append-only `registry.ts` edits + new tests only.

### 2.1 What comes from `core`, unchanged

Contract (`Detector`/`RuleMeta`/`Finding`, `FindingCategory` union
`kem|key-exchange|signature|tls|certificate|hash|rng`, `AlgorithmFamily`), helpers
(`eachMatch`, `findingFromRule`, `hasExtension`, `makeFinding`), CWE constants,
reporters (`toSarif`/`toJson`/`toCbom`), score (`buildInventory`), severity utils,
baseline, redactor — all already exported from `packages/core/src/index.ts`.

## 3. New detectors (this build)

Already on `main`: `terraform` (IaC keys/KMS), `jwk` (JSON Web Keys). New:

| Detector file | Surface | Representative rules (HNDL) |
|---|---|---|
| `cicd.ts` | CI/CD artifact & code signing | cosign key/keyless (ECDSA), GPG `--detach-sign` (RSA), `jarsigner`, `codesign`, minisign — long-lived signatures forgeable at CRQC (signature-side, `hndl:false`) |
| `secrets.ts` | Secrets at rest | SOPS `age1…` recipients (X25519 KEM, `hndl:true`), SOPS `pgp:` (RSA), `$ANSIBLE_VAULT`, sealed-secrets RSA, Vault `transit`/`pki` key specs |
| `k8s.ts` | Kubernetes / cert-manager / mesh | cert-manager `privateKey.algorithm` RSA/ECDSA, `keyAlgorithm`, apiserver legacy `--tls-cipher-suites` / `--tls-min-version`, Istio `minProtocolVersion: TLSV1_0/1`, `PeerAuthentication` |
| `messaging.ts` | Kafka / RabbitMQ / MQTT / NATS | `ssl.protocol=TLSv1/1.1`, weak `ssl.cipher.suites`, MQTT `tls_version`; TLS-PSK surfaced as a *positive* signal |
| `database.ts` | DB transport & at-rest | `sslmode` < `verify-full`, legacy `ssl_ciphers`, `pgp_pub_encrypt` (pgcrypto RSA/ElGamal), TDE KEK algorithm |
| `jose.ts` | JWT / JWE token crypto | JWE `alg` `RSA-OAEP`/`ECDH-ES` = confidentiality (`hndl:true`, HNDL-critical); JWS `RS256`/`ES256` = signature (`hndl:false`). Complements `jwk.ts` |

Precision discipline (the repo's `= 1.000` bar): gate by extension/path, prefer
distinctive tokens, and every test file includes **clean-negative** cases (the same
token in an out-of-scope file must not fire) mirroring `terraform.test.ts`.

Parsing stays regex-over-content like every existing detector (no YAML/HCL parser
dependency — zero-dep vow intact). `appliesTo` uses `hasExtension` or a small path
predicate (e.g. `.github/workflows/`, basename `Jenkinsfile`, `.sops.yaml`).

## 4. `@quantakrypto/qprobe` — the gated networked plane

The only package that opens sockets; isolated like `@quantakrypto/agent`.

- **TLS probe:** `node:tls` for the negotiated suite + full DER cert chain
  (`node:crypto` `X509Certificate`), **plus** a hand-rolled raw ClientHello over
  `node:net` advertising `X25519MLKEM768` (codepoint `0x11EC`) and parsing the
  ServerHello `key_share` to detect PQC-hybrid support (Node's bundled OpenSSL
  can't negotiate it). Byte-level parser, fuzzed like `core`'s parsers.
- **SSH probe:** read the cleartext banner + `KEXINIT` name-lists over `node:net`
  (`sntrup761x25519`, `mlkem768x25519` = positive; classical = flagged). No auth.
- **Findings reuse `core`:** emits `Finding[]` (category `tls`/`certificate`,
  `hndl` set), scored + reported by the same `buildInventory`/`toSarif`/`toCbom`.
- **`engine disposes`:** reports negotiated reality; never mutates an endpoint.
- **Hard gate (first-class):** mandatory `--i-own-this` attestation (or ownership
  manifest); **refuses CIDR/range sweeps**; per-host rate limit; a dedicated
  `THREAT-MODEL.md` covering authorization scope, CFAA-style concerns, redaction,
  and a default mode that consumes externally-captured input for endpoints you
  don't own. Negative tests prove it refuses to connect without attestation.
- **Zero-dep:** `node:net`/`node:tls`/`node:crypto` only.

## 5. Reporting, MCP, Action — free

Because the new detectors register in `builtinDetectors`, `qscan` (human/JSON/SARIF/
CBOM/score/baseline), the GitHub Action, and the MCP server surface them with **no
new code**. `qprobe` findings flow through the same reporters. A combined code+infra
CBOM `bom-link` report is a later reporting nicety, not part of this build.

## 6. Testing

`node:test` via `tsx`, per the repo. Each detector: positive classification tests +
gating test + clean-negative test (matching `terraform.test.ts`). `qprobe`:
byte-parser fuzz tests + attestation-refusal tests. Target keeps the precision bar.

## 7. Deliverables

- New detectors + `qprobe`, built + tested green, committed on `pqc-infra-line`,
  merged into `qproof-tools` `main` at the end (conflicts resolved then).
  **No push/publish without explicit confirmation.**
- Docs: root README infra section, per-surface notes, `qprobe/THREAT-MODEL.md`,
  `CHANGELOG.md` entries, a `docs/` infra how-to + roadmap update.
- A new **`/tools`-style page on quantakrypto.com** (`~/development/qproof` Next.js
  app) presenting the infra line, matching the existing `tools` route + i18n.
- A **full audit of the new work** + a prioritised "where to grow next" roadmap.

## 8. Concurrency / conflict plan

All work in the `pqc-infra-line` worktree. New files + append-only `registry.ts` /
`CHANGELOG.md` / `README.md` edits. Rebased onto `main` before starting; final
sync-merge + conflict resolution before integrating. The website lives in a separate
repo (`qproof`) with no concurrent agent.

## 9. Locked decisions

- In-repo; reuse `core`; **detectors inside `core`** (not a separate package line).
- `qprobe` included, isolated, **hard-gated**.
- Zero runtime dependencies; no modification of existing detectors/packages.
- Regex-over-content parsing (no new parser deps); precision bar preserved via
  clean-negative tests.
