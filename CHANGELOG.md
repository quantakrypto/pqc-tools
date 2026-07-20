# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.

## [Unreleased]

### Added — CI enforcement of the offline/agent boundary (ADR-0005)

- New guard `scripts/check-offline-boundary.mjs` (wired into `ci.yml` and
  `supply-chain-audit.yml`) enforces the two-plane architecture that was
  previously convention-only: `core`/`mcp`/`sieve` stay strictly offline and
  key-free (no `@quantakrypto/agent` import, no outbound `fetch(`/WebSocket/XHR,
  no LLM API-key read), `qscan` reaches the agent **only** via a dynamic
  `import()`, and **no package or workflow auto-merges** (`gh pr merge` /
  `--admin`). Uses comment/string masking so a token that only appears inside a
  regex or comment (e.g. core's own redaction patterns) is not a false positive.
  Its reject logic is covered by known-bad fixtures in the guard-script tests.

### Changed — CBOM asset-type refinement

- The CycloneDX CBOM now classifies each finding into its proper `assetType`
  instead of labelling everything `algorithm`: X.509 findings become
  `certificate`, private/public key material becomes `related-crypto-material`
  (typed `private-key` / `public-key`), and TLS findings become `protocol`
  (`protocolProperties.type: "tls"`). Algorithm-usage components are unchanged.
  Every asset still carries `quantumVulnerable` / `harvestNowDecryptLater`.
  (Completes the "future refinement" noted in the CBOM audit.)

### Added — OpenVEX export (`--format vex`)

- `qscan --format vex` emits an **OpenVEX 0.2.0** document so the quantum-readiness
  posture flows into the same supply-chain pipeline that ingests CVE-based VEX.
  One statement per rule (a synthetic `QK-<ruleId>` vulnerability), every affected
  `file:line` product, `status: "affected"`, remediation as `action_statement`,
  and any `--triage` verdict in `status_notes`. Deterministic output. New
  `@quantakrypto/core` API: `toOpenVex`, `OpenVexDocument`, `OpenVexStatement`,
  `OpenVexOptions`; qScan re-exports `renderVex`.

### Added — evidence verification (`verifyReadinessReport`)

- New `@quantakrypto/core` API `verifyReadinessReport(report)` closes the
  build → sign → **verify** loop for the ISO A.8.24 evidence chain. It recomputes
  the deterministic content hash over the report's own body and returns
  `{ valid, computedHash, claimedHash, reason? }`, detecting tampering with any
  hashed field (findings, inventory, policy verdicts, subject/tool metadata) while
  ignoring the excluded scan time / CBOM envelope / attestation block. Integrity
  only — the detached signature/timestamp remain the external signer's to verify
  (ADR-0004).

### Changed — test hardening

- De-stubbed the qScan CLI and MCP tool tests that predated a real `core.scan`
  and tolerated every exit code / both if-else branches; they now assert
  deterministic outcomes against real fixtures.
- Added coverage for previously-untested failure paths: the sieve runner's
  timeout/crash/spawn-failure rejections, the stateful-HBS detector (its first
  unit test), the CI guard scripts' reject logic (via known-bad fixtures), and
  the agent BYOK adapters' timeout / network-error / key-only-in-header invariants.
- Fixed a latent bug surfaced by the guard tests: `scripts/validate-sarif.mjs` ran
  its CLI `main()` at import time (no `import.meta.url` guard), so importing it
  triggered a scan and `process.exit()`. CLI behaviour is unchanged.

### Added — detection coverage (SAML/XML-DSig, PKCS#11, TDE, CDK/Pulumi/GCP/Azure KMS)

Closes the real coverage gaps the pre-1.0 audit found:

- **XML-DSig / XML-Enc (SAML, WS-Security)** — a new detector flags classical XML
  signature algorithm URIs (`xmldsig-more#rsa-sha256`, `#dsa-sha1`, `#ecdsa-sha256`)
  and XML encryption key transport (`xmlenc#rsa-oaep`) — the algorithm layer under
  enterprise SSO, whose long-lived IdP signing keys are a prime forgery surface.
- **PKCS#11 / HSM** — a new detector flags classical keys behind a token: the OpenSC
  `pkcs11-tool --key-type rsa:2048 | EC:*` keygen and the PKCS#11 mechanism constants
  (`CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_ECDSA_*`, `CKM_DSA*`, `CKM_DH_PKCS_DERIVE`).
  HSMs hold an org's longest-lived roots — the keys a migration must find first.
- **SQL Server TDE** — the database detector now flags `CREATE ASYMMETRIC KEY … WITH
  ALGORITHM = RSA_*` (Transparent Data Encryption protecting the DEK with a classical
  RSA key — at-rest data is HNDL-exposed).
- **Cloud KMS breadth** — `cloud-kms` now covers the AWS **CDK enum form**
  (`kms.KeySpec.RSA_2048`, `acm.KeyAlgorithm.EC_prime256v1`) and Pulumi camelCase
  props (previously *zero* findings), plus **GCP** (`RSA_SIGN_*` / `EC_SIGN_*`) and
  **Azure Key Vault** (`createRsaKey`, `KeyType.Rsa`) runtime SDK forms.

All added with positive + negative + doc-suppression tests; benchmark unaffected.

### Added — selectable standards regimes (`--profile`)

- **`qscan --profile <id>`** tailors the migration guidance to a standards regime
  instead of a single hardcoded NIST/CNSA worldview: **nist** (default), **cnsa-2.0**,
  **bsi-tr-02102**, **anssi**, **uk-ncsc**. Each profile carries its parameter sets,
  deprecate/disallow deadlines, and — the key fix — a **hybrid stance**. The
  pre-profile code told everyone "hybrids optional" (CNSA's position), which is
  **wrong** for an ANSSI or BSI audience where hybridization is *required*; now the
  report says "hybrid required" for ANSSI/BSI and "hybrids optional" for CNSA 2.0,
  with the regime's own citation. `--tier category-5` is now an alias for
  `--profile cnsa-2.0`, and `--policy` still composes an org's exceptions on top.
  New `@quantakrypto/core` API: `StandardsProfile`, `STANDARDS_PROFILES`,
  `getStandardsProfile`, `standardsProfileIds`, `defaultStandardsProfile`,
  `remediationForProfile`, `formatProfileGuidance`. A drift test keeps the profile
  parameter sets aligned with `PQC_STANDARDS`.

### Added — evidence signing orchestration (A.8.24)

- **`qscan --format evidence --sign <cmd>` / `--timestamp <cmd>`** complete the
  A.8.24 evidence chain: the readiness report's deterministic `contentHash` is piped
  to an operator-provided external signer (openssl / cosign / an RFC-3161 TSA client)
  on **stdin**, and its **stdout** is recorded as the detached signature / timestamp
  token in `attestation.signature` / `attestation.timestamp`, alongside a
  non-sensitive `signedWith` / `timestampedWith` provenance label (the program name —
  never the argument list, so a key path can't leak). The payload is never
  interpolated into the command, and signing never changes `contentHash` (attestation
  is excluded from the hashed body). Per **ADR-0004** the tool implements no
  cryptography — it orchestrates the signer; per **ADR-0005** this is a `qscan` CLI
  feature only (the MCP server stays offline and key-free). New `@quantakrypto/core`
  API: `signReadinessReport`, `EvidenceSigner`, `SignEvidenceOptions`. Both flags
  require `--format evidence` (a loud error otherwise), and a non-zero signer exit
  aborts with a clear message.

### Added — frozen public API surface + generated reference (1.0 gate)

- **`docs/API.md`** (human reference) and **`docs/api-surface.json`** (the
  machine-readable contract) are generated from each package's public entry point by
  **`npm run api:docs`** (`scripts/gen-api-reference.mjs`, zero-dep). They enumerate
  every SemVer-covered symbol across `@quantakrypto/`core · qscan · mcp · sieve ·
  agent · qprobe (318 symbols today).
- **`npm run api:check`** — a new CI gate (in the lint job) that fails if a package's
  real exports drift from the frozen snapshot, so adding or removing a public symbol
  is a deliberate, reviewed change rather than an accident. Closes the
  [VERSIONING.md](docs/VERSIONING.md) "generated API reference + frozen surface" 1.0
  requirement.

## [0.5.0] — 2026-07-20

### Fixed — detector precision (cross-detector double-counts)

Several config detectors emitted a second finding for a line another detector
already owned, inflating counts and depressing the readiness score. Ownership is
now single-source:

- **`source.ts` owns transport tokens.** Removed the redundant `vpn`
  `net-sshd-classical-kex` (sshd KexAlgorithms) and `mesh`
  `mesh-istio-classical-cipher` (ECDHE-RSA suites) rules — `source.ts`'s
  `ssh-kex-classical` / `tls-classical-kex` token detectors already cover them.
- **`cloudformation.ts` owns crypto inside templates.** `jwk` and `cloud-kms` now
  defer inside a CloudFormation/ARM template (new `isCloudTemplate` gate), and the
  CFN KMS rule matches all three spec-key spellings (`KeySpec` / `KeyPairSpec` /
  `CustomerMasterKeySpec`) so nothing is missed.
- **`jwk` skips docs** (README examples) and is now **usage-aware**: an RSA/EC
  *signing* JWK (`use:"sig"`, or `RS`/`PS`/`ES` alg) is classified as a `signature`
  (`hndl:false`) instead of an HNDL-exposed key; encryption keys stay `hndl:true`.
- **`jose` defers to `jwk`** when the `alg` belongs to a JWK object (a `kty` is in
  the same object), so a JWK's declared alg is not counted twice.

### Added — A.8.24 evidence policy mapping (roadmap 🟡)

- **`qscan --format evidence --policy <file>`** completes §4 of the ISO/IEC 27001
  A.8.24 evidence report: an org supplies a machine-readable cryptography policy (a
  permit-list of algorithm families — `prohibited` / `inTransition` / `permitted`,
  plus a `transitionDeadline` and `defaultVerdict`), and every finding is flagged
  **conformant / violation / transition-pending** against it, with a per-verdict
  summary. The verdicts are folded into the attested (hashed) body, so *this policy
  judgment over this scan* is reproducible and tamper-evident. A malformed policy
  fails loudly (`parseCryptoPolicy` throws on an unknown family) rather than
  silently dropping the verdicts. New `@quantakrypto/core` API: `buildPolicyMapping`,
  `parseCryptoPolicy`, `verdictForAlgorithm`, `CryptoPolicy`. See
  [`docs/compliance/example-crypto-policy.json`](docs/compliance/example-crypto-policy.json).

### Added — standards-currency cadence (roadmap 🟠)

- **A single, dated, cited source of truth for the PQC standards the tool tracks**
  (`@quantakrypto/core` `PQC_STANDARDS`): FIPS 203/204/205, the CNSA 2.0 tiers,
  SP 800-208, the NIST IR 8547 2030/2035 timeline, and the emerging (HQC, FN-DSA,
  X-Wing) / hybrid (X25519MLKEM768, SecP384r1MLKEM1024) targets — each with a
  `source` and an `asOf` date, plus `lastReviewed` / `nextReview` (quarterly).
- **A drift test** (`test/standards.test.ts`) that fails the build if the runtime
  remediation constants (`TIER_PARAMS`, `PQC_TRANSITION_NOTE`, `STATEFUL_HBS_NOTE`)
  fall out of sync with the manifest — code and the documented standards can no
  longer silently diverge.
- **An advisory cadence check** — `npm run standards:check`
  (`scripts/standards-check.mjs`, wired into CI) prints the sources to re-verify
  and warns (never fails) when the quarterly review is due; `standardsReviewStatus(now)`
  is the pure predicate behind it. Runbook: `docs/standards/pqc-standards.md`.

### Fixed (from a real-repo precision audit)

- **`ssh-public-key` false positives on i18n / label strings.** The rule matched
  the bare key-type token (`ssh-rsa`, `ssh-ed25519`, …), so it fired on UI labels
  and translation values like `"ssh-rsa": "ssh-rsa"` — **124 false positives** on a
  single real repo (activepieces, 22.8k files). A bare token now counts only when
  it is either followed by base64 key material (a real `authorized_keys` /
  `known_hosts` entry) or is one of ≥2 distinct ssh key/host-key algorithm tokens
  on the line (a `HostKeyAlgorithms …` preference list) — the two genuine SSH
  surfaces. The line window is bounded so detection stays linear-time. Both
  benchmarks unchanged (tuned P/R/F1 **1.000**, recall **0.847**); the real repo
  drops from 161 → 37 findings with the SSH FPs gone.

### Added — new detector surfaces (Bicep, Swift, Pulumi)

- **Azure Bicep** (`.bicep`) — the native Azure IaC DSL, distinct from the ARM/
  CloudFormation JSON already covered (Bicep is the source, ARM JSON its compiled
  output). Flags `Microsoft.KeyVault` `kty: 'RSA'/'EC'` keys (gated to the Key Vault
  marker) and legacy `minimumTlsVersion: 'TLS1_0'/'TLS1_1'`.
- **Swift / CryptoKit + Security framework** — P256/384/521 `Signing` vs
  `KeyAgreement` (ECDSA / ECDH), `Curve25519` `Signing`/`KeyAgreement`
  (Ed25519 / X25519), and `SecKeyCreateRandomKey` `kSecAttrKeyTypeRSA`/`EC`.
  `.swift` added to the C-style comment table and to `DetectorLanguage`.
- **Pulumi** — the `pulumi-tls` provider's `tls.PrivateKey` across TS/JS/Python/Go,
  gated to a pulumi-tls marker, classifying the `algorithm` value (RSA/ECDSA/ED25519).
- All three validated against real OSS repos with **zero false positives**, and
  pinned by new labeled benchmark corpus cases.

### Fixed — false-positive classes (comment/prose masking)

- **Commented-out code fired detectors.** PHP (`.php`/`.php3-5`/`.phtml`), Scala
  (`.scala`/`.sc`), Ruby/Elixir (`.rb`/`.ex`/`.exs`) and Swift were absent from the
  comment tables, so a commented `// openssl_pkey_new(...)` scanned as live code.
- **Config-format comments** now masked per detector: SQL `--`/`/* */`, ini `;`,
  zone-file `;`, `named.conf` `//`, YAML/HCL `#`/`//`, and Jenkinsfile `//` — the
  central stripper covers no config extension, so mesh, dnssec, cloudformation,
  database, supply-chain, terraform, ansible, vault now mask their own comment lines.
- **Bare PEM header string literals** (`PEM_HEADER = "-----BEGIN RSA PRIVATE
  KEY-----"`) and a parser's paired header/footer constants no longer report as
  embedded keys — a real block now needs a base64 body, an escaped-newline body
  (GCP-style single-line `"…\n…"` keys), or a matching `-----END-----` with no quote
  between the markers.
- **Transport-KEX names in a doc string.** From a real-repo sweep
  (terraform-aws-eks): `ssh-kex-classical`/`tls-classical-kex` fired on algorithm
  names listed inside a Terraform/Packer `description = "…"` (6 hits on one line).
  A `description`/`help`/`doc`/`comment` field value is now treated as prose.
- **String-aware object scoping.** `enclosingObject` (used by the JWK/JOSE per-key
  analysis) now honours JSON string values, so a brace inside a string can't
  mis-scope a key; its brace-less fallback is a bounded ±window so a distant `"kty"`
  can't over-suppress a standalone JWT/JOSE finding.

### Fixed — cross-detector double-counts & language precision

- **webcrypto × jose / jwk × jwt.** A quoted `RSA-OAEP`/`ECDH-ES` next to a
  `subtle.*(` call is owned by the WebCrypto detector; an `alg` inside a JWK object
  (a `"kty"` in scope) is owned by the JWK detector — the `jwt-jose` detector defers
  in both cases (mirroring the existing `jose`→`jwk` guard). `RSA1_5` is still
  reported (WebCrypto doesn't match it).
- **Java**: ECIES (EC encryption, HNDL); `SSLContext.getInstance("TLSv1.1"/"SSLv2")`;
  the `new X448KeyPairGenerator()`/`Ed448KeyPairGenerator`/`X448PrivateKeyParameters`
  forms. **C#**: `SecurityAlgorithms.*Sha256Signature` constants; certificate
  *pinning* no longer flagged as a disabled validator, while `=> true`,
  `=> { return true; }`, and `delegate { return true; }` still are. **Rust**:
  qualified `x448::Secret`. **Elixir**: `:crypto.compute_key` (the (EC)DH agreement
  op) and JOSE OKP X25519/X448 as key agreement (not an EdDSA signature).
- **C**: `EVP_PKEY_derive` on an HKDF/scrypt/TLS1-PRF context and `EVP_DigestSign*`
  keyed by HMAC/CMAC are no longer flagged as asymmetric crypto (per-match, so a real
  RSA/ECDSA operation in the same file still fires). Widened the legacy-TLS method
  forms (`TLSv1_1_method`, `_client`/`_server`, `SSLv2_method`).
- **`tls-weak-cipher`** now catches a weak cipher inside a hyphenated suite name
  (`ECDHE-RSA-RC4-SHA`) without flagging a hardened full-suite exclusion
  (`HIGH:!ECDHE-RSA-RC4-SHA`). Identifier-form JWT alg constants (Java/C#/Rust) are
  string-literal-suppressed like the Go rule.
- **False negatives closed**: DNSSEC lowercase mnemonics (BIND `dnssec-policy`);
  terraform `tls_private_key` ED25519 and the modern `aws_kms_key key_spec` alias;
  database `PGSSLMODE`/MySQL `ssl-mode`/YAML `sslmode:` forms; ansible
  X25519/X448/Ed25519/DSA; CloudFront `SSLv3`; Consul agent config in `.json`;
  RFC 9580 (v6) OpenPGP algorithm ids 25–28 (X25519/X448/Ed25519/Ed448); PKCS#12
  BER indefinite-length (`0x80`, NSS/Firefox `.p12` exports).

### Fixed — engine correctness

- **Triage cap** now selects the top findings by **severity**, not file-path order —
  a critical in a late-sorting file is no longer dropped from triage and sunk to the
  bottom of the report.
- **CBOM merge** no longer crashes on a legal CBOM with no `components`, nor on a
  duplicate `bom-ref` whose copy lacks `cryptoProperties`. CBOM `serialNumber` is now
  content-addressed over the finding set / occurrence evidence (was derived from the
  finding *count*, so distinct scans could collide).
- **Readiness score** is independent of file order and real/test interleaving — the
  diminishing-returns counter is bucketed per (severity × test-path), so a directory
  rename can no longer move the score.
- **CLI**: an `ENOENT` reports the actual missing path (a `--policy` /
  `--write-baseline` failure is no longer blamed on the scan path); `--merge` without
  `--format cbom` is now a loud error instead of silently dropping the merge files.
- **sieve KAT**: an unverifiable vector (no seed/coins) is a *skip*, not a match — it
  no longer inflates the "N/N matched" count into a false conformance pass.

### Changed — dead-code removal & API surface

- Removed three unused exported symbols (`ToolInputSchema`, `SuccessResponse`,
  `writeLine`) and the dead `JsonValue` type; fixed two unreachable/redundant
  branches (cosign `sign-blob` alternation, a redundant `CustomerMasterKeySpec`
  fast-reject conjunct). Narrowed the visibility of **71** internal-only symbols
  (used within a single file, not part of any package's public API). No behavior
  change; the build's `declaration` emit + `noUnusedLocals` verify nothing external
  depended on them.

### Testing

- Real-repo validation sweep (gin, gorilla/mux, flask, terraform-aws-eks, express,
  helm/charts): the only false-positive class found (transport-KEX in a doc string)
  is fixed above; everything else was legitimate. Benchmark corpus expanded with 11
  labeled cases (positives + negative baits) for the new surfaces; suite at **916**
  passing, precision/recall gates and the zero-FP negative set held throughout.

## [0.4.4] — 2026-07-19

### Added — infrastructure post-quantum readiness

- **Committed-keystore detection (`keystore`)** — JKS/JCEKS (magic `0xFEEDFEED` /
  `0xCECECECE`), PKCS#12 (`.p12`/`.pfx`, DER SEQUENCE), and BouncyCastle (`.bks`).
  Keystores are binary, so the scan pipeline now reads keystore extensions
  byte-preserving (latin1) and exempts them from the minified skip (`walk.ts`
  `isKeystorePath`, serial + parallel read paths); the match is sensitive key
  material so the snippet is dropped. Other binaries stay skipped.
- **Binary OpenPGP detection (`openpgp`)** — building on the byte-preserving read,
  a new detector identifies binary `.gpg`/`.pgp` OpenPGP packets by tag: committed
  SECRET keys (sensitive, RSA/DSA/ElGamal/EC — the sharp finding), public keys,
  binary PGP-encrypted messages (PKESK → HNDL), and GnuPG keyboxes (`.kbx`). The
  public-key algorithm is read from the packet; the parser is bounds-checked and
  fuzzed. Armored (`-----BEGIN PGP …-----`) blocks remain handled by PEM/secrets.
- **`qscan --cbom --merge <cbom.json>`** — wires core's `mergeCboms` so a scan CBOM
  and an external CBOM (e.g. a qProbe endpoint CBOM) fuse into one combined
  code + infrastructure CycloneDX bill of materials.
- **qProbe definitive hybrid negotiation** — the TLS probe now sends a WELL-FORMED
  X25519MLKEM768 key_share (a real X25519 public from `node:crypto` + a valid-range
  ML-KEM-768 encapsulation key, `ML-KEM-768.ek || X25519.pk` per
  draft-ietf-tls-ecdhe-mlkem), so a supporting server selects the hybrid group
  DIRECTLY in its ServerHello — catching servers that support-but-don't-*prefer* it,
  which the old HelloRetryRequest-only inference missed. No full ML-KEM keygen is
  needed (qProbe never completes the handshake): a `ByteEncode₁₂` of in-range
  coefficients passes the server's encaps modulus check; the throwaway secret is
  never computed. New `mlkem768.ts` (pure, unit-tested encode/decode).
- **qProbe protocol coverage** — added `--imap` (STARTTLS `:143`), `--pop3` (STLS
  `:110`), and `--postgres` (SSLRequest `:5432`) probes, auto-selected by
  well-known port. IMAP/POP3 reuse the line-based STARTTLS upgrade; PostgreSQL
  sends the 8-byte libpq SSLRequest and upgrades on `S`. DNS-over-TLS (`:853`) and
  IMAPS (`:993`) already work as direct-TLS probes. All reuse the same negotiated-
  parameter + certificate inspection and the clean-close hang guard.
- **MCP `probe_endpoint` tool** — exposes qProbe to AI agents; the qprobe plane is
  dynamically imported so the server stays offline until invoked, the ownership
  attestation is enforced (refuses unless `i_own_this=true`, refuses CIDR/ranges),
  errored endpoints can't read as a false clean score, and the tool is disabled by
  default on the HTTP transport (opt-in via `QUANTAKRYPTO_MCP_ALLOW_NETWORK=1`).
- **Infrastructure GitHub Action recipe** — IaC scan + weekly scheduled qProbe of
  owned endpoints + a merged code+infra CBOM artifact.
- **Detector-audit fixes** — bounded the messaging/cicd ReDoS regexes (+ config
  inputs in `redos.test.ts`), added `#`/`--` comment-masking to k8s/secrets/database,
  and corrected `mq-classical-cipher` algorithm labelling / legacy-TLS `hndl` messages.
- **Six new config-scope detectors** in `@quantakrypto/core`, surfaced
  automatically by qScan, the Action and MCP (no new install) — each gated and
  tested with clean-negative cases to hold the precision bar:
  - **`cicd`** — classical artifact/code signing in CI/CD pipelines (cosign/ECDSA,
    GPG/RSA, `jarsigner`, `codesign`, minisign/Ed25519). Signature-side exposure
    (`hndl:false`): forgeable once a CRQC exists.
  - **`secrets`** — secrets wrapped at rest with classical asymmetric crypto:
    SOPS/age recipients (X25519), PGP MESSAGE blocks (RSA/ElGamal), Bitnami
    Sealed Secrets (RSA-OAEP). The sharpest harvest-now-decrypt-later story
    (ciphertext committed to git is retroactively un-fixable). Symmetric
    ansible-vault is intentionally out of scope.
  - **`jose`** — JWE key-management algorithms (`RSA-OAEP`, `ECDH-ES`) —
    confidentiality, HNDL-exposed; complements the JWK detector.
  - **`k8s`** — cert-manager `privateKey.algorithm` (RSA/ECDSA/Ed25519) and Istio
    legacy TLS floors, gated by a cert-manager / Istio marker.
  - **`messaging`** — Kafka/MQTT legacy TLS protocols and classical (EC)DHE cipher
    suites in broker config.
  - **`database`** — pgcrypto public-key encryption (`pgp_pub_encrypt`) and libpq
    `sslmode` without certificate verification.
- **`@quantakrypto/qprobe`** — a new package for **active** post-quantum readiness
  probing of live TLS/SSH endpoints you own. The only package that opens sockets,
  isolated like `@quantakrypto/agent` and **hard-gated** behind an ownership
  attestation (`--i-own-this` / `--owned-hosts`) enforced in code before any
  network I/O; refuses CIDR/ranges/wildcards/lists. Detects PQC-hybrid TLS support
  (X25519MLKEM768) via a hand-rolled raw ClientHello, reads SSH `KEXINIT`
  algorithms, and reports the negotiated reality without ever modifying an endpoint
  ("engine disposes"). Ships a `THREAT-MODEL.md`. Zero runtime dependencies.
- **qProbe SARIF + CBOM output** (`--sarif` / `--cbom` / `--format`). Live-endpoint
  findings now emit the same SARIF 2.1.0 and CycloneDX 1.6 CBOM as qScan (the core
  reporters are findings-based, so no registry entry is needed for the `qprobe-*`
  rules). This unifies the three planes — code, infrastructure-as-code/config, and
  live endpoints — into one post-quantum posture: the CBOMs are all CycloneDX 1.6
  `cryptographic-asset` documents that merge via `bom-link`, and every readiness
  score comes from the same `buildInventory` math.
- **`mergeCboms(boms)` in `@quantakrypto/core`** — merges multiple CycloneDX 1.6
  CBOMs into one combined bill of materials, unioning components by their
  deterministic `bom-ref` (same algorithm+primitive collapses to one asset whose
  occurrence evidence spans every plane) and OR-ing the harvest-now-decrypt-later
  flag. Turns the "code + infra + live-endpoint" story into a single artifact:
  `qscan . --cbom` and `qprobe … --cbom`, then `mergeCboms([code, endpoints])`.
- **Three more infra detectors** in `@quantakrypto/core` (surfaced automatically by
  qScan / Action / MCP): **`cloudformation`** (AWS CloudFormation / Azure ARM /
  Bicep-JSON: `AWS::KMS::Key` KeySpec RSA/ECC, ACM `KeyAlgorithm`, CloudFront/ELB
  legacy TLS policies, ARM Key Vault key type), **`mesh`** (Linkerd ECDSA identity
  issuer, Consul Connect CA key type, Istio classical `cipherSuites`), and
  **`dnssec`** (classical DNSSEC signing algorithms — RSASHA*, ECDSAP*, ED25519/448,
  DSA — in zone files and signer config). Each gated + clean-negative-tested.
- **qProbe protocol depth**: **X.509 signature-algorithm extraction** (a hand-rolled
  DER parse reads how the leaf certificate is *signed* — the CA's algorithm, the
  forgeable-at-Q-day part — which `node:tls` does not expose), and an **SMTP
  STARTTLS** probe mode (`--smtp`, auto on :25/:587) that upgrades the mail session
  to TLS and inspects the negotiated posture. (Real ML-KEM keygen for definitive
  hybrid negotiation is intentionally NOT implemented — it would violate the repo's
  "implements no crypto itself" principle, and the HelloRetryRequest-based detection
  already works without it.)
- **Network transport / VPN detector (`vpn`)** in `@quantakrypto/core` — classical
  key exchange in the tunnels carrying communication between things: **WireGuard**
  (`[Interface]`/`[Peer]` Curve25519 keys — a sharp finding, since WireGuard has no
  standard PQC KEM; the private key is treated as sensitive material), **IPsec /
  strongSwan** IKE/ESP proposals naming classical DH groups (`modp*` = finite-field
  DH, `ecp*` = ECDH), and **sshd_config / ssh_config** `KexAlgorithms` lines that
  offer no PQC hybrid KEX — a server that already lists `sntrup761x25519` /
  `mlkem768x25519` stays silent. Each rule is gated to its own config shape.
- **Four more infra detectors** in `@quantakrypto/core`, closing audited gaps
  (each comment-masked and gated; clean-negative tested):
  - **`ansible`** — Ansible `community.crypto` `openssl_privatekey`/`csr` `type:
    RSA/ECC`.
  - **`age`** — a committed `AGE-SECRET-KEY-1…` identity (X25519 private key,
    marked sensitive) — worse than a recipient; closes the secrets-detector gap.
  - **`supply-chain`** — classical container/artifact signing beyond cosign/GPG:
    Docker Content Trust (Notary v1), CNCF Notation, in-toto.
  - **`vault`** — native HashiCorp Vault HCL: `transit` key types (`rsa-*`,
    `ecdsa-p*`, `ed25519`) and `pki` role `key_type` (Terraform-provisioned Vault
    stays with the terraform detector; this covers Vault's own `.hcl`).
- **qprobe: fixed a probe hang on clean connection close** — the raw `net` probes
  (SSH, TLS-hybrid, SMTP) added no `close`/`end` handler, so a peer that accepted
  then cleanly closed before a complete response left the run wedged (the socket
  timeout does not fire post-close). Each now resolves on close. Also synced
  `version.ts` so JSON/SARIF/CBOM report the correct tool version.

### Added / Changed (standards currency + guidance wiring)

- **Elixir language pack** — a 10th source language (the BEAM / Phoenix
  ecosystem). Detects Erlang `:crypto.generate_key` (`:rsa` / `:dh` / `:ecdh`,
  with the curve atom disambiguating X25519/X448 from a NIST-curve ECDH) and
  `:crypto.sign`/`:crypto.verify` (`:rsa` / `:ecdsa` / `:eddsa`), the `X509` hex
  package (`X509.PrivateKey.new_rsa` / `new_ec`), and erlang-jose
  (`JOSE.JWK.generate_key({:rsa|:ec|:okp, …})`). Symmetric/MAC `:crypto` calls and
  non-asymmetric type atoms (e.g. `:srp`) stay silent; precision/recall hold at
  1.000/0.847.
- **Scala coverage on the JVM pack.** Scala (`.scala`) and Scala scripts (`.sc`)
  compile against the same JCA (`KeyPairGenerator` / `Signature` / `KeyAgreement`)
  and BouncyCastle APIs the Java/Kotlin rules already match, so the JVM detector now
  reads them too — a major JVM language covered with no new rules. Added to the
  analyzable-language set (label now reads "Java/Kotlin/Scala").
- **PHP language pack** — a 9th source language (one of the most-deployed
  backends, previously uncovered). Detects `ext/openssl` (`openssl_pkey_new`
  classified by its `OPENSSL_KEYTYPE_*`, defaulting to RSA; `openssl_public_encrypt`
  / `_private_decrypt`; `openssl_sign` / `_verify`), phpseclib3
  `RSA`/`EC`/`DSA`/`DH` `::createKey`, and libsodium `sodium_crypto_box`/`kx`
  (X25519) + `sodium_crypto_sign` (Ed25519). The key-type window is bounded to the
  current statement so one `openssl_pkey_new` can't inherit the next call's key
  type; symmetric AEAD stays silent. Adds PHP to the analyzable-language set;
  precision/recall hold at 1.000/0.847.
- **Import-alias resolution (JS/TS + Python + Rust).** Detectors now follow
  renamed imports so an aliased call still detects, precision-safe (the alias is
  only ever bound to a known crypto symbol, and the alias regexes run on the
  original text so locations stay exact):
  - **JS/TS** — `import { generateKeyPairSync as gk } from 'node:crypto'` and the
    CommonJS `const { createECDH: mk } = require(...)` destructure-rename, for the
    keygen / ECDH / DH constructors.
  - **Python** — module aliases (`from ...asymmetric import rsa as _rsa`,
    comma-separated specifiers, and PyCryptodome `import ...RSA as _R`), resolving
    `_rsa.generate_private_key(` / `_ec.ECDSA(` / `_ec.ECDH(` / `_R.generate(`.
  - **Rust** — braced/renamed `use x25519_dalek::{EphemeralSecret as
    MontgomerySecret}` (and `x448` / `ed25519_dalek`), resolving the aliased type's
    construction call. Also adds the **`x448`** crate to the catalog.

  Together these lift recall's `aliased` bucket 0.32 → 0.47 and overall recall
  0.824 → **0.847**, with precision held at 1.000.
- **Cloud KMS SDK detection (AWS KMS)** — a config-scope detector for classical
  keys minted at *runtime* via the AWS KMS SDK (the app-code counterpart to the
  Terraform IaC detector): `CreateKey` / `GenerateDataKeyPair` with a
  `KeySpec` / `KeyPairSpec` / legacy `CustomerMasterKeySpec` of `RSA_*` or `ECC_*`.
  One lexical rule catches every SDK language (JS/TS, Python/boto3, Java, Go, CLI,
  JSON) and both the `key: val` and quoted-JSON `"key": val` forms; the case-
  sensitive PascalCase field name means it never double-counts with Terraform's
  snake_case `customer_master_key_spec`. Symmetric (`SYMMETRIC_DEFAULT`) keys stay
  silent.
- **Terraform / OpenTofu (IaC) detection** — a new config-scope detector for the
  classical keys and CMKs that infrastructure code provisions (never visible to
  the language packs): hashicorp/tls `tls_private_key` (`algorithm = "RSA"/"ECDSA"`),
  AWS KMS `customer_master_key_spec` (`RSA_*` / `ECC_*`), Google Cloud KMS
  `RSA_SIGN_*` / `EC_SIGN_*` algorithm strings, and Azure Key Vault `key_type`
  (`RSA`/`EC`, incl. `-HSM`). Matches both HCL and `.tf.json` syntax; gated to
  `.tf` / `.tf.json` so it never fires on arbitrary files.
- **JSON Web Key (JWK / JWKS) detection** — a new config-scope detector finds
  classical key material in JSON (`.json` / `.jwks`, OIDC discovery docs, config):
  `"kty":"RSA"` → RSA; `"crv":"P-256/384/521/secp256k1"` → EC (ECDSA+ECDH);
  `"crv":"Ed25519/Ed448"` → EdDSA; `"crv":"X25519/X448"` → key agreement. Keys EC/OKP
  off `crv` so a single key is counted once; symmetric `oct` keys and ordinary JSON
  don't fire. A real key-material surface the source packs and the PEM detector both
  missed; precision/recall stay **1.000** on the tuned corpus.
- **SARIF results now carry `partialFingerprints`** (`quantakrypto/v1` = the same
  line-insensitive sha256 the baseline uses). GitHub code scanning keys alert
  identity and dedup off this, so a finding survives line shifts and reformatting
  instead of re-alerting as "new" every time code moves above it.
- **Partial-coverage honesty caveat on the readiness score.** When the analyzable
  subset is only a small slice (<25%) of the files scanned, the human report now
  notes that the score covers only that slice — a high score on a mostly-unsupported
  tree no longer reads as a clean bill of health. (Complements the existing
  zero-analyzable guard.)
- **Worked liboqs / OQS composition example** (`examples/liboqs-migration/`) +
  a README section. Makes the intended positioning concrete — quantakrypto is
  the scanner / CI gate / conformance harness *around* a real PQC library, not a
  replacement for one — with a full scan → migrate (hybrid X25519MLKEM768 via
  liboqs) → verify (sieve conformance) → gate walkthrough. Directly answers the
  "no full PQC library — use alongside liboqs" framing from external reviews.
- **Embedded C crypto coverage (Mbed TLS + wolfSSL/wolfCrypt).** The C/C++
  detector previously covered only OpenSSL and libsodium; it now also detects the
  two dominant *embedded* libraries — `mbedtls_rsa_gen_key` / `mbedtls_ecp_gen_key`
  / `mbedtls_ecdsa_*` / `mbedtls_ecdh_*` / `mbedtls_dhm_*`, and `wc_MakeRsaKey` /
  `wc_ecc_*` / `wc_DhAgree` / `wc_curve25519_*` / `wc_ed25519_*` — with the same
  HNDL classification as the OpenSSL rules. Directly closes the "embedded / IoT /
  firmware" scanning-depth gap; distinctive `mbedtls_*` / `wc_*` prefixes keep
  false positives near zero (precision/recall stay **1.000** on the tuned corpus).
- **GitHub Action now writes a job summary (`$GITHUB_STEP_SUMMARY`)** on every
  run — the readiness score and the findings table (or the migration plan in
  `comment-plan` mode) render on the workflow run's summary page with no PR
  context and no token, so push builds and fork PRs surface results too. The PR
  comment path is unchanged. Best-effort: a summary-write failure never breaks
  the build.
- **`qscan` human report now carries a "Standards & timeline" footer** whenever
  findings exist: the NIST IR 8547 deprecation deadlines (classical public-key
  crypto deprecated after 2030, disallowed after 2035) plus the standards worth
  tracking (HQC, FN-DSA/Falcon, X-Wing). Signature findings additionally get the
  SP 800-208 stateful-HBS note. This wires up guidance that already lived in
  core (`PQC_TRANSITION_NOTE` / `STATEFUL_HBS_NOTE`) but was never surfaced.
- **Stateful-HBS detector broadened to the full SP 800-208 parameter space** —
  LMS/XMSS/XMSSMT rules now match the **SHAKE256** hash variants and the
  **192-bit** (M24/N24, `_192`) parameter sets, not just RFC 8554/8391's SHA-256
  sets.
- **Sharper remediation copy** — embedded EC private keys now point at
  ML-DSA (FIPS 204) for signatures *or* hybrid X25519MLKEM768 for key agreement;
  the CIRCL dependency note clarifies you migrate the classical *usage*, not the
  package (CIRCL itself already ships PQC).

### Testing

- **Remediation-correctness benchmark** — the counterpart to the detection
  benchmark: it measures whether the deterministic codemod layer *fixes* what
  qScan finds. For a labeled corpus it scores every produced patch on four
  properties — **applied**, **cleared** (re-scan confirms the classical crypto is
  gone, via the same `verifyFix` the pipeline uses), **no-regression**, and
  **idempotent** — and, on a second corpus, asserts the layer **declines**
  findings with no safe mechanical fix (RSA keygen, ECDH handshake) rather than
  emitting a wrong patch. Deterministic → gated at **1.000**. Documented in
  [`docs/validation/remediation-benchmark.md`](docs/validation/remediation-benchmark.md);
  it's the harness future codemods (and, report-only, LLM fixes) plug into.
- **Triage exit-code invariant is now regression-tested.** Added a `triageFn`
  test hook to `runQscan` so the `--triage` path runs offline, and a test that
  proves triage can re-rank/annotate a blocking finding but **never** drops it or
  changes the exit code (the exit code is computed from raw severities before
  triage runs — a prompt-injected "de-prioritize" verdict can't sneak a finding
  past CI).
- **MCP `FIX_EXAMPLES` meta-test.** Every canned before/after example the
  `get_fix_examples` tool serves is now asserted well-formed (non-empty, before ≠
  after) and required to name a post-quantum target — so no example can silently
  hand an agent classical crypto — with coverage pinned for every HNDL-critical
  and signature family.

### Fixed (security & correctness — from a post-release 5-lens audit)

- **Agent-line exfiltration-guard bypass** — the `qremediate` blast-radius guard
  (`NEW_SINK_RE`) matched only bare `require("http")` / dynamic `import("http")`,
  so a hostile or prompt-injected LLM patch adding `require("node:https")` or a
  **static** `import { request } from "node:net"` sink was accepted (verified
  end-to-end). It now matches the `node:` prefix, static-import forms, and
  `tls`/`http2`, and **rejects any sink on a newly-added line** (robust to
  sink-swaps), covered by a red-team fixture suite.
- **Comment/string lexer bugs (introduced in 0.4.3)** — the filter now handles
  **Go raw strings** (`` `C:\` `` no longer swallows the code after it, which had
  hidden a real finding) and **Rust lifetimes** (`'a` no longer starts an
  unterminated char-literal scan that silently disabled comment-based
  false-positive suppression for the rest of the file). Both verified and
  regression-tested.
- **`secp256k1` key agreement mis-classified** — `secp.getSharedSecret()` / `.ecdh()`
  were flagged as non-HNDL ECDSA signatures; they are now **ECDH key agreement
  (`hndl: true`)**, so a genuine harvest-now-decrypt-later surface is no longer
  deprioritized.
- **MCP `score_delta` NaN** — validates its `before`/`after` findings arrays
  (mirroring the triage/remediate tools) instead of emitting `NaN` readiness
  scores on malformed input.

## [0.4.3] — 2026-07-15

The **2026-07-15 5-lens audit** ([`docs/audits/2026-07-15-v0.4-review.md`](docs/audits/2026-07-15-v0.4-review.md))
and its remediation, plus the detection-depth work that followed — the
false-negative **recall benchmark** and the precision/recall fixes a **real-repo
validation** run surfaced. Build clean; tuned benchmark precision/recall **1.000**
throughout; still zero runtime dependencies.

### Detection depth + real-repo validation

- **Recall (false-negative depth) benchmark** — the last open item from the
  2026-07-15 audit backlog. A deliberately-hard, real-world crypto corpus across
  all eight languages (`packages/core/test/benchmark/recall/`, **85 files / 166
  occurrences**), labeled by what the crypto *truly is* — independent of, and
  written blind to, the detectors. `recall.test.ts` measures **detection recall**
  (family-level, greedy per file; `unknown`-classified findings count as
  detections) and prints the exact false-negative list. Baseline **0.645**;
  guarded by a floor (not gated at 1.000 like the tuned benchmark, since
  real-world recall < 1 is expected). The per-difficulty split — `canonical`
  0.81 vs `aliased` 0.32 / `adversarial` 0.37 — quantifies the lexical ceiling
  and names the closable gaps. See
  [`docs/validation/recall-benchmark.md`](docs/validation/recall-benchmark.md).
- **`tls-classical-kex` detector** (language-agnostic, config scope) — flags
  classical TLS key-exchange cipher suites (`ECDHE-RSA`/`ECDHE-ECDSA`/`DHE-RSA`,
  OpenSSL and IANA spellings) as harvest-now-decrypt-later exposure, the
  cross-language TLS gap the legacy-*version* rule missed. Closes the first
  cluster the recall benchmark surfaced: **config recall 0.74 → 0.96, overall
  0.645 → 0.711**, tuned benchmark held at 1.000.
- **Library-form detector coverage** — the second recall cluster, closed across
  six detectors: Go `jwt.SigningMethod*` and Rust `Algorithm::RS256/ES256`
  identifier forms; libsodium `crypto_sign_ed25519_keypair` / `crypto_kx` /
  `scalarmult` (C); the `ed25519` + `rbnacl` Ruby gems; BouncyCastle
  `Ed25519`/`X25519`/`X448`/DH lightweight classes (Java + C#, incl. the bare
  Kotlin-constructor form); and the `cloudflare/circl` + decred `secp256k1/v4`
  Go modules in the dependency catalog. **uncommon recall 0.66 → 0.90, overall
  0.711 → 0.813**; tuned benchmark held at 1.000, no new false positives. The
  residual 31 FNs are the lexical ceiling (runtime-constructed algorithm names,
  import aliasing) — out of reach without dataflow.
- **Real-repo validation fixes** — running qscan over four real OSS repos
  (golang-jwt, paramiko, panva/jose, gin) surfaced precision bugs and recall holes
  the authored corpus missed; all closed and pinned by benchmark cases. **Recall:**
  `x509`/PEM **key parsing** (`x509.Parse*`, Go — not just keygen), JOSE **RSA-OAEP**
  key transport (`jose-rsa-oaep`), and classical **SSH key exchange**
  (`ssh-kex-classical`: `diffie-hellman-group*` / `ecdh-sha2-*` / `curve25519`) —
  overall recall 0.813 → 0.824. **Precision:** a code-only **string-literal guard**
  (identifier rules like `go-jwt-signingmethod` no longer fire inside string
  literals), a **documentation-file skip** (SSH/TLS/cert token rules skip
  `.rst`/`.md`), and **Python-docstring** suppression for token rules (PEM key
  material inside a docstring is still caught). **Readiness score** now down-weights
  findings in test/fixture/doc paths (a no-crypto web app scored 40 → 81). Tuned
  benchmark held at 1.000 with three new negative baits.

### Added (audit remediation)

- **`qscan --tier category-3|category-5`** — CNSA security-tier migration targets
  in the report footer (`formatTierGuidance`), making the previously library-only
  `remediationForTier` reachable (category-5 → ML-KEM-1024 / ML-DSA-87).
- **Cross-language detector parity** — TLS-config detection across all 7 non-JS
  packs; verify/decrypt-only coverage (Go/C/Ruby); the Rust `openssl` crate +
  ring X25519 + braced-import constructors; Python hazmat-DSA; Java BouncyCastle
  agreement classes; the JWT detector extended to Go/Ruby; PEM public-key / DH-
  parameters / CSR markers; C EVP API + libsodium; Python `ec.ECDH()`.
- **Supply-chain CI** — OpenSSF Scorecard workflow; a zero-runtime-dependency
  enforcement gate (`scripts/check-zero-deps.mjs`); `reuse lint` (advisory);
  `dependabot.yml`; per-package `LICENSE`.
- **`PQC_TRANSITION_NOTE`** — IR 8547 deprecation timeline + HQC / FN-DSA (FIPS
  206) / X-Wing forward-standards tracking. Dependency catalog: JOSE/JWT libs,
  pycrypto/jwcrypto/authlib, secp256k1 (cargo), net-ssh.
- **`qscan --format evidence`** — ISO/IEC 27001 A.8.24 readiness report (findings
  + inventory + CBOM + a deterministic content hash; external signer fills the
  attestation). **NuGet** dependency ecosystem (`.csproj`/`packages.config`).
  **SP 800-208** stateful-HBS detector (LMS/HSS/XMSS/XMSSMT). **Java/C# JWT
  identifier-form** detection. **MCP `apply_verified_patch`** (runs the
  patch-policy + verify + blast-radius gates offline). **ACVP vector-provenance**
  in Sieve reports (raw-byte hashes + declared source, so a `kat` PASS is
  traceable). Agent **entropy-based redactor catch-all**.

### Fixed / changed (security & correctness)

- **Agent line (from the adversarial audit):** `qremediate --llm` now rejects
  LLM patches that add a network/exec sink or rewrite >60 lines and holds them
  back from `apply` without `--apply-llm`; "verified" reworded to "crypto-verified,
  not security-reviewed". Rubric moved to the provider `system` role + anti-injection
  preamble. Spend caps (`--max-llm`, `--max-findings`). Provider host-pinning
  (refuse plaintext non-local base URLs). `git add --` separator.
- **Standards:** SSH guidance → `mlkem768x25519-sha256`; SLH-DSA ACVP loader fixed
  (classify SLH before DSA); X448 → SecP384r1MLKEM1024; RSASSA-PSS keygen no longer
  mis-classified as KEM (Java); Go `ecdh.X25519()` split into its own family.
- **X25519 / X448 severity** `low` → `medium` (confidentiality/key-agreement, as
  Shor-broken as P-256 ECDH; the largest HNDL surface).

### Release

- The `v1` Action tag is auto-moved to the released commit on publish (was stale);
  per-job workflow permissions scoped; `persist-credentials: false` on CI checkouts;
  `inlineSources` so published sourcemaps aren't dangling.

## [0.4.2] — 2026-07-04

Multi-expert audit-hardening pass across all packages; Action `dist/` re-bundled.
First published to npm under the `@quantakrypto` scope with build provenance.

### Fixed

- Hardening fixes from a multi-discipline review (redactor coverage, readiness
  scoring, remediation edge cases); build clean, benchmark 1.000, zero runtime deps.

## [0.4.1] — 2026-07-03

### Fixed

- `qremediate` now fully fixes files with multiple TLS issues in one pass; added
  the end-to-end testing runbook ([`docs/how-to-test-0.4.md`](docs/how-to-test-0.4.md)).

## [0.4.0] — 2026-07-03

The multi-language + BYOK-agent release (0.3 skipped). Six new detector languages
and the optional LLM agent line land together; still **zero runtime dependencies**.

### Added

- **core (detectors):** language packs for **Python, Go, Java/Kotlin, C#, Rust,
  Ruby, and C/OpenSSL** — the `DetectorRegistry` now spans **8 source languages**
  (JS/TS + 7) plus PEM key material. Multi-ecosystem dependency manifests:
  PyPI, cargo, Go modules, Maven, RubyGems (in addition to npm; +yarn/pnpm lock
  parsing). Coverage-honesty labelling (`ANALYZABLE_LANGUAGES_LABEL`).
- **agent (new package `@quantakrypto/agent`):** zero-dep BYOK LLM client —
  native-`fetch` adapters for Anthropic Messages + OpenAI-compatible APIs, a
  zero-dep JSON-schema response validator, a repair-retry loop, and a response
  cache keyed by `(promptVersion, model, level, fingerprint)`. Triage orchestrator
  (rubric prompt) and LLM fix orchestrator (`proposeFix`, skips secret-bearing files).
- **qscan:** **`--triage`** (BYOK LLM re-ranks + explains findings; **never
  suppresses, never gates CI**) and **`qremediate`** — deterministic codemod fixes
  (`--mode diff|apply`), plus **`--llm`** and **`--mode pr`** (draft-PR), all
  verify-gated and worktree-isolated with **no auto-merge**.
- **mcp:** deterministic **`triage_findings` / `apply_triage`** and
  **`remediate_findings`** — request/apply tools that stay **offline and key-free**
  (the host agent reasons; the server never calls a provider).
- **action:** **`comment-plan`** migration-plan PR comment; `dist/` re-bundled.

### Notes

- This is the first release published to npm; earlier versions were tagged but
  the packages went public here.

## [0.2.2] — 2026-07-02

### Changed / Fixed

- Readiness score uses exponential decay so it stays responsive across the whole
  range (was pinning flat at 0 on large repos, hiding all progress).
- The Action upserts its PR comment via a hidden marker instead of stacking a new
  comment every push.
- Expanded the npm dependency DB (+15: ethers, web3, bitcoinjs-lib, openpgp,
  node-jose, ssh2, @peculiar/x509, http-signature, libsodium-wrappers, …).

## [0.2.1] — 2026-07-02

### Fixed

- The `qscan` CLI was a silent no-op via `npx` / the `.bin` symlink / macOS
  `/tmp` — the main-guard compared `import.meta.url` to the unresolved `argv[1]`.
  Resolve symlinks like the MCP stdio guard does; added a symlink smoke test.

## [0.2.0] — 2026-06-29

The audit-hardening release. Implements the full P0/P1/P2 roadmap (see
[`docs/ROADMAP.md`](docs/ROADMAP.md)). Build clean; **307 tests pass**; ESLint +
Prettier clean; still zero runtime dependencies.

### Added

- **core:** shared canonical baseline (`fingerprintFinding`/`applyBaseline`/…);
  `DetectorRegistry` + `Detector.scope`/`language`; wired `ScanOptions`
  (`include`/`files`/`scanMinified`); new detectors (DH MODP, SSH keys, TLS
  certificate signature algorithms, JOSE `ECDH-ES*`, one-shot `sign`/`verify`,
  `secp256k1`); CWE tags on findings; CycloneDX **CBOM** export (`toCbom`);
  `scanParallel` worker pool; `changedFiles` incremental helper; CNSA 2.0
  Category-5 + SP 800-208 remediation guidance.
- **qscan:** `--include`, `--max-file-size`, `--no-default-ignores`,
  `--scan-minified`, `--changed`/`--since` (incremental), `--parallel`/
  `--concurrency`, and `--cbom` output.
- **mcp:** safe-by-default HTTP transport (loopback bind, `QUANTAKRYPTO_MCP_TOKEN`
  auth, filesystem tools gated behind `QUANTAKRYPTO_MCP_ALLOW_FS`, per-request
  timeout + response cap); `generate_cbom` tool.
- **sieve:** SLH-DSA (FIPS 205); FIPS 203 §7.2 encapsulation-key modulus-range
  check; deeper ML-DSA + deterministic/hedged signing probe; bounded pipelining.
- **repo:** ESLint + Prettier, `test:coverage`, a benchmark harness, OpenSSF
  Scorecard + release workflows, `REUSE.toml`, threat model, ADRs, SemVer
  policy, config spec, and ISO 27001 A.8.24 / ACVP-provenance designs.

#### Follow-ups landed (previously documented designs)

- **core/qscan:** `quantakrypto.config.json` support — `loadConfig` in core plus
  flags > config > defaults precedence in qScan, with `--config <path>` and
  `--no-config-file` (distinct from the `--no-config` *detector* toggle). [P2-9]
- **tests:** deterministic, seeded-PRNG fuzz targets for the hand-rolled parsers
  — manifest/dependency parsing + `toSarif` (core), `decodeResponse`/`fromB64`
  (sieve), and the argv parser (qscan), in each package's `test/fuzz.test.ts`. [P1-10]
- **repo:** a zero-dep `.githooks/pre-commit` hook (build → lint → format:check →
  test) [P2-5]; `scripts/validate-sarif.mjs` SARIF 2.1.0 structural validator +
  `validate:sarif` script [P2-6]; and advisory `bench` + gating `sarif` CI jobs.

### Fixed (security & correctness)

- EC key generation is now classified as key-exchange-capable (harvest-now
  exposure was under-reported). [P0-4]
- PR-comment Markdown and `::error::` workflow-command output are escaped against
  injection from attacker-controlled finding text. [P0-2]
- The Sieve runner spawns the SUT with a scrubbed minimal environment. [P0-3]
- `explain_finding` resolves library-rule findings (was "no matching detector"). [P0-5]
- Hardened the TLS cipher regex (ReDoS) and replaced the quadratic proximity
  scan with a binary search. [P0-6]
- The GitHub Action now reuses qScan's `runQscan` and the shared baseline instead
  of a divergent second implementation. [P1-3]

## [0.1.0] — 2026-06-03

Initial release of the `quantakrypto-tools` monorepo — a zero-runtime-dependency
TypeScript toolset for post-quantum readiness.

### Added

- **`@quantakrypto/core`** — shared engine: JavaScript/TypeScript + config crypto
  detectors, a vulnerable-dependency database, a cryptographic inventory with a
  0–100 readiness score, and SARIF 2.1.0 / JSON / text reporters.
- **`@quantakrypto/qscan`** — CLI to scan any codebase for quantum-vulnerable
  cryptography, with baselines, severity gating, and SARIF output.
- **`@quantakrypto/mcp`** — Model Context Protocol server (stdio JSON-RPC implemented
  in-house) exposing scan/inventory/explain/suggest tools to AI coding agents,
  plus a hostable HTTP transport scaffold.
- **`@quantakrypto/action`** — GitHub Action that fails CI when newly introduced
  quantum-vulnerable cryptography lands, with baseline suppression and SARIF.
- **`@quantakrypto/sieve`** — conformance battery for ML-KEM / ML-DSA implementations
  driven over a JSON protocol; ships no KAT vectors and never fabricates them.
- Project governance, CI, and a multi-discipline audit set under `docs/`.

<!-- Per-version compare links are omitted: releases are currently published from
`main` rather than immutable `vX.Y.Z` tags (only a moving `v1` Action tag exists).
Cutting semver tags + a GitHub Release per version is tracked as a release-process
fix. -->
[Unreleased]: https://github.com/quantakrypto/pqc-tools/commits/main
[0.1.0]: https://github.com/quantakrypto/pqc-tools/releases/tag/v0.1.0
