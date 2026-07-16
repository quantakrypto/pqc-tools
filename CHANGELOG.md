# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.

## [Unreleased]

### Added / Changed (standards currency + guidance wiring)

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
