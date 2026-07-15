# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.

## [Unreleased]

_Nothing yet._

## [0.4.3] — 2026-07-15

The **2026-07-15 5-lens audit** ([`docs/audits/2026-07-15-v0.4-review.md`](docs/audits/2026-07-15-v0.4-review.md))
and its remediation. Build clean; **~640 tests**; benchmark precision/recall
**1.000** throughout; still zero runtime dependencies.

### Added

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
