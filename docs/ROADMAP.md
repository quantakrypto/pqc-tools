# quantakrypto-tools — Roadmap & Status

The forward plan is in §1–§2. The v0.2 audit tables (§3 onward) are retained as
the historical record of how the tool got here — every item in them shipped.

Audit sources: [security](audits/security.md) · [cryptography](audits/cryptography.md)
· [architecture](audits/architecture.md) · [performance](audits/performance.md)
· [testing/devex](audits/testing-devex.md) · [overview](AUDIT.md) · [COMPLIANCE.md](COMPLIANCE.md).

---

> ## ✅ Current status — v0.4.2 (published)
>
> All five packages are live on npm at **0.4.2** with build provenance:
> `@quantakrypto/`**core · qscan · mcp · sieve · agent**.
>
> - **Detectors:** **9 source languages** — JS/TS, Python, Go, Java/Kotlin, C#,
>   Rust, Ruby, PHP, C/C++ — plus PEM key material and the config-scope infra
>   detectors (Terraform, cloud KMS, JWK, k8s, CI/CD, secrets, messaging, …).
> - **Quality:** **593 tests** across the workspaces (core 259 · qscan 116 ·
>   mcp 94 · sieve 55 · action 50 · agent 19); precision/recall benchmark
>   **= 1.000**; build + ESLint + Prettier clean; **zero runtime dependencies**.
> - **Distribution:** the GitHub Action ships a committed `dist/` (usable via
>   `uses:`); packages published under the real `@quantakrypto` scope.

### What shipped since the v0.2 audit

The v0.2 roadmap (below) closed every P0/P1/P2 item. Since then, three things
landed that the old roadmap treated as **future** or **deferred**:

1. **BYOK LLM agent line** — a new **`@quantakrypto/agent`** package (zero-dep,
   native-`fetch` adapters for Anthropic + OpenAI-compatible APIs, response
   validator, cache) plus:
   - **`qscan --triage`** — an LLM re-ranks findings by real exposure and
     explains them. It **never suppresses a finding and never changes the exit
     code** ("model proposes, engine disposes").
   - **`qremediate`** — deterministic template codemods first, then optional
     **`--llm`** fixes applied in an **ephemeral worktree behind a `verify_fix`
     gate**; `--mode diff|apply|pr`; **no auto-merge**.
   - **MCP `triage_findings` / `remediate_findings`** — exposed as deterministic
     request/apply tools; **the MCP itself stays offline and key-free** (the host
     agent reasons; no network, no API key in the server).
   - **Action `comment-plan`** — posts a migration-plan comment on PRs.
   - Hard invariants: zero third-party runtime deps (native `fetch`), **secrets
     redacted before any egress**, `verify_fix` on every patch, no auto-merge,
     triage never suppresses / never changes exit code.

2. **Six more detector languages** — v0.2 shipped JS/TS only and listed "add a
   language (Python/Go/Java)" as future work (P1-4). The `DetectorRegistry` now
   carries Python, Go, Java, C#, Rust, Ruby, and C/C++.

3. **Published + distributable** — §5 "release readiness (deferred)" is **done**:
   npm publish under `@quantakrypto` with provenance, the Action `dist/`
   committed, and `repository`/`bugs`/`homepage` filled in on every package.

---

## 1. v0.4 → 1.0 — what's actually left

Re-prioritised against the shipped v0.4 surface. A multi-lens Fable 5 audit is
running against this list; findings will be folded in.

### 🔴 Critical — clear before a credible 1.0

- **Threat-model the agent / BYOK line.** Every prior security audit targeted the
  deterministic, offline v0.2 scanner. The agent line is the tool's **only**
  networked, secret-handling, code-writing surface and is **not yet covered by
  [THREAT-MODEL.md](THREAT-MODEL.md)**. Needs an adversarial review of:
  - **prompt injection** from scanned repos into LLM triage/remediation (verify
    "triage never suppresses / never changes exit code" is enforced in *code*,
    not just prompt text);
  - **data egress** to the LLM provider — is the secret redactor applied on
    *every* path that builds LLM context? Can PEM / keys / `.env` leak?
  - **remediation-patch safety** — verify-gate bypass, out-of-scope file writes,
    ephemeral-worktree escape, the no-auto-merge guarantee;
  - **BYOK key handling** (never logged / cached / echoed in errors);
  - **budget / DoS** from a hostile repo.
  - *Status (2026-07-15): **audit complete** — see
    [audits/2026-07-15-v0.4-review.md](audits/2026-07-15-v0.4-review.md). The
    safety spine (no-suppress triage, no auto-merge, key hygiene, redactor-on-every-
    path, worktree isolation) was verified held in code. The residual gaps it found
    are **fixed**: the crypto-only verify gate now has a blast-radius guard + honest
    "crypto-verified, not security-reviewed" framing (F1), instruction/data
    separation via the provider system role (F2), spend caps (F3), and F5–F7. The
    THREAT-MODEL §4.6/§6.5 carries the verdicts.*

### 🟠 High

- ~~**Cross-language detection parity.**~~ ✅ **Done (2026-07-15).** The 7 non-JS
  packs gained cross-language TLS-config detection, verify/decrypt-only coverage,
  the Rust `openssl` crate + ring X25519, Java BouncyCastle + the RSASSA-PSS fix,
  Go's X25519-as-its-own-family, JWT for Go/Ruby, and PEM public-key/DH/CSR
  markers — with 9 new labelled corpus fixtures and the benchmark held at 1.000.
  See [audits/2026-07-15-v0.4-review.md](audits/2026-07-15-v0.4-review.md).
  *Residual:* a per-language false-negative *depth* benchmark (measuring recall
  against a larger real-world corpus) is still worthwhile as a standing quality gate.
- ~~**Standards-currency cadence.**~~ ✅ **Done (2026-07-19).** Operationalised:
  a single dated, cited source of truth ([`packages/core/src/standards.ts`](../packages/core/src/standards.ts),
  `PQC_STANDARDS`) for FIPS 203/204/205, the CNSA 2.0 tiers, SP 800-208, the
  IR 8547 timeline, and the emerging/hybrid targets; a **drift test** that fails
  CI if the runtime remediation constants diverge from it; an advisory
  `npm run standards:check` (in CI) that warns when the quarterly review is due;
  and a review runbook ([docs/standards/pqc-standards.md](standards/pqc-standards.md)).
  "Are we current?" is now a checkable, dated question.

### 🟡 Medium

- ~~**ISO/IEC 27001 A.8.24 evidence-chain export + ACVP provenance.**~~ ✅
  **Done (2026-07-19).** `qscan --format evidence` emits the readiness report
  (findings + inventory + CBOM + a deterministic content hash); Sieve records
  ACVP vector **provenance** (`provenanceDeclared`); and `--policy <file>` now adds
  the §4 **conformant / violation / transition-pending** verdicts against an org
  crypto policy, folded into the attested hash. Only signing + RFC-3161 timestamping
  remain, and those are **deliberately external** (ADR-0004 — the tool orchestrates
  a signer, it does not implement one).
- **Reproducible-build verification** for the published artifacts.
- **Report i18n / accessibility** of human-facing output.
- **Published supply-chain gate on a cadence** — Scorecard + dependency/Action
  review, now that the packages are live on npm.

---

## 2. Recurring audit vectors (run on a cadence)

Fold these recurring lenses in beyond one-off reviews:

- **Fuzz / property-based testing** of every parser, in CI. *(landed — seeded
  fuzz in each package's `test/fuzz.test.ts`; keep extending.)*
- **Supply-chain posture** as a gate: OpenSSF Scorecard + dependency review (even
  at zero runtime deps, dev-deps and Actions are surface).
- **Detection-quality benchmark:** curated corpus measuring false-positive /
  false-negative rates **per language**, regression-tested over time.
- **Agent-line adversarial review:** prompt-injection, data-egress, and
  patch-safety re-tested whenever the agent/remediation code changes.
- **Reproducible-build** verification for published artifacts.
- **Standards drift:** re-check against NIST / CNSA / BSI updates each quarter.
- **CLI / output accessibility & i18n** of human-facing reports.

---
---

# Historical record — v0.2 audit & gap analysis

> The v0.2 roadmap below was the consolidated, prioritised plan distilled from the
> multi-discipline audits in [`docs/audits/`](audits/). **Every P0/P1/P2 item was
> implemented** (build clean, 307 tests at v0.2 → 593 now, ESLint + Prettier
> clean, zero runtime deps). Retained verbatim as the record of what each item
> entailed. The one item marked "deferred" at the time — publishing (§5) — has
> since shipped (see "Current status" above).

**Pre-v0.2 baseline:** the audits were run against v0.1 (182 tests). The items
below are improvements and gaps — not regressions.

## 3. What's missing (gap matrix)

| Area | Item | Status |
|---|---|---|
| Governance | `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue/PR templates, `.editorconfig` | ✅ **added** |
| CI | GitHub Actions: build + test on Node 20/22, self-scan dogfood | ✅ **added** (`.github/workflows/ci.yml`) |
| Docs | Discipline audits, compliance mapping, docs index, README badges | ✅ **added** |
| Quality | Code coverage tooling + gate | ✅ **done** (`test:coverage`, advisory CI job) |
| Quality | ESLint + Prettier | ✅ **done** (pre-commit hook: `.githooks/pre-commit`) |
| Tests | Real `core.scan()` over a real tree | ✅ **done** (core `scan.test.ts` + bench parity) |
| Tests | Coverage for `mcp/http.ts`, the action PR-comment path, runner timeouts | ✅ **done** |
| Crypto | SLH-DSA (FIPS 205) conformance in Sieve | ✅ **done** (SP 800-208: documented out-of-scope) |
| Crypto | Detectors for DH groups, SSH keys, TLS cert sig algs, JOSE/COSE | ✅ **done** |
| Perf | Benchmark harness | ✅ **done** (`scripts/bench.mjs`; advisory `bench` CI job) |
| Perf | Parallel (worker pool) + incremental (changed-files) scanning | ✅ **done** (`scanParallel`, `--changed`) |
| Security | Threat-model doc | ✅ **done** (+ deterministic fuzz targets, P1-10) |
| Compliance | CBOM (CycloneDX) output, CWE tagging | ✅ **done** (+ SARIF structural CI check, P2-6) |
| Supply chain | OpenSSF Scorecard, SLSA provenance, REUSE | ✅ **done** (workflows + `REUSE.toml`) |
| Release | Commit/bundle the Action `dist/`; npm publish under `@quantakrypto` | ✅ **done** (v0.4.x — see "Current status") |

---

## 4. P0 — security & correctness (do before hosting / 1.0)

These are confirmed bugs or real risks, each cited to source.

| # | Item | Package | Audit | Effort | Impact |
|---|---|---|---|---|---|
| P0-1 | **Hosted MCP = unauthenticated arbitrary read.** `scan_path`/`inventory_crypto` pass a client path into `core.scan` (`mcp/src/tools.ts:152,183`); `http.ts` binds `0.0.0.0` with no auth/timeout/size cap (`http.ts:171`, `server.ts:168`); the `snippet` field turns it into a content-disclosure oracle. **Gate the filesystem tools OFF by default on the HTTP transport; require auth + per-tool timeouts before exposing.** | mcp | security | M | Critical |
| P0-2 | **Output injection.** Attacker-named files / finding text flow unescaped into the PR-comment Markdown table and `::error::` workflow commands (`action/src/main.ts:190-193`), posted with a write token. **Escape `file`/`message` for Markdown and for workflow-command syntax.** | action | security | S | High |
| P0-3 | **Untrusted SUT inherits full env.** The Sieve runner spawns the SUT with the parent environment (`sieve/src/runner.ts:~89`), exposing secrets. **Pass a scrubbed, minimal env.** | sieve | security | S | High |
| P0-4 | **EC keys under-report harvest-now exposure.** `generateKeyPair('ec', …)` is hard-classified signature-only with `hndl:false` (`core/src/detectors/source.ts:54`), but EC keys feed **both ECDSA and ECDH** — so ECDH HNDL exposure is silently missed. **Classify EC keygen as key-exchange-capable (`hndl:true`) or emit both concerns.** | core | cryptography | S | High |
| P0-5 | **`explain_finding` is broken for library findings.** It maps `ruleId`→detector by prefix (`mcp/src/tools.ts:252`) and returns "no matching detector" for real `crypto-libs` findings (`forge-*`, `elliptic-ec`, `node-rsa`). **Look findings up by rule, not prefix.** | mcp | architecture | S | Medium |
| P0-6 | **ReDoS surface.** The TLS cipher regex has two unbounded spans around an alternation → super-linear backtracking (`core/src/detectors/source.ts:439`); `nearCall` is O(matches×calls) quadratic (`source.ts:196`). Bounded today by the 2 MiB cap, but **harden the regex and binary-search `callIndexes`** before any scan-on-content path ships. | core | security/perf | S | Medium |

---

## 5. P1 — correctness coverage & architecture

| # | Item | Package | Audit | Effort |
|---|---|---|---|---|
| P1-1 | **Unify the baseline.** qScan (`baseline.ts:40`, sha256 of `ruleId\|file\|snippet\|line`) and the Action (`main.ts:84`, raw `ruleId file message`) use incompatible fingerprints, semantics, and on-disk formats. Extract one shared baseline module in `@quantakrypto/core`. | core/qscan/action | architecture | M |
| P1-2 | **Repair `ScanOptions`.** `include` is declared but **unwireable** (`WalkOptions` has no field; `types.ts:107`); `runQscan` drops `maxFileSize`/`noDefaultIgnores` (`qscan/src/index.ts:110`) and there are no CLI flags. Wire them through. | core/qscan | architecture | S |
| P1-3 | **Action should reuse qScan.** It declares `@quantakrypto/qscan` + a project reference but never imports it, re-implementing `fingerprint`/`applyBaseline`/`renderReport`. Use `runQscan` (or drop the unused reference). | action | architecture | S |
| P1-4 | **Make detectors a real plugin point.** `scan()` closes over a hardcoded array and classifies scope by ruleId prefix (`scan.ts:23,26`). Add a `DetectorRegistry`, declare `language`/`scope` on `Detector`, and write an "add a language" guide (Python/Go/Java). | core | architecture | M |
| P1-5 | **New detectors** (false-negative closure): DH MODP groups (`getDiffieHellman`), SSH keys, TLS certificate signature algorithms, JOSE `ECDH-ES*` / COSE / WebAuthn, one-shot `crypto.sign`/`verify`, `secp256k1`. | core | cryptography | M |
| P1-6 | **Remediation nuance.** Surface the CNSA 2.0 Category-5 tier (ML-KEM-1024 / ML-DSA-87) and SP 800-208 (LMS/XMSS) where relevant, not only Category-3 defaults. | core | cryptography | S |
| P1-7 | **Sieve depth.** Add the FIPS 203 §7.2 encapsulation-key modulus-range check (deepens AF-05), deeper ML-DSA probes, and a deterministic-vs-hedged signing test. | sieve | cryptography | M |
| P1-8 | **Real integration test.** qScan's e2e runs through a `fakeScan` — add a test that runs the real `core.scan()` over a fixture tree. Add tests for `mcp/http.ts`, the action PR-comment path, and runner timeout/crash escalation. Add coverage tooling (`node --test --experimental-test-coverage`) + a CI gate. | all | testing | M |
| P1-9 | **Cheap perf wins.** Precompile the ~16 per-file inline regexes at module scope; skip minified/generated files beyond `.min.js`/`.map` (`walk.ts:79-85`); handle lockfiles > 2 MiB instead of silently skipping (`walk.ts:159`). | core | performance | S |
| P1-10 | **Threat model doc** + fuzz targets for the four hand-rolled parsers (Sieve protocol/base64, manifest, SARIF, qScan args). ✅ Fuzz targets landed: deterministic seeded-PRNG fuzz in each package's `test/fuzz.test.ts`. | all | security/testing | M |

---

## 6. P2 — scale, polish, assurance

| # | Item | Package | Audit |
|---|---|---|---|
| P2-1 | Parallel scanning: a `node:worker_threads` pool (`scanParallel(opts, { concurrency })`) with chunking, backpressure, deterministic merge, and a small-repo crossover guard. | core | performance |
| P2-2 | Incremental scanning: `git diff --name-only` changed-files mode + per-file hash cache (big CI win). | core/qscan | performance |
| P2-3 | Sieve throughput: pipeline / bounded-concurrency pool over the id-correlated protocol. | sieve | performance |
| P2-4 | Benchmark harness (zero-dep) + a perf-regression CI check on representative corpora. | all | performance |
| P2-5 | ESLint flat config + typescript-eslint (`no-floating-promises` for the async transports), Prettier, commit hooks. ✅ Pre-commit hook in `.githooks/pre-commit`. | all | testing |
| P2-6 | **CBOM** (CycloneDX cryptographic bill of materials) output from the inventory; CWE tagging on findings; SARIF schema validation in CI. ✅ `scripts/validate-sarif.mjs` (structural) + a `sarif` CI job. | core/compliance | compliance |
| P2-7 | OpenSSF Scorecard workflow, SLSA build provenance, SPDX/REUSE license headers, npm publish provenance. | repo | compliance/testing |
| P2-8 | ISO/IEC 27001 **A.8.24 evidence-chain** export (a signed, timestamped readiness report); ACVP vector-provenance pipeline; SLH-DSA (FIPS 205) conformance category. | core/sieve | compliance/crypto |
| P2-9 | Semver + deprecation policy, a generated public API reference, and ADRs; an optional `quantakrypto.config.json`. ✅ `quantakrypto.config.json` implemented: `loadConfig` in core, flags > config > defaults in qScan (see [CONFIG.md](CONFIG.md)). | all | architecture |
