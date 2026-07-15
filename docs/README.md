# quantakrypto-tools — documentation

Engineering, audit, and compliance docs for the [quantakrypto-tools](../README.md)
monorepo. Start here.

## Roadmap & gaps

- **[ROADMAP.md](ROADMAP.md)** — the consolidated, prioritised plan (P0/P1/P2)
  and the "what's missing" gap matrix, distilled from every audit below. Most of
  it has shipped, so it now reads as a **status doc** — what's done and what
  remains — rather than a worklist.

## Audits

A general audit plus five discipline-specific reviews, each by an independent
expert pass. They cite `file:line` and propose concrete fixes.

| Audit | Lens | File |
|---|---|---|
| Overview | Correctness, security, perf, hosting (first pass) | [AUDIT.md](AUDIT.md) |
| Security | Threat model, ReDoS, hosted-MCP, injection (CWE-mapped) | [audits/security.md](audits/security.md) |
| Cryptography | NIST PQC correctness, detector accuracy, Sieve methodology | [audits/cryptography.md](audits/cryptography.md) |
| Architecture | Contracts, extensibility, baseline schism, API design | [audits/architecture.md](audits/architecture.md) |
| Performance | Hot path, complexity, parallelism, incremental scans | [audits/performance.md](audits/performance.md) |
| Testing / DevEx | Coverage, CI, lint/format, OSS governance | [audits/testing-devex.md](audits/testing-devex.md) |

## Validation & accuracy

Empirical, reproducible measurements of detector behaviour — locked as
regression guards in the test suite.

| Doc | What it measures |
|---|---|
| [validation/detection-benchmark.md](validation/detection-benchmark.md) | qScan detector precision / recall / F1 against a labeled corpus (current: P 0.969 · R 1.000 · F1 0.984), with a frank list of known false positives / false negatives |
| [validation/sieve-real-impl.md](validation/sieve-real-impl.md) | Sieve driven against a real audited PQC implementation (`@noble/post-quantum`): passes ML-KEM/ML-DSA/SLH-DSA, catches a broken variant, and surfaced one genuine FIPS 203 §7.2 deviation |
| [validation/qscan-dogfood.md](validation/qscan-dogfood.md) | qScan run on real repositories (`jsonwebtoken`, `jose`) — accurate inventory + readiness verdict on crypto-heavy code |

- **[how-to-test-0.4.md](how-to-test-0.4.md)** — hands-on walkthrough for exercising
  the 0.4 release end to end (scan, `--triage`, `qremediate`, MCP, the Action).

## Security & threat model

- **[THREAT-MODEL.md](THREAT-MODEL.md)** — assets, trust boundaries, data flows,
  STRIDE per tool, the hosted-MCP and Sieve↔SUT boundaries, attacker scenarios,
  and the mitigations→ROADMAP-P0 map. Companion to the [security audit](audits/security.md).

## Architecture decisions & policies

| Doc | What it covers |
|---|---|
| [adr/README.md](adr/README.md) | ADR index + template |
| [adr/0001](adr/0001-zero-runtime-dependencies.md) | Zero runtime dependencies (Node built-ins only) |
| [adr/0002](adr/0002-shared-core-contract.md) | `@quantakrypto/core` is the single shared contract |
| [adr/0003](adr/0003-monorepo-and-build.md) | npm-workspaces monorepo + `tsc -b` project references |
| [adr/0004](adr/0004-sieve-no-fabricated-vectors.md) | Sieve ships no KAT vectors / never fabricates values |
| [VERSIONING.md](VERSIONING.md) | SemVer + deprecation policy for `@quantakrypto/*`; what's breaking on the core contract |
| [CONFIG.md](CONFIG.md) | Spec for the optional `quantakrypto.config.json` (schema + precedence) |

## Standards & compliance

- **[COMPLIANCE.md](COMPLIANCE.md)** — what the tools touch / help align with /
  would need to certify against: NIST FIPS 203/204/205, SP 800-208, CNSA 2.0,
  SARIF, CWE, ISO/IEC 27001 (A.8.24), Common Criteria, FIPS 140-3, EU DORA/NIS2,
  US M-23-02 / NSM-10, and OSS-assurance (SLSA, OpenSSF Scorecard, SPDX/REUSE).
- **[SUPPLY-CHAIN.md](SUPPLY-CHAIN.md)** — OpenSSF Scorecard + SLSA/npm provenance
  + SPDX/REUSE: targets vs. current status, and the deferred npm-provenance plan.

### Compliance designs (not yet implemented)

| Doc | What it designs |
|---|---|
| [compliance/iso27001-a8.24-evidence.md](compliance/iso27001-a8.24-evidence.md) | A signed, timestamped A.8.24 "Use of cryptography" readiness-evidence report (scan + inventory + CBOM + attestation) |
| [compliance/acvp-provenance.md](compliance/acvp-provenance.md) | How Sieve records provenance (source URL, hash, version) of operator-supplied NIST ACVP vectors |

## Agent line (BYOK, opt-in)

The optional bring-your-own-key LLM line — qScan `--triage`, the `qremediate` CLI,
and the key-free MCP `triage_findings` / `apply_triage` / `remediate_findings`
tools — is built on [`@quantakrypto/agent`](../packages/agent/README.md).

- [superpowers/specs/2026-07-03-byok-agent-tools-design.md](superpowers/specs/2026-07-03-byok-agent-tools-design.md) — the BYOK agent-tools design.
- [superpowers/plans/2026-07-03-byok-agent-tools.md](superpowers/plans/2026-07-03-byok-agent-tools.md) — the implementation plan.

## Per-package & protocol docs

- [`@quantakrypto/core`](../packages/core/README.md) · [`qscan`](../packages/qscan/README.md) · [`mcp`](../packages/mcp/README.md) · [`action`](../packages/action/README.md) · [`sieve`](../packages/sieve/README.md) · [`agent`](../packages/agent/README.md)
- [MCP hosting design](../packages/mcp/HOSTING.md)
- [Sieve ↔ SUT protocol](../packages/sieve/PROTOCOL.md) · [obtaining NIST ACVP vectors](../packages/sieve/vectors/README.md)

## Project governance

- [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md) · [Code of Conduct](../CODE_OF_CONDUCT.md) · [Changelog](../CHANGELOG.md)
