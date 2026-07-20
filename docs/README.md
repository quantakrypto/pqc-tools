# quantakrypto-tools — documentation

Engineering, standards, and compliance documentation for the
[quantakrypto-tools](../README.md) monorepo. Start here.

## Objectives & decisions

- **[OBJECTIVES.md](OBJECTIVES.md)** — what the toolchain is for, what each library
  does, the load-bearing decisions, and the deliberate scope boundaries. Read this
  first.
- **[adr/](adr/README.md)** — Architecture Decision Records: the immutable "why"
  behind each load-bearing choice (zero deps, shared core contract, monorepo, no
  fabricated vectors, the two-plane agent architecture, English-only output).
- **[VERSIONING.md](VERSIONING.md)** — SemVer + deprecation policy (operationalises
  ADR-0002).
- **[CONFIG.md](CONFIG.md)** — the optional `quantakrypto.config.json` spec.

## Standards & compliance

- **[COMPLIANCE.md](COMPLIANCE.md)** — how the toolset maps to PQC standards
  (FIPS 203/204/205, CNSA 2.0, SP 800-208, IR 8547), interchange formats
  (SARIF, CycloneDX/CBOM, OpenVEX, SPDX/REUSE), and information-security frameworks
  — with honest "touches / helps align / would require" verbs.
- **[standards/pqc-standards.md](standards/pqc-standards.md)** — the dated, cited
  standards source of truth and the quarterly review runbook.
- **[compliance/iso27001-a8.24-evidence.md](compliance/iso27001-a8.24-evidence.md)**
  — the ISO/IEC 27001 A.8.24 evidence-chain export (`qscan --format evidence`),
  its deterministic content hash, external signing, and `--policy` verdicts.
- **[compliance/acvp-provenance.md](compliance/acvp-provenance.md)** — how Sieve
  records ACVP vector provenance for exact-value conformance claims.

## Security & supply chain

- **[THREAT-MODEL.md](THREAT-MODEL.md)** — the security model: the offline scanner's
  posture and the BYOK agent line's threats/mitigations (STRIDE, CWE-mapped).
- **[SUPPLY-CHAIN.md](SUPPLY-CHAIN.md)** — the supply-chain posture: zero runtime
  deps, SHA-pinned Actions, provenance, and the weekly cadence audit.

## API reference

- **[API.md](API.md)** + **[api-surface.json](api-surface.json)** — the generated,
  frozen public API surface for `@quantakrypto/core` and the other packages
  (`npm run api:docs` regenerates; `npm run api:check` gates drift).

## Validation & accuracy

Empirical, reproducible measurements of behaviour — each locked as a regression
guard in the test suite:

| Doc | What it measures |
|---|---|
| [validation/detection-benchmark.md](validation/detection-benchmark.md) | qScan detector precision / recall / F1 against a labelled corpus, with a frank list of known false positives / false negatives |
| [validation/recall-benchmark.md](validation/recall-benchmark.md) | Real-world false-negative (recall depth) benchmark, gated per language |
| [validation/remediation-benchmark.md](validation/remediation-benchmark.md) | Correctness of the deterministic codemod layer (applied / cleared / no-regression / idempotent) |
| [validation/sieve-real-impl.md](validation/sieve-real-impl.md) | Sieve driven against a real audited PQC implementation |
| [validation/qscan-dogfood.md](validation/qscan-dogfood.md) | qScan run on real crypto-heavy repositories |
| [validation/reproducible-build.md](validation/reproducible-build.md) | Byte-for-byte reproducibility of the published tarballs |

---

Per-package usage docs live in each package's own README:
[core](../packages/core/README.md) ·
[qscan](../packages/qscan/README.md) ·
[mcp](../packages/mcp/README.md) ·
[sieve](../packages/sieve/README.md) ·
[action](../packages/action/README.md) ·
[agent](../packages/agent/README.md) ·
[qprobe](../packages/qprobe/README.md).
