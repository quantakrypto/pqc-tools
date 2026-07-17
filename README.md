# quantakrypto-tools

[![CI](https://github.com/quantakrypto/pqc-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/quantakrypto/pqc-tools/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![npm @quantakrypto/core](https://img.shields.io/npm/v/@quantakrypto/core?label=%40quantakrypto%2Fcore)](https://www.npmjs.com/package/@quantakrypto/core)
[![npm @quantakrypto/qscan](https://img.shields.io/npm/v/@quantakrypto/qscan?label=%40quantakrypto%2Fqscan)](https://www.npmjs.com/package/@quantakrypto/qscan)
[![npm @quantakrypto/mcp](https://img.shields.io/npm/v/@quantakrypto/mcp?label=%40quantakrypto%2Fmcp)](https://www.npmjs.com/package/@quantakrypto/mcp)
[![npm @quantakrypto/sieve](https://img.shields.io/npm/v/@quantakrypto/sieve?label=%40quantakrypto%2Fsieve)](https://www.npmjs.com/package/@quantakrypto/sieve)
[![npm @quantakrypto/agent](https://img.shields.io/npm/v/@quantakrypto/agent?label=%40quantakrypto%2Fagent)](https://www.npmjs.com/package/@quantakrypto/agent)
![Node ≥20](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)
![TypeScript strict](https://img.shields.io/badge/TypeScript-strict-3178c6)
![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0-success)
[![NIST FIPS 203/204/205](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-7c3aed)](docs/COMPLIANCE.md)

Open-source post-quantum readiness tooling by [quantakrypto](https://quantakrypto.com).
Find quantum-vulnerable cryptography in any codebase, wire post-quantum readiness
into your editor and your CI, and conformance-test post-quantum implementations —
with **zero runtime dependencies** (Node built-ins only).

> **Design goals:** simple, clean, reusable code; **zero runtime dependencies**;
> everything documented, tested, and example-driven.

## What's inside

| Tool | What it does | Get it |
|---|---|---|
| **[qScan](packages/qscan)** (`@quantakrypto/qscan`) | CLI that finds quantum-vulnerable crypto (RSA, (EC)DH, ECDSA, EdDSA, …) across **9 languages** (JS/TS, Python, Go, Java/Kotlin/Scala, C#, Rust, Ruby, PHP, C/OpenSSL) and prints a readiness score. SARIF / JSON / CBOM output, baselines, incremental & parallel scans. Opt-in `--triage` (BYOK LLM re-rank/explain) and a `qremediate` codemod CLI. | `npx @quantakrypto/qscan ./` |
| **[MCP](packages/mcp)** (`@quantakrypto/mcp`) | Model Context Protocol server that gives AI coding agents post-quantum readiness tools (scan, inventory, explain, suggest-hybrid, CBOM). Local stdio + hostable HTTP. | `claude mcp add quantakrypto npx @quantakrypto/mcp` |
| **[Sieve](packages/sieve)** (`@quantakrypto/sieve`) | Conformance battery for ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) implementations, driven over a JSON stdin/stdout protocol. | `npx @quantakrypto/sieve --help` |
| **[Action](packages/action)** (`@quantakrypto/action`) | GitHub Action that runs qScan in CI, uploads SARIF, annotates the diff, and fails the build only on **new** quantum-vulnerable crypto. | `uses: quantakrypto/pqc-tools/packages/action@v1` |
| **[agent](packages/agent)** (`@quantakrypto/agent`) | Optional, zero-dependency BYOK (bring-your-own-key) LLM client (native `fetch`; Anthropic + OpenAI-compatible adapters) that powers qScan `--triage` and `qremediate --llm`. Networked, key-holding — kept isolated (see also qProbe). | `npm i @quantakrypto/agent` |
| **[qProbe](packages/qprobe)** (`@quantakrypto/qprobe`) | Actively probes **live TLS/SSH endpoints you own** for post-quantum readiness — PQC-hybrid key exchange (X25519MLKEM768) and classical certificate posture. Gated behind an ownership attestation; reports, never modifies ("engine disposes"). See [THREAT-MODEL](packages/qprobe/THREAT-MODEL.md). | `npx @quantakrypto/qprobe --i-own-this host` |

All four of qScan, MCP, the Action, and agent share the engine in
**[`@quantakrypto/core`](packages/core)** (`npm i @quantakrypto/core`) — detectors,
the vulnerable-dependency DB, the readiness score, SARIF/JSON/CBOM reporting, and the
offline agent-plane primitives (context redactor, `verify_fix` gate, codemods, patch
policy). Sieve is standalone: it tests *other* implementations and implements no
crypto itself.

**Infrastructure coverage.** Beyond application source, the shared `core` engine
carries **config-scope detectors** for Terraform/OpenTofu IaC and cloud KMS, JSON
Web Keys, Kubernetes / cert-manager / Istio, CI/CD artifact & code signing
(cosign/GPG/jarsigner/codesign/minisign), secrets at rest (SOPS/age, PGP, Sealed
Secrets), message brokers (Kafka/MQTT), databases (pgcrypto, libpq `sslmode`), and
JOSE/JWE key management — so `qscan`, the Action, and MCP flag **infrastructure**
crypto with no extra install. **qProbe** adds the live-endpoint dimension (see the
table above). The narrative anchor for infrastructure is *harvest now, decrypt
later*: data and secrets captured today are decryptable once a CRQC exists.

## Quick start

```bash
# 1. Scan a codebase for quantum-vulnerable cryptography.
npx @quantakrypto/qscan ./

# 2. Give your AI coding agent post-quantum readiness tools.
claude mcp add quantakrypto npx @quantakrypto/mcp

# 3. Conformance-test a post-quantum implementation (adapter speaks the JSON protocol).
npx @quantakrypto/sieve --impl "node ./my-impl.js" --param ml-kem-768
```

Add the CI gate by dropping
[`packages/action/examples/quantum-readiness.yml`](packages/action/examples/quantum-readiness.yml)
into `.github/workflows/`, or wire it up directly:

```yaml
- uses: quantakrypto/pqc-tools/packages/action@v1
  with:
    path: "."
    severity-threshold: "high"
```

Each package README has the full options reference and more examples:
[qScan](packages/qscan/README.md) ·
[MCP](packages/mcp/README.md) ·
[Sieve](packages/sieve/README.md) ·
[Action](packages/action/README.md) ·
[core](packages/core/README.md) ·
[agent](packages/agent/README.md).

## Using quantakrypto alongside a PQC library (liboqs / OQS)

quantakrypto **does not implement post-quantum cryptography, by design** — it is
the scanner, the CI gate, and the conformance harness you wrap around a real PQC
library like [liboqs / Open Quantum Safe](https://openquantumsafe.org/). They
compose: quantakrypto **finds and gates** classical crypto (`qscan`, the Action),
tells you **what to migrate to and in what order** (`qscan --tier`, MCP
`plan_migration`, `qremediate`), and **proves the replacement is correct**
(`sieve` conformance-tests any ML-KEM/ML-DSA/SLH-DSA implementation against
FIPS 203/204/205). liboqs supplies the primitives.

See the worked end-to-end walkthrough — scan → migrate → verify → gate — in
**[`examples/liboqs-migration/`](examples/liboqs-migration/README.md)**.

## Workspace layout

```
quantakrypto-tools/
├── packages/
│   ├── core/     @quantakrypto/core    — shared engine (the contract lives in src/types.ts + src/index.ts)
│   ├── qscan/    @quantakrypto/qscan   — CLI
│   ├── mcp/      @quantakrypto/mcp     — MCP server (stdio now, HTTP scaffold for hosting)
│   ├── action/   @quantakrypto/action — GitHub Action
│   ├── sieve/    @quantakrypto/sieve   — conformance battery + JSON protocol
│   ├── agent/    @quantakrypto/agent   — opt-in BYOK LLM client (triage + remediation)
│   └── qprobe/   @quantakrypto/qprobe  — active TLS/SSH endpoint probing (gated; the only prober)
├── docs/         architecture, hosted-MCP design, improvement roadmap
└── examples/     end-to-end examples
```

## Development

Requires Node ≥ 20.

```bash
npm install        # links the workspaces
npm run build      # tsc --build (project references)
npm test           # node:test across all packages
```

The toolchain is intentionally tiny: TypeScript + `tsx` (to run `node:test` on
`.ts`) are the only dev dependencies; there are **no runtime dependencies**.

## Documentation, audits & compliance

Full documentation lives in **[`docs/`](docs/README.md)**:

- **[Roadmap & status](docs/ROADMAP.md)** — the prioritised plan (P0/P1/P2) and
  "what's missing", distilled from the audits. Most of it has shipped, so it now
  reads as a status doc — what's done and what remains — rather than a worklist.
- **Audits** (independent expert passes): [security](docs/audits/security.md) ·
  [cryptography](docs/audits/cryptography.md) · [architecture](docs/audits/architecture.md) ·
  [performance](docs/audits/performance.md) · [testing/devex](docs/audits/testing-devex.md) ·
  [overview](docs/AUDIT.md).
- **[Standards & compliance](docs/COMPLIANCE.md)** — what the tools touch and
  could align to: NIST FIPS 203/204/205, SP 800-208, CNSA 2.0, SARIF, CWE,
  ISO/IEC 27001 (A.8.24), Common Criteria, FIPS 140-3, EU DORA/NIS2, US
  M-23-02 / NSM-10, and OSS assurance (SLSA, OpenSSF Scorecard, SPDX/REUSE).
- **Governance:** [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
  [Code of Conduct](CODE_OF_CONDUCT.md) · [Changelog](CHANGELOG.md).

## License

[Apache-2.0](LICENSE). The methodology is open; the audits, certificates, and
deliverables are where the [quantakrypto](https://quantakrypto.com) practice lives.

## Support & training

Questions, commercial support, or post-quantum readiness training for your team —
visit **[quantakrypto.com](https://quantakrypto.com)** or email
**[hello@quantakrypto.com](mailto:hello@quantakrypto.com)**.
