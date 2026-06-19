# quantakrypto-tools

[![CI](https://github.com/dandelionlabs-io/qproof-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/dandelionlabs-io/qproof-tools/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Node ≥20](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)
![TypeScript strict](https://img.shields.io/badge/TypeScript-strict-3178c6)
![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0-success)
![Tests: 307 passing](https://img.shields.io/badge/tests-307%20passing-brightgreen)
[![NIST FIPS 203/204/205](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-7c3aed)](docs/COMPLIANCE.md)

Open-source post-quantum readiness tooling by [quantakrypto](https://quantakrypto.com/tools).
Free to use, instrumented for nothing — find quantum-vulnerable cryptography,
wire post-quantum readiness into your editor and your CI, and conformance-test
post-quantum implementations.

> **Design goals:** simple, clean, reusable code; **zero runtime dependencies**
> (Node built-ins only); everything documented, tested, and example-driven.

## Packages

| Package | What it is | Install |
|---|---|---|
| [`@quantakrypto/core`](packages/core) | Shared library — crypto detectors, vulnerable-dependency DB, inventory + SARIF reporting | `npm i @quantakrypto/core` |
| [`@quantakrypto/qscan`](packages/qscan) | **qScan** — CLI that finds quantum-vulnerable crypto in any codebase | `npx @quantakrypto/qscan ./` |
| [`@quantakrypto/mcp`](packages/mcp) | **quantakrypto MCP** — post-quantum readiness for AI coding agents (local + hostable) | `claude mcp add quantakrypto npx @quantakrypto/mcp` |
| [`@quantakrypto/action`](packages/action) | **quantakrypto Action** — fail CI when new quantum-vulnerable crypto lands | `uses: dandelionlabs-io/qproof-tools/packages/action@v1` |
| [`@quantakrypto/sieve`](packages/sieve) | **Sieve** — conformance battery for ML-KEM / ML-DSA implementations | `npx @quantakrypto/sieve` |

`qScan`, `quantakrypto MCP`, and `quantakrypto Action` all share `@quantakrypto/core`. `Sieve` is
standalone (it tests *other* implementations, it doesn't implement crypto).

## Workspace layout

```
quantakrypto-tools/
├── packages/
│   ├── core/     @quantakrypto/core    — shared engine (the contract lives in src/types.ts + src/index.ts)
│   ├── qscan/    @quantakrypto/qscan   — CLI
│   ├── mcp/      @quantakrypto/mcp     — MCP server (stdio now, HTTP scaffold for hosting)
│   ├── action/   @quantakrypto/action — GitHub Action
│   └── sieve/    @quantakrypto/sieve  — conformance battery + JSON protocol
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

- **[Roadmap & gap analysis](docs/ROADMAP.md)** — the prioritised plan (P0/P1/P2)
  and "what's missing", distilled from the audits. Start here to pick up work.
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
