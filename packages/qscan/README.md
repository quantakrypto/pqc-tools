# @quantakrypto/qscan

**Find quantum-vulnerable cryptography in any codebase.**

`qscan` walks a project and reports where it relies on classical asymmetric
cryptography (RSA, (EC)DH, ECDSA, EdDSA, DSA, …) — the algorithms broken by a
sufficiently large quantum computer, and the ones exposed to *harvest-now,
decrypt-later* (HNDL) attacks today. It scans source files, dependency
manifests, and configuration, then prints a readiness score and a concrete next
step.

- **Zero runtime dependencies.** Node built-ins only; the engine is
  [`@quantakrypto/core`](../core).
- **CI-friendly.** Severity thresholds drive the exit code; baselines suppress
  known findings so the build only fails on *new* problems.
- **Multiple formats.** `human` (default), `json`, SARIF 2.1.0 for code-scanning
  dashboards, a CycloneDX 1.6 **CBOM** for compliance tooling, an ISO 27001
  A.8.24 **evidence** report, and an **OpenVEX** 0.2.0 document for VEX pipelines.
- **Fast on big repos.** Optional worker-thread parallelism (`--parallel`) and
  git-aware incremental scanning (`--changed`).

## Language coverage

Inline crypto detection currently covers **JavaScript/TypeScript**, **Python**,
**Go**, **Java/Kotlin/Scala** (JCA + BouncyCastle), **C#/.NET**, **Rust**, **Ruby**,
**PHP** (openssl / phpseclib3 / libsodium), **Elixir** (`:crypto` / X509 / JOSE),
and **C/C++** (OpenSSL, Mbed TLS, wolfSSL) source. PEM key material, SSH keys, TLS/certificate
config, and dependency manifests for **six ecosystems** — npm (plus
`yarn.lock` / `pnpm-lock.yaml`), PyPI, Cargo, Go modules, Maven, and RubyGems —
are detected in **any** file regardless of language.

qScan is **honest about coverage**: if a scan walks files but finds none in a
supported source language, it says so and will **not** present a bare `100/100`
as a clean bill of health — the crypto may simply live in a language it can't
read yet. Always check the `analyzed` count in the report before relying on the
score.

## Install

```bash
npm install -g @quantakrypto/qscan
# or run without installing
npx @quantakrypto/qscan .
```

Requires Node ≥ 20.

## Usage

```bash
qscan [path] [options]
```

`path` defaults to the current directory (`.`).

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--format <human\|json\|sarif\|cbom\|evidence\|vex>` | Output format. | `human` |
| `--cbom` | Alias for `--format cbom` (CycloneDX 1.6 CBOM). | — |
| `-o, --output <file>` | Write the report to a file instead of stdout. | stdout |
| `--severity-threshold <level>` | Exit 1 if any finding is at/above this level. One of `critical`, `high`, `medium`, `low`, `info`. | `high` |
| `--no-source` | Skip scanning source files for inline crypto. | scan on |
| `--no-deps` | Skip scanning dependency manifests. | scan on |
| `--no-config` | Skip scanning config files (TLS/certificates). Toggles config *detectors* — not the config file below. | scan on |
| `--config <path>` | Use this `quantakrypto.config.json` instead of auto-discovering one at the scan root. | auto |
| `--no-config-file` | Disable `quantakrypto.config.json` auto-discovery. | discovery on |
| `--ignore <pattern>` | Exclude paths matching `<pattern>`. Repeatable. | — |
| `--include <pattern>` | Restrict the scan to paths matching `<pattern>`. Repeatable. | all files |
| `--max-file-size <bytes>` | Skip files larger than `<bytes>`. | 2 MiB |
| `--no-default-ignores` | Don't skip `node_modules`/`.git`/`dist` by default. | ignores on |
| `--scan-minified` | Scan minified/generated/bundled files too. | skipped |
| `--changed` | Incremental: scan only files git reports as changed. | off |
| `--since <git-ref>` | With `--changed`, diff against `<git-ref>` (implies `--changed`). | working tree |
| `--parallel` | Scan using a worker-thread pool when the workload is large enough. | off |
| `--concurrency <n>` | Worker count for `--parallel` (implies `--parallel`). `0`/`1` forces serial. | CPU count |
| `--triage` | BYOK LLM pass that re-ranks findings by real exposure and explains them. Never suppresses; never changes the exit code. Needs an API key. | off |
| `--triage-floor <level>` | With `--triage`, only triage findings at/above this level. | `medium` |
| `--context <level>` | How much source is shared with the LLM: `metadata`, `snippet`, `function`, `file` (secrets always redacted). | `snippet` |
| `--dry-run` | With `--triage`, print the exact payload that would be sent and exit without contacting the provider. | off |
| `--llm-provider <name>` | BYOK provider: `anthropic` or `openai-compatible`. | `anthropic` |
| `--llm-model <id>` | Model id for the BYOK provider. | provider default |
| `--baseline <file>` | Suppress findings whose fingerprint is in the baseline file. | — |
| `--write-baseline <file>` | Write current findings as a baseline, then exit 0. | — |
| `--quiet` | Suppress the human summary banner. | off |
| `-v, --version` | Print version and exit. | — |
| `-h, --help` | Print help and exit. | — |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at/above the threshold — or a baseline was written. |
| `1` | One or more findings at/above the severity threshold. |
| `2` | Usage error or I/O failure. |

### Config file (`quantakrypto.config.json`)

qScan auto-discovers a `quantakrypto.config.json` at the scan root and applies it
under a strict precedence: **CLI flags > config file > built-in defaults**
(per-key). It encodes `include` / `exclude` / `maxFileSize` / `noDefaultIgnores`
/ `scanMinified`, the detector-family toggles, `severityThreshold`, and a
`baseline` path so CI and local runs share one policy. Point at a file elsewhere
with `--config <path>`, or disable discovery with `--no-config-file`. See
[docs/CONFIG.md](../../docs/CONFIG.md) for the full schema.

## Example output

```
qScan — quantum-vulnerable cryptography report
root: ./examples/vulnerable-app  •  files scanned: 2  •  qscan v0.4.2

3 findings  (2 high, 1 medium)
2 exposed to harvest-now-decrypt-later (HNDL).
Readiness score: 70/100

Top findings
  high     rsa-keygen      src/crypto.js:5
           RSA is not quantum-safe.
           → Use ML-KEM-768 (hybrid X25519MLKEM768).
  high     dep-vulnerable  package.json:7
           Dependency "node-forge" provides classical asymmetric crypto.
  medium   ecdh-usage      src/crypto.js:13
           ECDH is not quantum-safe.
           → Use a hybrid KEM (X25519MLKEM768).

Next step: migrate src/crypto.js — Use ML-KEM-768 (hybrid X25519MLKEM768).
```

Color is emitted only when writing the human format to an interactive terminal
(and is suppressed by the `NO_COLOR` environment variable). Reports written to a
file or piped are always plain text.

## Baselines

A baseline records the **fingerprints** of findings you have already triaged.
qScan uses the **canonical baseline** shared across the whole monorepo
(`@quantakrypto/core`, the GitHub Action, and this CLI): a single on-disk format and a
single fingerprint algorithm, so a baseline written by one tool is understood by
the others.

A fingerprint is a full SHA-256 of `ruleId|file|normalizedSnippet`. It is
deliberately **line-insensitive** — unrelated edits that shift line numbers no
longer invalidate it — and the snippet's whitespace is normalized so
reformatting doesn't either. It ignores volatile fields like severity wording or
timestamps.

```bash
# 1. Accept the current state of the world.
qscan . --write-baseline qscan-baseline.json

# 2. From now on, fail only on findings that are NOT in the baseline.
qscan . --baseline qscan-baseline.json
```

The baseline file is plain JSON:

```json
{
  "version": 1,
  "fingerprints": [
    "0f1e2d3c4b5a...full-sha256...",
    "a1b2c3d4e5f6...full-sha256..."
  ]
}
```

## Incremental scans

In CI you usually only care about what a change introduced. `--changed` restricts
the scan to the files git reports as modified, which is a large win on big repos:

```bash
# Files modified in the working tree (staged, unstaged, and untracked).
qscan . --changed

# Everything that changed since a base ref (e.g. a PR base).
qscan . --changed --since origin/main
```

Outside a git work tree the changed-file list is empty (nothing is scanned),
rather than an error.

## Parallel scans

For large trees, route the scan through a worker-thread pool. qScan automatically
stays serial for small inputs, so `--parallel` is safe to leave on:

```bash
qscan . --parallel               # auto worker count (CPU cores)
qscan . --concurrency 4          # pin the worker count (implies --parallel)
```

## CBOM (CycloneDX)

Emit a CycloneDX 1.6 **cryptographic bill of materials** — one
`cryptographic-asset` component per distinct (assetType, algorithm, discriminator),
with file:line occurrence evidence — for compliance and supply-chain tooling.
Findings are classified into their proper CycloneDX `assetType`: `algorithm`
(crypto usage), `certificate` (X.509), `related-crypto-material` (private/public
key material), and `protocol` (TLS):

```bash
qscan . --cbom -o qscan-cbom.json
# equivalently:
qscan . --format cbom -o qscan-cbom.json
```

The output is deterministic (sorted components and occurrences, stable serial
number), so re-running on an unchanged tree produces byte-identical CBOMs.

## VEX (OpenVEX)

Emit an **OpenVEX 0.2.0** document so the quantum-readiness posture flows into the
same supply-chain pipeline that already ingests CVE-based VEX:

```bash
qscan . --format vex -o qscan.openvex.json
```

One statement per rule (a synthetic `QK-<ruleId>` vulnerability), listing every
affected `file:line` product with `status: "affected"` and the rule's remediation
as the `action_statement`. PQC findings have no CVE, so qScan mints a stable
per-rule identifier rather than claiming one. qScan never reports `not_affected`
— only an operator can attest a mitigation — so downgrading a statement is left to
you to post-process. When `--triage` is also set, each verdict (exposure score /
priority / rationale) is carried in the statement's `status_notes`. Output is
deterministic (statements sorted by vulnerability, products deduped and sorted;
the `@id` derives from the finding set).

## Triage (opt-in, BYOK)

`--triage` adds an optional LLM pass that **re-ranks and explains** findings by
their real-world exposure. It is purely additive: it **never suppresses** a
finding and **never changes the exit code** (that is still computed from severity
alone), so it cannot mask a problem or gate CI. It is **bring-your-own-key** —
provide an API key via `QK_LLM_API_KEY` (or `ANTHROPIC_API_KEY` /
`OPENAI_API_KEY`); without a key, triage is skipped and the deterministic scan is
unaffected.

```bash
# Re-rank + annotate findings at/above the floor (default floor: medium).
qscan . --triage

# Only triage the most serious findings, with a specific provider/model.
qscan . --triage --triage-floor high --llm-provider anthropic --llm-model claude-sonnet-5

# See exactly what would be sent — contacts nothing, needs no key.
qscan . --triage --dry-run
```

`--context` controls how much source leaves the machine (`metadata` | `snippet` |
`function` | `file`, default `snippet`); secrets are always redacted. `--dry-run`
prints the exact, redacted payload and exits **without contacting the provider**,
so you can review what triage would send before enabling it.

## Remediation (`qremediate`)

This package also ships a `qremediate` bin that **applies** fixes, not just
reports them. It scans, then for each finding a deterministic **codemod** proposes
a patch; every patch must clear a **verify gate** (the crypto finding is gone and
no new crypto finding is introduced) and a patch policy (only files that have
findings, plus dependency manifests) before it is offered.

```bash
qremediate .                 # print a unified diff of every verified fix (default; writes nothing)
qremediate . --mode apply    # write the verified fixes into the working tree
qremediate . --mode pr       # commit them to a new branch and open a DRAFT PR (never merges)
```

Deterministic codemod fixes are safe to apply directly. With `--llm` (BYOK, same
keys as `--triage`), an LLM can also propose fixes codemods can't:

```bash
qremediate . --llm --mode diff   # review LLM-proposed fixes as a diff first
qremediate . --llm --mode pr     # or stage them as a draft PR
```

**Review LLM-proposed fixes before trusting them.** The verify gate only confirms
the classical crypto finding was removed (a crypto-count check) — it is **not** a
full semantic safety review, so read every LLM-proposed change as a diff. Prefer
`--mode diff` or `--mode pr` for `--llm` fixes; `--mode apply` writes straight to
the working tree. Draft PRs are built in an isolated git worktree (your checkout is
never touched) and are **never** auto-merged.

## CI

Fail the build on any high-or-worse finding, while tolerating an accepted
baseline:

```yaml
# .github/workflows/qscan.yml
name: qscan
on: [push, pull_request]

jobs:
  quantum-readiness:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Scan for quantum-vulnerable crypto
        run: npx @quantakrypto/qscan . --severity-threshold high --baseline qscan-baseline.json

      # Optional: upload SARIF to GitHub code scanning.
      - name: Generate SARIF
        if: always()
        run: npx @quantakrypto/qscan . --format sarif -o qscan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: qscan.sarif
```

## Programmatic API

The CLI is a thin shell over `runQscan`, which `@quantakrypto/action` reuses:

```ts
import { runQscan, EXIT } from "@quantakrypto/qscan";

const { result, exitCode, suppressed } = await runQscan({
  path: "src",
  format: "json",
  severityThreshold: "high",
  baseline: "qscan-baseline.json",
});

console.log(`${result.findings.length} findings, exit ${exitCode}`);
if (exitCode === EXIT.FINDINGS) process.exitCode = 1;
```

`runQscan` never touches `process` or stdout — it returns the rendered `report`
string and a suggested `exitCode`, leaving I/O to the caller. The package also
re-exports the argument parser (`parseArgs`, `defaultOptions`), severity helpers
(`severityRank`, `meetsThreshold`), and the **canonical** baseline utilities from
`@quantakrypto/core` (`fingerprintFinding`, `baselineFromFindings`, `applyBaseline`,
`loadBaseline`, `saveBaseline`) plus their legacy aliases (`fingerprint`,
`buildBaseline`, `readBaseline`, `writeBaseline`) for source compatibility.

## Examples

See [`examples/`](./examples) for a sample vulnerable project and the commands
to scan it.

## License

Apache-2.0

## Support & training

Questions, commercial support, or post-quantum readiness training for your team —
visit **[quantakrypto.com](https://quantakrypto.com)** or email
**[hello@quantakrypto.com](mailto:hello@quantakrypto.com)**.
