# quantakrypto-tools — objectives & scope

Why this toolchain exists, what each library is for, the decisions that shape it,
and the lines we deliberately do not cross. This is the durable "what and why";
the standards it targets are in [COMPLIANCE.md](COMPLIANCE.md) and
[standards/pqc-standards.md](standards/pqc-standards.md), and each load-bearing
decision has an [ADR](adr/README.md).

## Mission

Help an organization **find, quantify, migrate, and verify** its exposure to
quantum-vulnerable cryptography — before a cryptographically-relevant quantum
computer (CRQC) exists — and do it as **honest, standards-anchored, zero-runtime-
dependency** tooling that is safe to run in CI, in an editor, and (for the offline
pieces) safe to host.

Two threats drive everything:

- **Harvest now, decrypt later (HNDL).** Traffic and data protected by classical
  key exchange / public-key encryption (ECDH, DH, RSA-OAEP) can be recorded today
  and decrypted once a CRQC exists. Findings carry an `hndl: true` flag.
- **Forgery.** Classical signatures (RSA, ECDSA, EdDSA, DSA) become forgeable by a
  quantum attacker. These are `hndl: false` but still high-value exposure.

The scanner points every finding at a NIST PQC replacement (ML-KEM / FIPS 203,
ML-DSA / FIPS 204, SLH-DSA / FIPS 205, hybrid `X25519MLKEM768`).

## What we want to achieve

1. **Find** every place classical asymmetric crypto lives — application source
   (14 language packs), infrastructure/config, dependency manifests, and live
   TLS/SSH endpoints.
2. **Quantify** readiness — a readiness score, a crypto inventory, an HNDL count,
   and a machine-readable CBOM / SARIF / OpenVEX / ISO A.8.24 evidence report.
3. **Gate** CI on *new* exposure (severity threshold + baselines), so a codebase
   ratchets toward PQC instead of regressing.
4. **Migrate** — deterministic codemods first, then optional BYOK-LLM triage and
   fix proposals, always "model proposes, engine disposes."
5. **Verify** the replacement is correct — conformance-test any ML-KEM / ML-DSA /
   SLH-DSA implementation against FIPS 203/204/205.
6. **Evidence** — produce audit-ready compliance artifacts (A.8.24 readiness
   report with a deterministic, externally-signable content hash; CBOM; VEX).

## The libraries and what each is for

| Package | Objective |
|---|---|
| **`@quantakrypto/core`** | The shared engine and single contract: the detector registry (source + config + dependency), the readiness score / inventory, the reporters (human, JSON, SARIF 2.1.0, CycloneDX CBOM, ISO A.8.24 evidence, OpenVEX), the standards source-of-truth, and the offline agent-plane primitives (context redactor, `verify_fix` gate, deterministic codemods, patch policy). Every other package builds on it — see [ADR-0002](adr/0002-shared-core-contract.md). |
| **`@quantakrypto/qscan`** | The CLI: scan a repo, print a readiness score and the concrete next step, and drive the CI exit code. Baselines, incremental/parallel scans, and the opt-in `--triage` / `qremediate` migration path. |
| **`@quantakrypto/mcp`** | An **offline, key-free** Model Context Protocol server that gives AI coding agents the readiness tools (scan, inventory, explain, suggest-hybrid, CBOM). Safe to host because it never phones home and never holds a key — see [ADR-0005](adr/0005-byok-agent-two-planes.md). |
| **`@quantakrypto/sieve`** | A conformance battery that tests *other people's* ML-KEM / ML-DSA / SLH-DSA implementations over a JSON stdin/stdout protocol. It implements no cryptography and ships no KAT vectors — see [ADR-0004](adr/0004-sieve-no-fabricated-vectors.md). |
| **`@quantakrypto/action`** | The GitHub Action: run qScan in CI, upload SARIF, annotate the diff, and fail the build only on **new** quantum-vulnerable crypto. |
| **`@quantakrypto/agent`** | The **only** networked, key-holding plane: a zero-dependency BYOK LLM client (native `fetch`; Anthropic + OpenAI-compatible adapters) that powers `qscan --triage` and `qremediate --llm`. Deliberately isolated from the offline engine — see [ADR-0005](adr/0005-byok-agent-two-planes.md). |
| **`@quantakrypto/qprobe`** | Actively probes **live TLS/SSH endpoints you own** for PQC-hybrid key exchange and classical certificate posture — the runtime complement to the static scan. Gated behind an ownership attestation; it reports, never modifies. |

`core`, `qscan`, `mcp`, `sieve`, `action`, and the offline half of the agent line
share one contract; `agent` and `qprobe` are the only network-touching pieces.

## Load-bearing decisions (the "why")

Recorded as immutable [ADRs](adr/README.md); the short version:

- **Zero runtime dependencies** ([ADR-0001](adr/0001-zero-runtime-dependencies.md)) —
  Node built-ins only, so the tools add no supply-chain surface to the repos that
  install them. Enforced by CI (`check-zero-deps.mjs`).
- **`core` is the single shared contract** ([ADR-0002](adr/0002-shared-core-contract.md)) —
  one place for the finding shape, detectors, score, and reporters, with a frozen,
  drift-gated public API surface (`api:check`).
- **Monorepo + `tsc -b` project references** ([ADR-0003](adr/0003-monorepo-and-build.md)).
- **Sieve ships no KAT vectors and never fabricates expected values**
  ([ADR-0004](adr/0004-sieve-no-fabricated-vectors.md)) — exact-value conformance
  requires the operator to supply official NIST ACVP vectors; without them the
  `kat` category is skipped, never faked.
- **Two-plane agent architecture** ([ADR-0005](adr/0005-byok-agent-two-planes.md)) —
  the LLM plane is fenced off from the deterministic engine, CI-enforced by
  `check-offline-boundary.mjs`; the model proposes, the engine disposes.
- **Human-facing output is English-only** ([ADR-0006](adr/0006-report-output-english-only.md)) —
  the audience reads FIPS / CNSA / IR-8547 terminology that is itself English.
- **Detection scope is PQC + quantum-adjacent.** The tool flags classical
  *asymmetric* crypto (Shor) and the quantum-adjacent surfaces on the same
  migration clock — SHA-1/MD5 **in signatures and certificates** (NIST retires
  SHA-1 by 2030, the PQC window). It deliberately does **not** flag password
  hashing, symmetric-mode misuse (ECB/DES/RC4), or act as a general secret scanner
  — those are classical hygiene, not quantum exposure, and mixing them would dilute
  the tool's sharpest property: *every finding is quantum exposure*.
- **HNDL-safe classification.** When a key's use is ambiguous (e.g. a freshly
  generated EC key that could feed ECDSA *or* ECDH), it is classified as the
  harvestable case (`key-exchange` / `hndl: true`) so exposure is never
  under-reported. A registry invariant test enforces this across every language pack.

## Non-goals (deliberate scope boundaries)

- It does **not** implement post-quantum cryptography. It scans for, gates, and
  helps migrate *to* PQC; a real library (e.g. liboqs) supplies the primitives.
- It does **not** validate or certify a FIPS 140-3 / CMVP cryptographic module.
  Sieve is a pre-screen / conformance battery, not a CAVP/CMVP harness.
- It is **not** a general-purpose secret scanner (gitleaks/TruffleHog own that) nor
  a classical-hygiene linter (Semgrep/SonarQube own that).
- Detection is **lexical** — it finds *candidate* usage to triage, not proofs of
  cryptographic correctness or runtime behaviour.

## Keeping it current (maintenance cadence)

The posture is only as good as its currency, so these are re-checked on a cadence,
each with a CI or scripted gate:

- **Standards drift** — a dated, cited source of truth (`PQC_STANDARDS`) with a CI
  drift test and an advisory quarterly `standards:check`. See
  [standards/pqc-standards.md](standards/pqc-standards.md).
- **Detection quality** — a labelled precision/recall benchmark, gated **per
  language** so no single pack can silently regress behind a healthy aggregate.
- **Agent-line safety** — prompt-injection, data-egress, and patch-safety are
  re-reviewed whenever the agent/remediation code changes; the offline boundary is
  CI-enforced.
- **Reproducible builds** — every published tarball is re-creatable byte-for-byte
  from source (`repro:check`).
- **Supply-chain posture** — zero-dep invariant, SHA-pinned Actions, and a weekly
  cadence audit. See [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).
