# Remediation benchmark — correctness of the deterministic codemod layer

The [detection benchmark](./detection-benchmark.md) measures whether qScan
**finds** classical cryptography. This document records how we measure whether
the deterministic codemod layer **fixes** it correctly, the current numbers, and
the honesty property that keeps the layer from ever emitting a wrong mechanical
fix.

The benchmark is executed by
[`packages/core/test/remediation-benchmark.test.ts`](../../packages/core/test/remediation-benchmark.test.ts)
as part of the normal `@quantakrypto/core` test suite (`node:test`, zero runtime
dependencies), so this page and the test cannot silently drift apart.

## What is measured

For a hand-labeled corpus of `(vulnerable file → target finding)` cases, the
harness produces a patch with the deterministic codemod that applies and scores
four properties of it:

| Property | Meaning |
|----------|---------|
| **applied** | a codemod exists for the finding and returns a non-null patch |
| **cleared** | re-running the detectors on the patched code no longer reports the target rule — the classical crypto is actually gone |
| **no-regression** | the patch introduces no finding it didn't start with (it fixed the target without adding a fresh problem) |
| **idempotent** | re-applying the codemod to already-fixed code is a no-op |

"cleared" reuses the exact same detector pass (`verifyFix`) that the MCP
`verify_fix` tool and the remediation pipeline use, so the benchmark, the tool,
and the pipeline can never disagree on what "the finding is gone" means.

## Honesty: the layer must decline when there is no safe mechanical fix

A second corpus contains findings with **no drop-in mechanical replacement** — an
RSA keygen, an ECDH handshake. For these the deterministic layer must **decline**
(offer no codemod) rather than emit a wrong patch; they are routed to triage and
the LLM remediation layer instead. A codemod that started "fixing" an RSA keygen
would be a correctness *regression*, not a feature, and the benchmark fails if the
layer stops declining.

## Current numbers

```
REMEDIATION  applied 4/4 (1.000)  cleared 4/4 (1.000)  no-regression 1.000  idempotent 1.000  declined 2/2
```

The corpus covers the two rules the `config-toggle` codemod handles
(`tls-legacy-version`, `tls-reject-unauthorized`), including a file with both
issues fixed in a single patch, plus the two honest-decline cases.

## Why this is gated at 1.000 (not floored)

These codemods are **deterministic** — mechanical, unambiguous config toggles
with a single correct replacement. Unlike detection recall (which is floored
because lexical detection of adversarial idioms has a real ceiling), a
deterministic fix that does not reliably clear its finding has no reason to exist
in this layer. So correctness is gated at a perfect score: a codemod that stops
clearing its finding, starts over-reaching, or loses idempotence fails the build.

## Extending it

This is the harness future codemods plug into: add a `(file, ruleId)` case to the
fix corpus and the four properties are enforced automatically. Non-deterministic,
LLM-produced fixes would be scored on the same four properties but **reported**
rather than gated — you cannot gate a model at 1.000 — giving a measured
correctness rate for the BYOK remediation layer without making CI flaky.
