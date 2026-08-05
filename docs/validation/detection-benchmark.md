# Detection benchmark — accuracy of the `@quantakrypto/core` crypto detectors

This document records how we **measure** the accuracy of qScan's crypto
detectors against a known ground truth, the **current measured numbers**
(precision / recall / F1, overall and per category), and — honestly — the
**false positives and false negatives** the scanner currently produces. It is a
companion to the cryptography audit, which reviews detector design; this doc
quantifies detector behaviour and locks it as a regression guard.

The benchmark is executed by
[`packages/core/test/benchmark.test.ts`](../../packages/core/test/benchmark.test.ts)
as part of the normal `@quantakrypto/core` test suite (`node:test`, zero runtime
dependencies). It prints the scorecard on every run; re-run it after any detector
change and update the measured numbers below (see [Updating](#updating)) so this
page stays in step with the test.

## What is measured

The detectors are lexical (regex over source/text plus a JSON manifest parser).
We score them at the **finding level**: a labeled corpus file declares exactly
which findings the scanner should emit, each described by its stable `ruleId`,
the classical algorithm family, and the `hndl` (harvest-now-decrypt-later) flag.

- **True positive (TP)** — an expected finding that the scanner produced.
- **False positive (FP)** — a finding the scanner produced that no label
  expected. On negative bait files, _every_ finding is an FP.
- **False negative (FN)** — an expected finding the scanner failed to produce.

From those:

```
precision = TP / (TP + FP)      recall = TP / (TP + FN)
F1        = 2·precision·recall / (precision + recall)
```

Matching is greedy multiset matching **per file**: each expected
`(ruleId, algorithm, hndl)` tuple is consumed at most once, so duplicate or
missing findings are scored correctly.

## Corpus

The corpus lives under
[`packages/core/test/benchmark/corpus/`](../../packages/core/test/benchmark/corpus/)
and is split into `positive/` (crypto that **must** be detected) and `negative/`
(false-positive **bait** that must produce **zero** findings). The ground-truth
labels are in
[`packages/core/test/benchmark/labels.json`](../../packages/core/test/benchmark/labels.json).

### Positives (61 files, 159 expected findings)

The positive corpus spans every detector surface and language toggle: JS/TS,
Python, Go, Java/Kotlin/Scala, C#, Rust, Ruby, Swift, C/C++, plus PEM/SSH key
material, dependency manifests, JWT/JOSE, TLS config, DNSSEC, and IaC
(Ansible / Bicep / Pulumi / Terraform). Each positive category and its
expected-finding count is listed in the per-category scorecard under
[Current measured results](#current-measured-results); the exact
`(ruleId, algorithm, hndl)` labels per file are in `labels.json`.

### Negatives (22 files, 0 expected findings)

The negative set is false-positive bait that must produce **zero** findings —
symmetric crypto (AES-GCM, ChaCha20-Poly1305), KDFs (bcrypt / scrypt / argon2),
hashes/MACs (SHA-256, HMAC, `@noble/hashes`), base64 blobs with no PEM header,
crypto terms appearing only in comments and identifiers, and manifests that
depend only on safe packages. Any finding on a negative file is a false positive
and fails the build.

## Current measured results

Measured by `packages/core/test/benchmark.test.ts` (Node 20,
`@quantakrypto/core` v0.9.0). The test prints this exact scorecard on each run.

**Overall: precision 1.000 · recall 1.000 · F1 1.000** (TP = 159, FP = 0, FN = 0).

| Category          | TP  | FP  | FN  | Precision | Recall | F1    |
| ----------------- | --- | --- | --- | --------- | ------ | ----- |
| c                 | 18  | 0   | 0   | 1.000     | 1.000  | 1.000 |
| csharp            | 6   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dependency        | 6   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dh                | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dnssec            | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dsa               | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ec-keygen         | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ecdh              | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ecdsa             | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| eddsa             | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| go                | 13  | 0   | 0   | 1.000     | 1.000  | 1.000 |
| iac-ansible       | 3   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| iac-bicep         | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| iac-pulumi        | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| iac-terraform     | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| java              | 23  | 0   | 0   | 1.000     | 1.000  | 1.000 |
| jwt-jose          | 4   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| library           | 6   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| negative          | 0   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| pem               | 5   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| pem-embedded-key  | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| python            | 17  | 0   | 0   | 1.000     | 1.000  | 1.000 |
| rsa               | 3   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ruby              | 9   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| rust              | 14  | 0   | 0   | 1.000     | 1.000  | 1.000 |
| signature         | 9   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| signature-oneshot | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ssh               | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| swift             | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| tls               | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| x25519            | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| **OVERALL**       | 159 | 0   | 0   | **1.000** | **1.000** | **1.000** |

### Regression thresholds (the guard)

The test asserts thresholds set **just below** the measured values, so a real
regression fails the build but the numbers above are not brittle:

- overall precision ≥ **0.98** (measured 1.000)
- overall recall ≥ **0.99** (measured 1.000)
- overall F1 ≥ **0.98** (measured 1.000)
- at least **30** true positives (measured 159)
- **false negatives must be exactly 0** (`recall is perfect` test) — any missed
  detection is a hard failure.
- the negative set is **strict**: **zero** false positives are allowed. Any new
  false positive fails the build.

## Known false positives / false negatives

We surface these on purpose rather than tuning the corpus to hide them.

### False positives (0)

None in the current corpus (precision 1.000). An earlier accepted FP — an API
name such as `createECDH (` appearing inside a comment — has been suppressed, so
the negative set now produces zero findings. This is a property of _this_ corpus,
not a guarantee that no prose can ever misfire (see Known gaps).

### False negatives (0)

None in the current corpus: every expected finding is produced (recall 1.000).
This is a property of _this_ corpus, not a proof of completeness — see the
caveats below.

### Known gaps (detector behaviour observed while measuring)

These are detector limitations, **documented, not necessarily counted as
benchmark failures**, because the corpus is built around the detectors'
documented lexical contract.

1. **Comment/string awareness is limited.** Matching runs over raw text, so an
   API name followed by `(` inside prose can in principle be flagged. The
   specific comment-FP case in the corpus is suppressed, but comment-aware
   scanning (or requiring a receiver like `crypto.` before the call) would harden
   the whole whitespace-tolerant call-pattern family.
2. **EdDSA one-shot signing via `crypto.sign(null, …)` is not detected.** The
   one-shot rule requires a **quoted** algorithm as the first argument. Idiomatic
   Ed25519 signing passes `null` as the algorithm (`crypto.sign(null, msg, key)`)
   and is therefore missed. The corpus uses `crypto.sign("sha256", …)` for the
   one-shot positive precisely because the `null` form is a known miss.
3. **WebCrypto algorithm proximity window.** `webcrypto-classical` only fires
   when the algorithm token (`ECDH`, `ECDSA`, `RSA-OAEP`, …) sits within ~400
   characters of a `subtle.*` call. Algorithm constants defined far from their
   use site would be missed.

## Caveats

- The corpus is **curated** to cover each detector on unambiguous cases. High
  precision/recall here means "the detectors do what they claim on canonical
  inputs and don't fire on the obvious traps" — it is **not** a statement about
  real-world recall over messy code.
- Findings are matched on `(ruleId, algorithm, hndl)`, not on line/column, so the
  benchmark validates _what_ is detected, not _where_.

## Reproducing

```bash
# from the repo root
npm test --workspace @quantakrypto/core            # runs the full suite incl. the benchmark
# or just the benchmark file:
node --import tsx --test packages/core/test/benchmark.test.ts
```

The scorecard table is printed as TAP diagnostics (`# …` lines) so the measured
numbers are visible in CI logs.

## Updating

When you add/adjust a detector:

1. Add corpus file(s) under `positive/` or `negative/`.
2. Add the matching entry to `labels.json` (use `[]` for negatives).
3. Run the benchmark, read the printed scorecard, and update the **measured**
   numbers and the **Known false positives / false negatives** section here.
4. Only then adjust the assertion thresholds, keeping them _just below_ the new
   measured values.
