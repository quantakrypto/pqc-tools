# Detection benchmark — accuracy of the `@qproof/core` crypto detectors

This document records how we **measure** the accuracy of qScan's crypto
detectors against a known ground truth, the **current measured numbers**
(precision / recall / F1, overall and per category), and — honestly — the
**false positives and false negatives** the scanner currently produces. It is a
companion to the [cryptography audit](../audits/cryptography.md), which reviews
detector design; this doc quantifies detector behaviour and locks it as a
regression guard.

The benchmark is executed by
[`packages/core/test/benchmark.test.ts`](../../packages/core/test/benchmark.test.ts)
as part of the normal `@qproof/core` test suite (`node:test`, zero runtime
dependencies). The numbers below are reproduced on every run, so this page and
the test cannot silently drift apart.

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
Files span `.ts`, `.js`, `.mjs`, `.pem`, `package.json`, and an
`authorized_keys` file to exercise every detector surface and language toggle.

### Positives (25 files, 31 expected findings)

| Category            | What it exercises                                                              | Rule(s)                                       |
| ------------------- | ----------------------------------------------------------------------------- | --------------------------------------------- |
| `rsa`               | RSA keygen + `createSign`; RSA `publicEncrypt`                                 | `node-crypto-keygen`, `node-crypto-sign`, `node-crypto-rsa-encrypt` |
| `signature-oneshot` | one-shot `crypto.sign` / `crypto.verify("sha256", …)`                          | `node-crypto-sign-oneshot`                    |
| `ecdh`              | `createECDH`; WebCrypto ECDH `deriveKey`                                       | `node-crypto-ecdh`, `webcrypto-classical`     |
| `ec-keygen`         | `generateKeyPair("ec")` (classified as key-exchange-capable / HNDL)           | `node-crypto-keygen`                          |
| `ecdsa`             | WebCrypto ECDSA `sign`                                                         | `webcrypto-classical`                         |
| `dh`                | `createDiffieHellman`; `getDiffieHellman("modp14")`                            | `node-crypto-dh`, `node-crypto-dh-modp`       |
| `dsa`               | `generateKeyPair("dsa")`                                                       | `node-crypto-keygen`                          |
| `eddsa`             | `generateKeyPair("ed25519")`                                                   | `node-crypto-keygen`                          |
| `x25519`            | `generateKeyPair("x25519")`                                                    | `node-crypto-keygen`                          |
| `jwt-jose`          | JWT `RS256` / `ES256`; JOSE `ECDH-ES+A256KW`                                   | `jwt-classical-alg`, `jose-ecdh-es`           |
| `library`           | node-forge, elliptic, `@noble/secp256k1`, jsrsasign, node-rsa                 | `forge-rsa-keygen`, `elliptic-ec`, `secp256k1-usage`, `jsrsasign-keygen`, `jsrsasign-sign`, `node-rsa` |
| `dependency`        | `package.json` depending on node-forge + jsonwebtoken                         | `dep-vulnerable`                              |
| `pem`               | PEM RSA + EC private keys                                                      | `pem-rsa-private-key`, `pem-ec-private-key`   |
| `ssh`               | `authorized_keys` with `ssh-rsa` + `ssh-ed25519`                              | `ssh-public-key`                              |
| `tls`               | legacy TLS version pin + `rejectUnauthorized: false`                          | `tls-legacy-version`, `tls-reject-unauthorized` |

### Negatives / false-positive baits (8 files, 0 expected findings)

| File                          | Why it is bait                                                                |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `password-hashing.ts`         | bcrypt / scrypt / argon2 — symmetric KDFs, not asymmetric crypto              |
| `symmetric-aead.ts`           | AES-256-GCM + ChaCha20-Poly1305 — symmetric, not Shor-broken                  |
| `hashing-hmac.js`             | SHA-256 + HMAC — hashes/MACs, not asymmetric                                   |
| `noble-hashes.mjs`            | `@noble/hashes` — pure hashing (distinct from the flagged `@noble/*` curves)  |
| `random-base64.txt`           | base64 blobs, no PEM header, no crypto call                                   |
| `comments-and-names.ts`       | "RSA"/"ECDSA"/"DH" only in comments and identifiers (`rsaToken`, `ecdsaLabel`) |
| `safe-package.json`           | depends only on express / lodash / `@noble/hashes` / zod / typescript         |
| `crypto-words-in-comment.ts`  | **known false positive** — a comment containing `createECDH (` (see below)    |

## Current measured results

Measured by `packages/core/test/benchmark.test.ts` (Node 20, `@qproof/core`
v0.1.0). The test prints this exact scorecard on each run.

**Overall: precision 0.969 · recall 1.000 · F1 0.984** (TP = 31, FP = 1, FN = 0).

| Category            | TP  | FP  | FN  | Precision | Recall | F1    |
| ------------------- | --- | --- | --- | --------- | ------ | ----- |
| rsa                 | 3   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| signature-oneshot   | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ecdh                | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ec-keygen           | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ecdsa               | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dh                  | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dsa                 | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| eddsa               | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| x25519              | 1   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| jwt-jose            | 3   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| library             | 6   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| dependency          | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| pem                 | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| ssh                 | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| tls                 | 2   | 0   | 0   | 1.000     | 1.000  | 1.000 |
| negative            | 0   | 1   | 0   | 0.000\*   | 1.000  | 0.000\* |
| **OVERALL**         | 31  | 1   | 0   | **0.969** | **1.000** | **0.984** |

\* The `negative` row has no true positives by construction, so its
per-category precision/F1 are 0 whenever a single FP appears. The meaningful
signal for the negative set is the **FP count** (1), not its F1. Overall
precision (0.969) already reflects that one FP.

### Regression thresholds (the guard)

The test asserts thresholds set **just below** the measured values, so a real
regression fails the build but normal variance does not:

- overall precision ≥ **0.95** (measured 0.969)
- overall recall ≥ **0.99** (measured 1.000)
- overall F1 ≥ **0.97** (measured 0.984)
- **false negatives must be exactly 0** (`recall is perfect` test) — any missed
  detection is a hard failure.
- the negative set is **strict**: the set of false positives must equal exactly
  the one documented known FP. Any _new_ false positive fails the build.

## Known false positives / false negatives

We surface these on purpose rather than tuning the corpus to hide them.

### False positives (1)

- **`createECDH (` (or any detected API name) inside a comment** — file
  `negative/crypto-words-in-comment.ts`, rule `node-crypto-ecdh`,
  `algorithm: ECDH`, `hndl: true`. The Node-`crypto` regexes allow optional
  whitespace before the call's `(` (e.g. `/createECDH\s*\(/`). A comment such as
  `// … createECDH (deprecated since 2019)` therefore matches even though there
  is no code. This is a general property of the whitespace-tolerant call
  patterns (`createDiffieHellman`, `createSign`/`createVerify`, `publicEncrypt`,
  …): the detectors do not strip comments or strings before matching, so prose
  that mentions an API immediately followed by a space and `(` will misfire.
  - **Impact:** low. It needs the exact `name (` shape in prose; the far more
    common bare mentions (no following `(`) and identifier/variable uses do
    **not** misfire (verified by `comments-and-names.ts`, which is clean).
  - **Status:** measured and asserted as the single accepted FP. Fixing it
    requires comment/string stripping or anchoring the call patterns, which is a
    detector-source change tracked separately — see _Known gaps_.

### False negatives (0)

None in the current corpus: every expected finding is produced (recall 1.000).
This is a property of _this_ corpus, not a proof of completeness — see the
caveats below.

### Known gaps (detector behaviour observed while measuring)

These are detector limitations the benchmark exposed. They are **documented, not
fixed here** — editing detector source is a separate task. They are not (yet)
counted as benchmark failures because the corpus is built around the detectors'
documented lexical contract.

1. **No comment/string stripping (root cause of the one FP above).** Because
   matching runs over raw text, API names in comments that are followed by `(`
   can be flagged. Tightening this (comment-aware scanning, or requiring a
   receiver like `crypto.`/an identifier before the call) would remove the FP
   class.
2. **EdDSA one-shot signing via `crypto.sign(null, …)` is not detected.** The
   one-shot rule requires a **quoted** algorithm as the first argument
   (`/(?:crypto\.)?(sign|verify)\s*\(\s*['"`][\w.-]+['"`]\s*,/`). Idiomatic
   Ed25519 signing passes `null` as the algorithm (`crypto.sign(null, msg, key)`)
   and is therefore missed. The corpus uses `crypto.sign("sha256", …)` for the
   one-shot positive precisely because the `null` form is a known miss. This is
   a true false-negative class not represented as a "must-detect" label to avoid
   asserting behaviour the detector does not claim.
3. **WebCrypto algorithm proximity window.** `webcrypto-classical` only fires
   when the algorithm token (`ECDH`, `ECDSA`, `RSA-OAEP`, …) sits within ~400
   characters of a `subtle.*` call. Algorithm constants defined far from their
   use site would be missed. Not exercised as a negative here.

## Caveats

- The corpus is **small and curated** to cover each detector once or twice with
  unambiguous cases. High precision/recall here means "the detectors do what
  they claim on canonical inputs and don't fire on the obvious traps" — it is
  **not** a statement about real-world recall over messy code.
- Findings are matched on `(ruleId, algorithm, hndl)`, not on line/column, so
  the benchmark validates _what_ is detected, not _where_.

## Reproducing

```bash
# from the repo root
npm test --workspace @qproof/core            # runs the full suite incl. the benchmark
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
