# Validation — Sieve against a real PQC implementation

Sieve's unit tests drive a deliberately non-cryptographic mock SUT. This document
records driving Sieve against a **real, audited** implementation —
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (pure
JavaScript ML-KEM / ML-DSA / SLH-DSA) — to prove the battery works end-to-end on
real cryptography, catches a deliberately broken implementation, and surfaces a
genuine conformance observation.

## Harness

`validation/sieve-real-sut/` is a **standalone** package — it lives **outside the
npm workspaces**, so adding `@noble/post-quantum` here keeps every published
`@quantakrypto/*` package zero-dependency. `sut.mjs` adapts the library to Sieve's
newline-delimited JSON protocol (`packages/sieve/PROTOCOL.md`).

```bash
cd validation/sieve-real-sut && npm install
cd ../..
SUT="node $(pwd)/validation/sieve-real-sut/sut.mjs"
node packages/sieve/dist/cli.js --impl "$SUT" --param ml-kem-768
node packages/sieve/dist/cli.js --impl "$SUT" --param ml-dsa-65
node packages/sieve/dist/cli.js --impl "$SUT" --param slh-dsa-sha2-128s \
  --iterations 2 --timeout-ms 120000 --pipeline-depth 1
```

## Results

| Parameter set | Categories | Verdict |
|---|---|---|
| `ml-kem-768` | correctness ✅ · determinism ✅ · implicit-rejection [AF-02] ✅ · robustness ✅ · **sizes [AF-05] ❌** | **FAIL** (one real finding, below) |
| `ml-dsa-65` | sign/verify self-consistency ✅ | **PASS** |
| `slh-dsa-sha2-128s` | sign/verify self-consistency ✅ | **PASS** (see timeout note) |
| `slh-dsa-sha2-128f` | sign/verify self-consistency ✅ | **PASS** |

`kat` is correctly **SKIP**ped everywhere (no official NIST ACVP vectors supplied;
Sieve ships none and never fabricates them).

### The finding — FIPS 203 §7.2 encapsulation-key check (real, since fixed upstream)

Sieve's `encaps-ek-coeff-out-of-range` check feeds `encapsulate` a correctly-sized
encapsulation key with one coefficient forced out of range (≥ q = 3329). A
FIPS 203 §7.2-conformant `Encaps` must reject it (the "modulus check" /
input validation). `@noble/post-quantum` **≤ 0.5.4** accepted it and returned a
success result instead of rejecting.

**Status (verified 2026-07-19):** already fixed upstream. `@noble/post-quantum`
**0.6.0 (2026-03-31)** added the missing mod-q reduction in the d=12 `ByteDecode12`
path, so the `encapsulate` modulus check is no longer a no-op — 0.6.0 and 0.6.1
correctly reject the out-of-range key. Confirmed empirically across 0.5.2 / 0.5.4
(accept) → 0.6.0 / 0.6.1 (reject); noble's own 0.6.x source comment names the exact
value ("the modulus check … becomes a no-op for malformed coefficients like 4095"),
which is precisely what Sieve exercises. Our original run hit an older pinned
release; the fix predates it. **No upstream report is warranted** — the fix shipped
~3.5 months before we looked.

The observation remains a valid demonstration: the §7.2 modulus check is
defense-in-depth and **commonly omitted** (it does not affect honest
interoperability), and **Sieve caught a genuine conformance deviation in audited
code** — exactly what a conformance battery is for. The lesson: always re-verify a
conformance finding against the *current* release before publishing, and pin the
version. A pinned regression test lives in `packages/sieve/test/noble-ml-kem.test.ts`.

## Negative control — Sieve catches a broken implementation

A fault-injecting variant where `decaps` returns a wrong (but valid-length) shared
secret is correctly rejected:

```bash
node packages/sieve/dist/cli.js --impl "$SUT bad-roundtrip" --param ml-kem-768
# [FAIL] correctness — 32 mismatch(es)
# [FAIL] implicit-rejection [AF-02] — violations detected
# OVERALL: FAIL
```

So the battery is not a rubber stamp — it distinguishes a correct implementation
from a broken one.

## Two operational notes confirmed in passing

- **Env-scrub (P0-3) works.** Injecting the fault via an environment variable
  (`SUT_BREAK=…`) had **no effect** — Sieve scrubs the SUT's environment to a
  minimal allow-list, so secrets in the parent environment never reach an
  untrusted SUT. Faults must be passed as a command argument instead.
- **Timeouts for slow signers.** `slh-dsa-sha2-128s` signing is expensive in pure
  JS; the default `--timeout-ms 10000` is too short under pipelining. Raise
  `--timeout-ms` and lower `--iterations` (or use the `…-128f` "fast" variant).
  This is a tuning note, not a conformance issue.

## Takeaway

Sieve drives a real, audited ML-KEM / ML-DSA / SLH-DSA implementation, agrees with
it on the conformance categories, **catches a deliberately broken variant**, and
**surfaced one genuine FIPS 203 §7.2 deviation** — all without implementing any
cryptography itself or shipping a single test vector.
