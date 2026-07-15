# Recall benchmark — false-negative depth over real-world crypto

This is the companion to the [detection benchmark](detection-benchmark.md). That
one scores precision/recall on a small, curated corpus and **gates it at 1.000** —
but its corpus is, by design, tuned to the detectors' documented lexical contract,
so (as its own caveats admit) it says nothing about **recall over messy,
real-world code**.

This benchmark fills that gap. It answers a harder question: *of the
quantum-vulnerable cryptography that actually appears in idiomatic code across all
eight supported languages, how much does the scanner catch?* The number is an
honest lower bound, and the false negatives it enumerates are the actionable
output — the roadmap for closing detector gaps.

Executed by [`packages/core/test/recall.test.ts`](../../packages/core/test/recall.test.ts)
as part of the normal test suite. Set `RECALL_DEBUG=1` to dump per-file found
families for calibration.

## The corpus

`packages/core/test/benchmark/recall/` — **85 labeled files, 166 expected crypto
occurrences**, one subdirectory per language (`js python go java csharp rust ruby
c`). Unlike the tuned corpus, it is deliberately built to be **hard**: real,
idiomatic library usage, including aliased imports, wrapper indirection, uncommon
APIs, crypto in config/manifest/PEM material, and adversarially-formatted call
sites (algorithm names built from constants, `StringBuilder`, `const_get`, split
across lines).

Two honesty rules govern it:

1. **Ground truth is labeled by what the crypto _truly is_** ([`recall-labels.json`](../../packages/core/test/benchmark/recall-labels.json)),
   independent of what the detectors happen to match. Each occurrence carries a
   `family` and a `difficulty` (`canonical | aliased | uncommon | config |
   adversarial`). A missed detection is therefore a genuine false negative.
2. **The corpus was written blind to the detector source** (each language builder
   was instructed not to read the detectors), so it is not tuned to pass.

## The metric

**Detection recall.** For each expected occurrence in a file we ask: *did the
scanner surface any finding for it?* Matching is greedy multiset per file, on the
crypto **family** (RSA, DH, ECDH, ECDSA, DSA, EdDSA, X25519, X448, secp256k1, and
the structural families TLS/SSH/DEP) — not on `ruleId`, so it is robust to which
rule fired. Two deliberate rules:

- A finding the scanner produced but **could not classify** (`algorithm:
  unknown` — e.g. a one-shot sign, a JWT `alg`, a PEM public key) still counts as
  a detection: the crypto _was_ surfaced to the user, which is what recall
  measures. Family-classification accuracy is a separate, stricter concern.
- A **secp256k1** use caught under the generic EC family (ECDSA/ECDH) counts —
  the curve was flagged even if not named. Exact families are matched first so a
  permissive family never steals a finding a stricter expected needed.

```
recall = detected / (detected + missed)
```

This is **not** gated at 1.000 — real-world recall < 1 is expected. The floor
assertion (`RECALL_FLOOR`) sits just below the measured value as a regression
guard; the enumerated false negatives are the point.

## Current measured results

2026-07-15, `@quantakrypto/core`, after closing the cross-language TLS gap and the
library-form gaps (initial baseline was 0.645):

**Overall: detection recall 0.813** (135 / 166; 8 caught unclassified; 31 false
negatives).

| By language | recall |     | By difficulty | recall |
| ----------- | ------ | --- | ------------- | ------ |
| python      | 0.952  |     | config        | 1.000  |
| c           | 0.933  |     | uncommon      | 0.902  |
| js          | 0.895  |     | canonical     | 0.892  |
| csharp      | 0.833  |     | adversarial   | 0.474  |
| ruby        | 0.800  |     | aliased       | 0.316  |
| rust        | 0.778  |     |               |        |
| go          | 0.739  |     |               |        |
| java        | 0.667  |     |               |        |

The shape is the finding: the scanner catches **config** (1.00), **uncommon**
(0.90), and **canonical** (0.89) idioms well, and is bounded where the algorithm
identity is **obscured** — `aliased` (0.32, renamed imports / wrappers) and
`adversarial` (0.47, algorithm names assembled at runtime). Those two bands are
the lexical ceiling, and they are where the residual 31 false negatives live.

## What the false negatives tell us

Grouping the 59 misses by root cause separates the *closable* gaps from the
*lexical ceiling*:

**Closable detector gaps:**

- ✅ **Classical TLS key-exchange config, all languages** (was ~11 misses,
  **closed**). A language-agnostic `tls-classical-kex` detector now flags classical
  cipher suites (`ECDHE-RSA`, `ECDHE-ECDSA`, `DHE-RSA`, `TLS_ECDHE_*`) — the
  Shor-broken key exchange the legacy-*version* rule missed. This lifted config
  recall 0.74 → 0.96 and overall 0.645 → 0.711 (the audit's "cross-language TLS"
  gap).
- ✅ **Library/identifier forms** (was ~15 misses, **closed**): Go/Rust JWT
  `SigningMethodRS256` / `Algorithm::RS256` identifier forms; libsodium
  `crypto_sign_ed25519_keypair`; the `ed25519`/`rbnacl` Ruby gems; BouncyCastle
  `Ed25519`/`X25519`/`X448`/DH lightweight classes in Java/C#; and the
  `cloudflare/circl` + decred `secp256k1/v4` Go modules in the dependency catalog.
  This lifted uncommon recall 0.66 → 0.90 and overall 0.711 → 0.813.

**The lexical ceiling (documented, not chased) — where the residual 31 FNs live:**

- **Algorithm identity constructed at runtime** — `"Ed" + "25519"`, `append("R")
  .append("s").append("a")`, `const_get('DSA')`, `string.Concat(...)`, curve names
  resolved from a config table. A regex scanner cannot follow arbitrary string
  construction; catching these would need dataflow. Surfaced honestly as the
  `adversarial` recall (0.47).
- **Import aliasing / re-export** — `import rsa as _rsa`, `generateKeyPairSync as
  gk`, dot-imports. The call is renamed away from the token the rule keys on.
- **Family-classification nuance** — a couple of residual FNs are cases where the
  crypto *was* detected but under a sibling family: an EC key generated for ECDSA
  signing is flagged as `ECDH` (EC keygen is ambiguous, so the scanner reports the
  key-agreement/HNDL family). The metric counts these strictly as misses of the
  labeled family; the underlying key was surfaced.

The benchmark exists so these numbers move deliberately, with evidence, rather
than being asserted.

## Reproducing

```bash
# from the repo root
node --import tsx --test packages/core/test/recall.test.ts
# with the per-file family dump:
RECALL_DEBUG=1 node --import tsx --test packages/core/test/recall.test.ts
```

## Updating

When you add a real-world idiom or close a gap:

1. Add corpus file(s) under `recall/<lang>/` and the matching `recall-labels.json`
   entry (label by the true crypto, not by what you think the detector does).
2. Run the benchmark, read the printed scorecard + false-negative list.
3. Update the **measured** numbers above.
4. Only then raise `RECALL_FLOOR`, keeping it just below the new measured value.
