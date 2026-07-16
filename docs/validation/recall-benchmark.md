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

2026-07-15, `@quantakrypto/core`, after closing the cross-language TLS gap, the
library-form gaps, and the gaps a real-repo validation run surfaced (initial
baseline was 0.645):

**Overall: detection recall 0.830** (146 / 176; 10 caught unclassified; 30 false
negatives).

| By difficulty | recall |
| ------------- | ------ |
| config        | 1.000  |
| uncommon      | 0.913  |
| canonical     | 0.892  |
| adversarial   | 0.474  |
| aliased       | 0.368  |

The shape is the finding: the scanner catches **config** (1.00), **uncommon**
(0.90), and **canonical** (0.89) idioms well, and is bounded where the algorithm
identity is **obscured** — `aliased` (0.37, renamed imports / wrappers) and
`adversarial` (0.47, algorithm names assembled at runtime). Those two bands are
the lexical ceiling, and they are where the residual 30 false negatives live.

**Import-alias resolution (JS/TS)** now follows `import { generateKeyPairSync as
gk } from 'node:crypto'` and the CommonJS `const { createECDH: mk } =
require(...)` destructure-rename for the keygen / ECDH / DH constructors, so an
aliased call still detects — lifting `aliased` 0.32 → 0.37 (and overall 0.824 →
0.830) with precision held at 1.000. Aliases in other languages (Python module
`as`, Java/Rust/Ruby renames) remain the residual `aliased` gap.

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
- ✅ **Real-repo validation gaps** (`0.813 → 0.824`). Running qscan over four real
  OSS repos (golang-jwt, paramiko, panva/jose, gin) surfaced holes the authored
  corpus lacked, now closed with a corpus case each: **x509/PEM key parsing**
  (`x509.Parse*`, not just keygen — Go), **RSA-OAEP key transport** (JOSE JWE
  `alg`), and **classical SSH key exchange** (`diffie-hellman-group*` /
  `ecdh-sha2-*` / `curve25519-sha256`). The same run also fixed three false-positive
  classes — algorithm identifiers inside string literals (Go error messages),
  documentation prose (`.rst`/`.md`), and Python docstrings (PEM keys still caught)
  — and taught the readiness score to down-weight test/fixture paths. See
  [Real-world validation](#real-world-validation) below.

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

## Real-world validation

The authored corpus measures recall on idioms we thought to write. To check what
it *missed*, qscan was run over four real OSS repos and the findings audited by
hand:

| repo | precision (sampled) | what it exposed |
| --- | --- | --- |
| gin (general Go app) | 7/7, 0 FP | readiness score too harsh on test-only findings |
| panva/jose (JS JOSE) | ~100% | RSA-OAEP key transport entirely missed |
| golang-jwt (Go) | ~90% | x509/PEM key-parsing layer missed; FPs from identifiers in error strings |
| paramiko (Py SSH) | ~83% | finite-field DH kex missed; FPs on docstrings + `.rst` prose |

Every gap above is now closed and pinned by a benchmark case — three recall
positives (`recall/go/x509_keyutils.go`, `recall/js/jose-rsa-oaep.ts`,
`recall/python/ssh_kex_prefs.py`) and three tuned-corpus negatives that keep the
precision fixes from regressing (`negative/go-jwt-in-string.go`,
`negative/ssh-doc-prose.rst`, `negative/python-docstring-crypto.py`). The
precision fixes: a **code-only string guard** (identifier rules don't fire inside
string literals), a **doc-file skip** (SSH/TLS/cert token rules don't scan
`.rst`/`.md`), and **Python-docstring suppression** for token rules (PEM key
material inside a docstring is still caught). On the real repos this took
`ssh-public-key` on paramiko from 113 → 91 findings (22 prose/doc FPs removed) with
zero real keys lost, and gin's readiness from 40 → 81.

The lesson: an authored recall corpus is necessary but not sufficient — a
periodic real-code run is the only thing that finds the idioms you didn't imagine.

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
