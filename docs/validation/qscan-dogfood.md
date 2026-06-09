# Validation — qScan dogfood on real repositories

Beyond the labeled [detection benchmark](detection-benchmark.md), qScan was run
against real third-party projects that deliberately use classical asymmetric
cryptography, to confirm it behaves sensibly on real-world code at scale.

## Method

Shallow-clone each project and scan its source (dependency manifests excluded
where noted, to focus on inline usage):

```bash
git clone --depth 1 https://github.com/auth0/node-jsonwebtoken
git clone --depth 1 https://github.com/panva/jose
node packages/qscan/dist/cli.js ./node-jsonwebtoken --no-deps
node packages/qscan/dist/cli.js ./jose/src
```

## Results

| Repository | Files | Findings (by severity) | HNDL | Readiness |
|---|---:|---|---:|---:|
| `auth0/node-jsonwebtoken` | 84 | 91 (9 critical · 79 high · 3 low) | 14 | 0 / 100 |
| `panva/jose` (`src/`) | 55 | 129 (3 critical · 124 high · 2 low) | 46 | 0 / 100 |

A **0 / 100** readiness score is the **correct** result here: both projects are
cryptography libraries whose entire purpose is RSA / ECDSA / ECDH / EdDSA and
JOSE algorithm support. The findings line up with what these codebases actually
contain:

- **jsonwebtoken** — `critical` findings are embedded EC / DSA private keys in
  `test/*.pem`; `high` findings are RSA / ECDSA sign-verify usage (`RS256`,
  `ES256`, …). 14 are flagged harvest-now-decrypt-later (the key-agreement and
  KEM-shaped usages).
- **jose** — `critical` findings are PKCS#8 private keys in test/example strings;
  `high` findings are WebCrypto and JOSE algorithm usage (`RSA-OAEP`, `ECDH-ES`,
  `ES256`, …), with 46 HNDL exposures (JOSE leans heavily on key agreement).

Spot-checks of the reported `file:line` locations matched real cryptographic
usage — no obvious spurious flags in the sampled output.

## Observation → backlog

The PEM/key detectors fire on **test fixtures and documentation examples** (e.g.
`test/ecdsa-private.pem`, example PKCS#8 blocks in doc comments). That is
technically correct — they *are* classical keys in the tree — but a real user
would [baseline](../../packages/qscan/README.md) the test directory or scan only
shipped source. A future heuristic could **down-rank key material found under
`test/` / `fixtures/` / `examples/`**, complementing the comment-context false
positive already recorded in the [detection benchmark](detection-benchmark.md).
Filed as a backlog item, not a blocker.

## Takeaway

On real, crypto-heavy repositories qScan produces an accurate inventory, a correct
readiness verdict, and actionable `file:line` findings — at interactive speed over
50–90-file trees.
