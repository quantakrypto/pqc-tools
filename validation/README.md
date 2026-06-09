# validation/

Validation-only harnesses that exercise the tools against **real** inputs. These
live **outside the npm workspaces** on purpose: they may depend on third-party
packages (e.g. a real PQC implementation), and keeping them out of `packages/*`
ensures every **published `@qproof/*` package stays zero-dependency**. CI does not
install or run anything here.

## Contents

- **`sieve-real-sut/`** — adapts the audited [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
  ML-KEM / ML-DSA / SLH-DSA implementation to Sieve's stdin/stdout JSON protocol,
  so Sieve can be run against real cryptography (and a fault-injected variant).
  Results: [`docs/validation/sieve-real-impl.md`](../docs/validation/sieve-real-impl.md).

  ```bash
  cd validation/sieve-real-sut && npm install
  cd ../..
  node packages/sieve/dist/cli.js \
    --impl "node $(pwd)/validation/sieve-real-sut/sut.mjs" --param ml-kem-768
  ```

## Related

- Detection accuracy benchmark (labeled corpus, precision/recall):
  [`docs/validation/detection-benchmark.md`](../docs/validation/detection-benchmark.md).
- qScan dogfood on real repositories:
  [`docs/validation/qscan-dogfood.md`](../docs/validation/qscan-dogfood.md).
