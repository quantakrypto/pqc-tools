# Reproducible-build verification

**Guarantee:** the npm tarball published for any `@quantakrypto/*` version can be
re-created, **byte for byte**, from the tagged source tree. Anyone can therefore
audit that the registry serves exactly what is in git — no injected, altered, or
extra files between `git` and `npm i`.

This complements the [Sigstore build provenance](../SUPPLY-CHAIN.md) attached at
publish time: provenance proves *where* the artifact was built; reproducibility
proves *that the source alone determines it*.

## How to verify

The workspaces must be built first (`npm run build` — its `postbuild` step pins
bin-file modes, see below).

```bash
npm run build

# Determinism (network-free): pack each workspace, perturb the known
# nondeterminism source, re-normalize, re-pack, and assert the SHA-512
# integrity is unchanged. This is the CI gate (`reproducible` job).
npm run repro:check

# Release verification (needs network + a published version): additionally
# diff each from-source pack integrity against the integrity npm recorded
# for that exact version.
npm run repro:npm
```

`repro:npm` output for the current release:

```
reproducible-build verification (vs npm)

  package                  version   deterministic  vs-npm
  --------------------------------------------------------------
  @quantakrypto/agent      0.4.4     ✅ yes          ✅ match
  @quantakrypto/core       0.4.4     ✅ yes          ✅ match
  @quantakrypto/mcp        0.4.4     ✅ yes          ✅ match
  @quantakrypto/qprobe     0.4.4     ✅ yes          ✅ match
  @quantakrypto/qscan      0.4.4     ✅ yes          ✅ match
  @quantakrypto/sieve      0.4.4     ✅ yes          ✅ match
```

All six published packages reproduce from source at v0.4.4.

## Why it works — and the one trap we had to close

npm tarballs are already mostly deterministic: `npm pack` normalizes entry
order, sets a fixed mtime (1985-10-26), and drops owner/group. The build output
itself is deterministic because `tsc` emits the same JavaScript for the same
source, and the packages carry **zero runtime dependencies** ([ADR-0001](../adr/0001-zero-runtime-dependencies.md)),
so there is no dependency tree to drift.

The one variance we found (and fixed) was **bin file mode**:

- `tsc -b` overwrites a file's *contents* but preserves its existing *mode*.
- A `dist/cli.js` that once picked up an exec bit (`0755`) during local dev keeps
  it on every rebuild; a fresh CI checkout creates the same file at `0644`.
- `npm pack` records the on-disk mode verbatim in the tar header, so identical
  source packed to two different tarballs — different integrity.

This affected exactly the three packages with a `bin` (`qscan`, `mcp`, `sieve`);
`core`, `agent`, and `qprobe` (no bin) always reproduced.

**Fix:** a root `postbuild` step, [`scripts/normalize-bin-modes.mjs`](../../scripts/normalize-bin-modes.mjs),
pins every workspace `bin` target to `0644` after each build. `0644` is safe
because npm re-creates the exec bit on the installed `bin` shim from the `bin`
field at install time — the mode inside the tarball never affects whether the
CLI runs. Pinning explicitly also makes the result umask-independent.

The [`reproducible` CI job](../../.github/workflows/ci.yml) runs `repro:check` on
every push and PR, so a new nondeterminism source (a generated file with an
embedded timestamp, a non-pinned mode, a stray artifact) fails the build instead
of silently shipping.

## Scope

- **Covered:** the six published npm packages.
- **Not covered here:** `@quantakrypto/action` is `private` and ships its committed
  `dist/` as a GitHub Action (kept current by the `action dist is fresh` gate),
  not an npm tarball — so it is out of scope for tarball reproducibility.
- **Toolchain assumption:** a matching major Node/npm (the releases are built on
  Node 20). A different npm major could in principle change tarball normalization;
  the CI gate pins Node 20, matching the release workflow.
