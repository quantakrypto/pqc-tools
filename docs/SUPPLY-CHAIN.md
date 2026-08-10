# Supply-Chain Assurance

How `quantakrypto-tools` targets the three pillars of OSS supply-chain assurance —
**OpenSSF Scorecard**, **SLSA / npm provenance**, and **SPDX/REUSE licensing** —
and where the project stands against each today. This operationalises the supply-chain section of [COMPLIANCE.md §5](COMPLIANCE.md).

The project's strongest asset here is the [zero-runtime-dependency](adr/0001-zero-runtime-dependencies.md)
posture: no transitive CVEs, no lifecycle scripts, a tiny dev-tool surface. That
buys several assurance checks for free; the gaps are process, not dependencies.

## 1. Targets vs. current status

> **Status as of 0.10.0 (published):** provenance is **live**, the
> Scorecard workflow is **wired**, `reuse lint` runs in CI (advisory), per-package
> `LICENSE` files ship in the tarballs, and the `v1` Action tag is **auto-moved**
> to each released commit on publish (see §3). The remaining gap is a repo
> setting: branch protection + required reviews.

| Pillar | Target | Status | Gap to target |
|---|---|---|---|
| **OpenSSF Scorecard** | A published score with a badge; act on findings each run. | **Wired** — [`scorecard.yml`](../.github/workflows/scorecard.yml) runs weekly + on push, uploads SARIF, and publishes the score. | Turn on **branch protection** + required reviews (a repo setting) to lift the remaining checks; add the badge once the first score publishes. |
| **SLSA provenance** | SLSA build-provenance on every released artifact (L2+: hosted, hardened CI builder). | **Live.** All 6 published packages carry Sigstore provenance attestations (verified via `npm audit signatures`; tarballs reproduce bit-for-bit from source). | Publish from an **immutable release tag** rather than `main` so the attested ref is non-mutable (the `vX.Y.Z` tags now exist — see §3). |
| **npm provenance** | Each `@quantakrypto/*` package page shows a signed provenance attestation. | **Live** on all 6 published packages via `release.yml` (`--provenance`, GitHub OIDC). | Same as SLSA: pin the publish to the release tag. |
| **SPDX / REUSE** | `reuse lint` passes; licensing is machine-verifiable. | [`REUSE.toml`](../REUSE.toml) bulk declaration + `LICENSES/Apache-2.0.txt`; **per-package `LICENSE` now committed** (tarballs carry the Apache-2.0 text) and the stale `graphify-out/**` carve-out dropped. | `reuse lint` runs in CI (advisory) via the `supply-chain` job. |
| **Zero-dep enforcement** (ADR-0001) | No third-party runtime dep + no install lifecycle scripts, enforced by CI. | **Wired** — `scripts/check-zero-deps.mjs` gates the `supply-chain` CI job (was review-only). | — |

## 2. OpenSSF Scorecard

**Wired.** [`scorecard.yml`](../.github/workflows/scorecard.yml) runs
`ossf/scorecard-action` weekly + on push, uploads SARIF to the Security tab, and
publishes the score (OIDC `id-token: write`). The remaining step is to add the
badge once the first score publishes.

- **Free wins from zero deps:** `Pinned-Dependencies` (no third-party runtime
  deps; pin dev deps via `npm ci` + lockfile), `Vulnerabilities` (minimal surface),
  no dangerous lifecycle scripts.
- **Already in place:** CI (`Token-Permissions` are scoped read-by-default),
  `SECURITY.md`, `License`, issue/PR templates, a maintained changelog.
- **To raise the score:** enable **branch protection** + required code review on
  `main`; the [fuzz targets](THREAT-MODEL.md) and the release/provenance work below
  feed `Fuzzing` and `Signed-Releases`.

## 3. SLSA + npm provenance

The plan is the standard GitHub-Actions-native path:

1. Build + test in the [release workflow](../.github/workflows/release.yml)
   (`npm ci`, `npm run build`, `npm test`).
2. Publish with **`npm publish --provenance --access public`** using the OIDC
   `id-token: write` token. npm generates a Sigstore-backed provenance attestation
   linking the artifact to the exact CI workflow + commit, shown on the package
   page. This is also a SLSA-aligned provenance statement.
3. Record the release in the [CHANGELOG](../CHANGELOG.md) per [VERSIONING.md](VERSIONING.md).

**Status: done (since v0.4).** All 6 published packages (core, qscan, mcp,
qprobe, sieve, agent) publish from `release.yml` with provenance — the Action
itself is private (consumed via `uses:`, not npm); the `NPM_TOKEN` is configured and the Action `dist/index.js` is
committed and guarded by a "dist is fresh" CI gate (`ci.yml`) + a pre-publish gate
(`release.yml`), with a real `uses:`-path smoke test.

**Both earlier release-process gaps are closed:**
- **The `v1` Action tag auto-moves.** Since 0.4.3, `release.yml` force-moves `v1`
  to the released commit after a successful publish, so
  `uses: quantakrypto/pqc-tools/packages/action@v1` always runs the latest
  released bundle. Since 0.10.0 the step *discovers* the `vN` tags rather than
  naming `v1`, so a future major cannot be left behind on a stale bundle. `v1`
  is the only one today: the action has had no breaking change, and a moving
  major tag is the wrong place to record anything else.
- **Immutable semver tags exist.** Every release since v0.4.3 cuts a `vX.Y.Z` tag
  (v0.4.3 … v0.10.0), so consumers and provenance verifiers can pin a non-mutable
  ref. The residual refinement is publishing *from* the tag ref rather than `main`.

## 4. SPDX / REUSE licensing

The project is uniformly **Apache-2.0**, copyright **"quantakrypto / Dandelion Labs JSC"**.
Rather than stamp a per-file `SPDX-License-Identifier` header into every source
file, we use a **bulk declaration**:

- [`REUSE.toml`](../REUSE.toml) declares `**` as `Apache-2.0` with the project
  copyright, plus carve-outs for generated/data files. This is the REUSE-spec
  machine-readable equivalent of per-file headers — `reuse lint` passes without
  modifying any source (consistent with the read-only-on-source constraint).
- [`LICENSES/Apache-2.0.txt`](../LICENSES/Apache-2.0.txt) holds the canonical
  Apache-2.0 text REUSE expects in the `LICENSES/` directory; the root
  [`LICENSE`](../LICENSE) remains the human-facing copy.
- **NIST ACVP vectors are explicitly excluded** — Sieve ships none
  ([ADR-0004](adr/0004-sieve-no-fabricated-vectors.md)); any operator-supplied
  vectors are uncommitted and out of REUSE scope (track provenance per
  [compliance/acvp-provenance.md](compliance/acvp-provenance.md)).

**To verify:** `reuse lint` (and wire it into CI alongside the build/test).

## 5. Ongoing posture (recurring gates)

Beyond the one-time setup, these are enforced continuously:
- **Scorecard weekly** ([`scorecard.yml`](../.github/workflows/scorecard.yml)) — track drift, act on regressions.
- **Cadence audit weekly** ([`supply-chain-audit.yml`](../.github/workflows/supply-chain-audit.yml))
  — `npm audit` over the dev surface (advisory; zero runtime deps means nothing ships)
  plus the two hard invariants below, re-checked even in weeks with no commits.
- **Dependency review on every PR** ([`ci.yml`](../.github/workflows/ci.yml) `dependency-review`)
  — blocks a PR that introduces a known-vulnerable dependency (`fail-on-severity: high`)
  or a copyleft-incompatible license.
- **SHA-pinned Actions, enforced** — [`scripts/check-action-pins.mjs`](../scripts/check-action-pins.mjs)
  fails CI if any `uses:` is on a mutable tag/branch instead of a 40-char commit SHA
  (Scorecard *Pinned-Dependencies*). Dependabot opens the bump PRs; the gate stops regressions.
- **Zero runtime dependencies**, enforced — [`scripts/check-zero-deps.mjs`](../scripts/check-zero-deps.mjs)
  ([ADR-0001](adr/0001-zero-runtime-dependencies.md)); a new runtime dep needs an ADR.
- **Lockfile integrity** — always `npm ci`; never run arbitrary lifecycle scripts.
- **`reuse lint`** on every push to keep licensing clean as files land.
- **Reproducible builds** — [`repro:check`](../.github/workflows/ci.yml) gates that the
  published tarballs re-create byte-for-byte from source ([validation/reproducible-build.md](validation/reproducible-build.md)).
