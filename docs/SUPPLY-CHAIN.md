# Supply-Chain Assurance

How `quantakrypto-tools` targets the three pillars of OSS supply-chain assurance —
**OpenSSF Scorecard**, **SLSA / npm provenance**, and **SPDX/REUSE licensing** —
and where the project stands against each today. This operationalises
[ROADMAP P2-7](ROADMAP.md) and the supply-chain section of [COMPLIANCE.md](COMPLIANCE.md §5).

The project's strongest asset here is the [zero-runtime-dependency](adr/0001-zero-runtime-dependencies.md)
posture: no transitive CVEs, no lifecycle scripts, a tiny dev-tool surface. That
buys several assurance checks for free; the gaps are process, not dependencies.

## 1. Targets vs. current status

> **Status as of v0.4.2 (2026-07-15):** provenance is **live**; the remaining
> gaps are the Scorecard workflow, `reuse lint` in CI, per-package `LICENSE` in
> tarballs, and — most actionably — the **stale `v1` Action tag** (see §3).

| Pillar | Target | Status | Gap to target |
|---|---|---|---|
| **OpenSSF Scorecard** | A published score with a badge; act on findings each run. | **Wired** — [`scorecard.yml`](../.github/workflows/scorecard.yml) runs weekly + on push, uploads SARIF, and publishes the score. | Turn on **branch protection** + required reviews (a repo setting) to lift the remaining checks; add the badge once the first score publishes. |
| **SLSA provenance** | SLSA build-provenance on every released artifact (L2+: hosted, hardened CI builder). | **Live.** All 5 library packages carry Sigstore provenance attestations (verified via `npm audit signatures`; tarballs reproduce bit-for-bit from source). | Publish from an **immutable release tag** rather than `main` so the attested ref is non-mutable. |
| **npm provenance** | Each `@quantakrypto/*` package page shows a signed provenance attestation. | **Live** on all 5 published packages via `release.yml` (`--provenance`, GitHub OIDC). | Same as SLSA: pin to a release tag; cut `vX.Y.Z` tags per release. |
| **SPDX / REUSE** | `reuse lint` passes; licensing is machine-verifiable. | [`REUSE.toml`](../REUSE.toml) bulk declaration + `LICENSES/Apache-2.0.txt`; **per-package `LICENSE` now committed** (tarballs carry the Apache-2.0 text) and the stale `graphify-out/**` carve-out dropped. | `reuse lint` runs in CI (advisory) via the `supply-chain` job. |
| **Zero-dep enforcement** (ADR-0001) | No third-party runtime dep + no install lifecycle scripts, enforced by CI. | **Wired** — `scripts/check-zero-deps.mjs` gates the `supply-chain` CI job (was review-only). | — |

## 2. OpenSSF Scorecard

**Not yet wired (the one remaining pillar with no implementation).** The repo is
now public, so the earlier "deferred while private" blocker is gone. The next step
is a workflow that runs `ossf/scorecard-action` (pin a real release, e.g.
`@v2.4.3`), uploads SARIF to the Security tab, and publishes the score (OIDC
`id-token: write`) so a badge can be displayed.

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

**Status: done (since v0.4).** All 5 library packages publish from `release.yml`
with provenance; the `NPM_TOKEN` is configured and the Action `dist/index.js` is
committed and guarded by a "dist is fresh" CI gate (`ci.yml`) + a pre-publish gate
(`release.yml`), with a real `uses:`-path smoke test.

**Two residual release-process gaps (both actionable):**
- **The `v1` Action tag is stale.** It points at a pre-0.4.2 commit, so
  `uses: quantakrypto/pqc-tools/packages/action@v1` runs a bundle **without the
  0.4.2 security fixes** and silently ignores the `mode: comment-plan` input.
  Fix: force-move `v1` to the release commit as a step in `release.yml` after a
  successful publish.
- **No immutable semver tags.** Releases publish from `main`, so provenance pins a
  mutable ref. Cut `vX.Y.Z` tags + a GitHub Release per version and publish from
  the tag.

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
