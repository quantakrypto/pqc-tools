# PQC standards currency — source of truth & review cadence

A post-quantum readiness scanner is only as credible as the standards its
recommendations track. This page operationalizes the quarterly re-check that
keeps those recommendations current, and records how drift is caught
automatically.

## Where the facts live

The **single source of truth** is
[`packages/core/src/standards.ts`](../../packages/core/src/standards.ts) —
`PQC_STANDARDS`, a typed, dated, cited snapshot of the NIST / CNSA / IETF facts
the tool depends on:

- **NIST FIPS 203 / 204 / 205** — ML-KEM, ML-DSA, SLH-DSA (the remediation targets).
- **CNSA 2.0 tiers** — the Category-3 and Category-5 KEM / signature parameter sets.
- **NIST SP 800-208** — LMS / XMSS stateful hash-based signatures.
- **NIST IR 8547** — the 2030-deprecate / 2035-disallow migration timeline.
- **Emerging** — HQC (backup KEM), FN-DSA / Falcon (draft FIPS 206), X-Wing.
- **Hybrids** — X25519MLKEM768, SecP384r1MLKEM1024.

Every fact carries a `source` and an `asOf` month; the snapshot carries
`lastReviewed`, `nextReview`, and `reviewIntervalMonths` (**quarterly**).

## How drift is caught (automatically)

- **Hard gate — the drift test.**
  [`packages/core/test/standards.test.ts`](../../packages/core/test/standards.test.ts)
  runs in CI (`npm test`) and **fails the build** if the runtime constants drift
  from the manifest: it asserts `remediation.TIER_PARAMS` equals the CNSA tiers,
  that `PQC_TRANSITION_NOTE` surfaces the IR 8547 timeline and every emerging
  algorithm, and that `STATEFUL_HBS_NOTE` cites SP 800-208. So a target can never
  change in code without the manifest (or vice-versa).

- **Calendar reminder — the cadence script.** `npm run standards:check`
  (`scripts/standards-check.mjs`) prints the review status and the list of sources
  to re-verify, and emits a `::warning::` annotation when `nextReview` has passed.
  It is **advisory** (never fails the build). `standardsReviewStatus(now)` is the
  pure predicate behind it.

## The quarterly review (runbook)

Do this on or before `nextReview`:

1. **Re-verify each source** in `PQC_STANDARDS` against its publication — run
   `npm run standards:check` for the checklist. Look for:
   - new or amended FIPS (e.g. FIPS 206 / FN-DSA finalization),
   - CNSA 2.0 tier or milestone changes,
   - HQC draft-FIPS / other backup-algorithm progress,
   - TLS/HPKE hybrid-group changes (IETF drafts → RFCs),
   - IR 8547 status (draft → final) and any date changes.
2. **Update `standards.ts`** — edit the affected facts and bump their `asOf`.
   If a recommendation target changes, update `remediation.ts`'s `TIER_PARAMS` /
   notes in the same commit (the drift test will otherwise fail).
3. **Roll the dates** — set `lastReviewed` to today and `nextReview` forward by
   `reviewIntervalMonths`.
4. **Run** `npm run build && npm test` — the drift test must stay green.
5. Note the review in the changelog.

> The point of the cadence isn't ceremony: it's that a stale recommendation in a
> security tool is a real defect, and this makes "are we current?" a checkable,
> dated question instead of an assumption.
