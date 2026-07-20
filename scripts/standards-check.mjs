#!/usr/bin/env node
// scripts/standards-check.mjs — advisory PQC standards-currency cadence check.
//
// Reads the dated standards source of truth (@quantakrypto/core `PQC_STANDARDS`)
// and warns — it does NOT fail the build — when the quarterly review is due, so a
// review can't be silently skipped. The hard gate is the drift test
// (packages/core/test/standards.test.ts, which keeps the runtime remediation
// constants aligned with the manifest); this script is the calendar reminder and
// prints the sources to re-check.
//
// Usage: node scripts/standards-check.mjs   (run `npm run build` first)

// Import from the `standards` module directly: `standardsReviewStatus` is an
// internal cadence helper that the frozen public barrel (index.js) does not
// re-export, so importing it from the barrel throws. `standards.js` exports both.
import { PQC_STANDARDS, standardsReviewStatus } from "../packages/core/dist/standards.js";

const s = PQC_STANDARDS;
const status = standardsReviewStatus(new Date());

console.log(
  `PQC standards — last reviewed ${s.lastReviewed}, next review ${s.nextReview} ` +
    `(cadence: every ${s.reviewIntervalMonths} months).`,
);

if (status.due) {
  // `::warning::` renders as a GitHub Actions annotation when run in CI.
  console.log(
    `::warning::PQC standards review is DUE (${-status.daysUntil} day(s) overdue). ` +
      `Re-verify each source below, update standards.ts + its asOf dates, and roll ` +
      `lastReviewed/nextReview forward — see docs/standards/pqc-standards.md.`,
  );
} else {
  console.log(`Review not due for ${status.daysUntil} day(s). ✓`);
}

console.log("\nSources to re-verify on each review:");
const line = (c) => console.log(`  - ${c.source} (asOf ${c.asOf}) — ${c.summary}`);
line(s.fips.mlKem);
line(s.fips.mlDsa);
line(s.fips.slhDsa);
console.log(`  - ${s.cnsa.source} (asOf ${s.cnsa.asOf})`);
console.log(
  `      category-3: ${s.cnsa.category3.kem} / ${s.cnsa.category3.signature}` +
    `  ·  category-5: ${s.cnsa.category5.kem} / ${s.cnsa.category5.signature}`,
);
line(s.statefulHbs);
console.log(
  `  - ${s.transitionTimeline.source} (asOf ${s.transitionTimeline.asOf}) — ` +
    `deprecate after ${s.transitionTimeline.deprecateAfter}, disallow after ${s.transitionTimeline.disallowAfter}`,
);
for (const c of [...s.emerging, ...s.hybrids]) line(c);

// Advisory: never fail the build. The drift test is the hard gate.
process.exit(0);
