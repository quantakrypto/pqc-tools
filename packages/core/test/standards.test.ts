/**
 * Standards-drift guard. The scanner's recommendations must track the published
 * NIST / CNSA / IETF standards; `standards.ts` is the dated source of truth and
 * these tests fail the build if the runtime constants drift from it. This is the
 * enforcement half of the quarterly standards-currency cadence
 * (docs/standards/pqc-standards.md).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  PQC_STANDARDS,
  PQC_TRANSITION_NOTE,
  STATEFUL_HBS_NOTE,
  TIER_PARAMS,
  standardsReviewStatus,
} from "../src/index.js";

test("CNSA tier params in remediation match the standards source of truth", () => {
  // If someone changes a tier target in remediation.ts (or the manifest) without
  // the other, this fails — the two can never silently diverge.
  assert.equal(TIER_PARAMS["category-3"].kem, PQC_STANDARDS.cnsa.category3.kem);
  assert.equal(TIER_PARAMS["category-3"].signature, PQC_STANDARDS.cnsa.category3.signature);
  assert.equal(TIER_PARAMS["category-5"].kem, PQC_STANDARDS.cnsa.category5.kem);
  assert.equal(TIER_PARAMS["category-5"].signature, PQC_STANDARDS.cnsa.category5.signature);
});

test("the transition note surfaces the manifest's IR 8547 timeline + emerging algos", () => {
  const t = PQC_STANDARDS.transitionTimeline;
  assert.match(PQC_TRANSITION_NOTE, new RegExp(String(t.deprecateAfter)));
  assert.match(PQC_TRANSITION_NOTE, new RegExp(String(t.disallowAfter)));
  assert.match(PQC_TRANSITION_NOTE, /IR 8547/);
  // Each emerging algorithm the manifest tracks is named in the note the tool
  // shows users, so the note can't quietly fall behind the manifest.
  for (const name of ["HQC", "FN-DSA", "X-Wing"]) {
    assert.ok(
      PQC_STANDARDS.emerging.some((e) => e.summary.includes(name)),
      `manifest tracks ${name}`,
    );
    assert.match(PQC_TRANSITION_NOTE, new RegExp(name.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")));
  }
});

test("the stateful-HBS note cites the manifest's SP 800-208 source", () => {
  assert.match(PQC_STANDARDS.statefulHbs.source, /SP 800-208/);
  assert.match(STATEFUL_HBS_NOTE, /SP 800-208/);
});

test("review dates are well-formed and ordered, and match the stated interval", () => {
  const iso = /^\d{4}-\d{2}-\d{2}$/;
  assert.match(PQC_STANDARDS.lastReviewed, iso);
  assert.match(PQC_STANDARDS.nextReview, iso);
  const last = Date.parse(`${PQC_STANDARDS.lastReviewed}T00:00:00Z`);
  const next = Date.parse(`${PQC_STANDARDS.nextReview}T00:00:00Z`);
  assert.ok(Number.isFinite(last) && Number.isFinite(next), "dates parse");
  assert.ok(next > last, "nextReview is after lastReviewed");
  // The gap should be ~reviewIntervalMonths (allow ±5 days of month-length slop).
  const months = (next - last) / (86_400_000 * 30.44);
  assert.ok(
    Math.abs(months - PQC_STANDARDS.reviewIntervalMonths) < 0.2,
    `gap (~${months.toFixed(1)}mo) matches reviewIntervalMonths (${PQC_STANDARDS.reviewIntervalMonths})`,
  );
  // Every citation carries a source + an asOf month.
  const cites = [
    PQC_STANDARDS.fips.mlKem,
    PQC_STANDARDS.fips.mlDsa,
    PQC_STANDARDS.fips.slhDsa,
    PQC_STANDARDS.statefulHbs,
    ...PQC_STANDARDS.emerging,
    ...PQC_STANDARDS.hybrids,
  ];
  for (const c of cites) {
    assert.ok(c.source.length > 0, "citation has a source");
    assert.match(c.asOf, /^\d{4}-\d{2}$/, `asOf is YYYY-MM (${c.source})`);
  }
});

test("standardsReviewStatus is deterministic around nextReview", () => {
  // The day before nextReview: not due, 1 day out.
  const before = standardsReviewStatus(new Date("2026-10-18T12:00:00Z"));
  assert.equal(before.due, false);
  assert.equal(before.daysUntil, 1);
  // On nextReview: due.
  const on = standardsReviewStatus(new Date("2026-10-19T00:00:00Z"));
  assert.equal(on.due, true);
  assert.equal(on.daysUntil, 0);
  // Past nextReview: due and overdue (negative days).
  const after = standardsReviewStatus(new Date("2026-11-19T00:00:00Z"));
  assert.equal(after.due, true);
  assert.ok(after.daysUntil < 0);
});
