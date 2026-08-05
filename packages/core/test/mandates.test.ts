/**
 * Tests for the compliance-mandate evaluator + gate: the dated catalog, the
 * tiered deprecate/disallow statuses, the honest in-scope summary, and the
 * deadline-aware gate semantics (`violation` fails; `deprecated` warns).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  MANDATES,
  assertKnownMandates,
  evaluateMandates,
  getMandate,
  mandateGateFails,
  mandateIds,
} from "../src/index.js";
import type { CryptoPolicy, Finding } from "../src/index.js";

/** Minimal Finding for the fields the evaluator reads. */
function f(algorithm: string | undefined, i = 0): Finding {
  return {
    ruleId: `rule-${i}`,
    algorithm,
    severity: "high",
    location: { file: "src/x.ts", line: i + 1 },
  } as unknown as Finding;
}

const rsa = f("RSA", 1);

// Org policies for the --policy composition tests: the same RSA finding under
// three different org stances. `permitted`/`inTransition` are ACKNOWLEDGED (an
// owned exception / a tracked migration); `prohibited` is not — it reinforces
// the mandate and never earns a gate exemption.
const permitRsa: CryptoPolicy = { name: "org", permitted: ["RSA"] };
const transitionRsa: CryptoPolicy = { name: "org", inTransition: ["RSA"] };
const prohibitRsa: CryptoPolicy = { name: "org", prohibited: ["RSA"] };

// The catalog derives its deadlines from PQC_STANDARDS.transitionTimeline
// (2030 / 2035, effective the LAST day of each year — see mandates.ts). The
// standards drift test (standards.test.ts) asserts that derivation; here we
// pin the behavioral consequences.
const DUE_NOW = new Date("2026-01-01"); // before the deprecate date
const DEPRECATED_NOW = new Date("2031-06-01"); // past deprecate, before disallow
const VIOLATION_NOW = new Date("2036-06-01"); // past disallow

describe("mandate catalog", () => {
  it("bundles the dated mandates with one deprecate + one disallow clause each", () => {
    assert.ok(mandateIds().includes("cnsa-2.0"));
    assert.ok(mandateIds().includes("nist-ir-8547"));
    for (const id of ["cnsa-2.0", "nist-ir-8547"]) {
      const mandate = getMandate(id);
      assert.ok(mandate, `${id} exists`);
      assert.equal(mandate.rules.length, 2);
      assert.equal(mandate.rules.filter((r) => r.tier === "deprecate").length, 1);
      assert.equal(mandate.rules.filter((r) => r.tier === "disallow").length, 1);
    }
    assert.equal(getMandate("nope"), undefined);
  });

  it("prohibits the standalone classical families but not the hybrid legs", () => {
    // X25519/X448 are the classical half of the recommended hybrid
    // (X25519MLKEM768); a static scan cannot tell standalone use from the
    // hybrid leg, so the clauses must not prohibit them.
    for (const mandate of Object.values(MANDATES)) {
      for (const rule of mandate.rules) {
        for (const family of ["RSA", "ECDH", "ECDSA", "EdDSA", "DH", "DSA", "ECIES"]) {
          assert.ok(rule.prohibits.includes(family as never), `${rule.clause} covers ${family}`);
        }
        assert.ok(!rule.prohibits.includes("X25519"), `${rule.clause} excludes X25519`);
        assert.ok(!rule.prohibits.includes("X448"), `${rule.clause} excludes X448`);
      }
    }
  });
});

describe("assertKnownMandates", () => {
  it("accepts known ids and the empty list", () => {
    assertKnownMandates([]);
    assertKnownMandates(["cnsa-2.0", "nist-ir-8547"]);
  });
  it("throws listing the unknown ids and the known catalog", () => {
    assert.throws(
      () => assertKnownMandates(["cnsa-2.0", "bogus"]),
      (err: Error) =>
        err instanceof Error && /bogus/.test(err.message) && /cnsa-2\.0/.test(err.message),
    );
  });
});

describe("evaluateMandates", () => {
  it("marks a prohibited family DUE before the deprecate date", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW);
    assert.deepEqual(ev.summary, { conformant: 0, due: 1, deprecated: 0, violation: 0 });
    assert.equal(ev.notInScope, 0);
    assert.equal(ev.hasViolation, false);
    const v = ev.findings[0];
    assert.equal(v.status, "due");
    // The governing clause of a due finding is the next upcoming (deprecate) one.
    assert.match(v.clause, /deprecate/);
    assert.equal(v.effective, "2030-12-31");
    assert.ok(v.monthsUntil > 0);
    // ...but the disallow clause is carried alongside for the gate.
    assert.equal(v.disallowEffective, "2035-12-31");
    assert.ok(v.monthsUntilDisallow !== null && v.monthsUntilDisallow > v.monthsUntil);
    assert.equal(ev.nextDeadline, "2030-12-31");
  });

  it("marks it DEPRECATED (warn tier) once the deprecate date has passed", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], DEPRECATED_NOW);
    assert.deepEqual(ev.summary, { conformant: 0, due: 0, deprecated: 1, violation: 0 });
    assert.equal(ev.hasViolation, false);
    const v = ev.findings[0];
    assert.equal(v.status, "deprecated");
    // Surfaces the DEPRECATE clause (now in the past)...
    assert.match(v.clause, /deprecate/);
    assert.equal(v.effective, "2030-12-31");
    assert.ok(v.monthsUntil < 0);
    // ...while the disallow deadline is still ahead and is the next deadline.
    assert.ok(v.monthsUntilDisallow !== null && v.monthsUntilDisallow > 0);
    assert.equal(ev.nextDeadline, "2035-12-31");
  });

  it("treats the deprecate effective date itself as passed", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], new Date("2030-12-31T00:00:00Z"));
    assert.equal(ev.findings[0].status, "deprecated");
  });

  it("marks it a VIOLATION once the disallow date has passed", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], VIOLATION_NOW);
    assert.deepEqual(ev.summary, { conformant: 0, due: 0, deprecated: 0, violation: 1 });
    assert.equal(ev.hasViolation, true);
    const v = ev.findings[0];
    assert.equal(v.status, "violation");
    // Surfaces the DISALLOW clause, not the deprecate one.
    assert.match(v.clause, /disallow/);
    assert.equal(v.effective, "2035-12-31");
    assert.ok(v.monthsUntilDisallow !== null && v.monthsUntilDisallow < 0);
    assert.equal(ev.nextDeadline, null);
  });

  it("leaves a hybrid-leg family (X25519) conformant with no row", () => {
    const ev = evaluateMandates([f("X25519", 2)], ["cnsa-2.0"], DUE_NOW);
    assert.deepEqual(ev.summary, { conformant: 1, due: 0, deprecated: 0, violation: 0 });
    assert.equal(ev.notInScope, 0);
    assert.deepEqual(ev.findings, []);
  });

  it("excludes non-asymmetric findings from the summary as notInScope", () => {
    // Hash / RNG / dependency / TLS-version findings carry no classical
    // asymmetric family; a PQC-asymmetric mandate does not adjudicate them and
    // they must not inflate the conformant count.
    const ev = evaluateMandates([f("unknown", 3), f(undefined, 4)], ["cnsa-2.0"], DUE_NOW);
    assert.deepEqual(ev.summary, { conformant: 0, due: 0, deprecated: 0, violation: 0 });
    assert.equal(ev.notInScope, 2);
    assert.deepEqual(ev.findings, []);
  });

  it("emits one row per prohibited finding x mandate", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0", "nist-ir-8547"], DUE_NOW);
    assert.equal(ev.findings.length, 2);
    assert.equal(ev.summary.due, 1);
  });

  it("ignores unknown mandate ids (assertKnownMandates is the loud path)", () => {
    const ev = evaluateMandates([rsa], ["bogus"], DUE_NOW);
    assert.deepEqual(ev.mandates, []);
    assert.deepEqual(ev.findings, []);
    assert.equal(ev.summary.conformant, 1);
  });
});

describe("evaluateMandates + org policy composition", () => {
  it("carries no policy signal when no policy is supplied", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW);
    assert.equal(ev.policyName, null);
    assert.equal(ev.acknowledged, 0);
    assert.equal(ev.findings[0].policyVerdict, null);
    assert.equal(ev.findings[0].acknowledged, false);
  });

  it("annotates each row with the org verdict + acknowledged and tallies the count", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, transitionRsa);
    assert.equal(ev.policyName, "org");
    assert.equal(ev.acknowledged, 1);
    const v = ev.findings[0];
    assert.equal(v.policyVerdict, "transition-pending");
    assert.equal(v.acknowledged, true);
    // The mandate STATUS is unchanged by the policy — acknowledgement is additive.
    assert.equal(v.status, "due");
    assert.deepEqual(ev.summary, { conformant: 0, due: 1, deprecated: 0, violation: 0 });
  });

  it("acknowledges a permitted family but not a prohibited one", () => {
    const permitted = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, permitRsa);
    assert.equal(permitted.findings[0].acknowledged, true);
    assert.equal(permitted.findings[0].policyVerdict, "conformant");

    const prohibited = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, prohibitRsa);
    assert.equal(prohibited.acknowledged, 0);
    assert.equal(prohibited.findings[0].acknowledged, false);
    assert.equal(prohibited.findings[0].policyVerdict, "violation");
  });

  it("does not acknowledge a family the policy also PROHIBITS (prohibited wins)", () => {
    // A plausible merge of two policy fragments lists RSA in both lists. The
    // verdict must resolve to violation AND not be acknowledged — otherwise the
    // row is self-contradictory (verdict violation, yet exempt from the gate).
    const overlap: CryptoPolicy = { name: "org", prohibited: ["RSA"], permitted: ["RSA"] };
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, overlap);
    assert.equal(ev.findings[0].policyVerdict, "violation");
    assert.equal(ev.findings[0].acknowledged, false);
    assert.equal(ev.acknowledged, 0);
    assert.equal(mandateGateFails(ev, { failNow: true }), true, "still trips --fail-now");
  });

  it("does not acknowledge an unlisted family under a permissive defaultVerdict", () => {
    // defaultVerdict:"conformant" yields a non-violation policyVerdict, but silence
    // is not consent: the family is not explicitly managed, so it is NOT exempt.
    const permissive: CryptoPolicy = { name: "org", defaultVerdict: "conformant" };
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, permissive);
    assert.equal(ev.findings[0].policyVerdict, "conformant");
    assert.equal(ev.findings[0].acknowledged, false);
    assert.equal(ev.acknowledged, 0);
    assert.equal(mandateGateFails(ev, { failNow: true }), true, "unmanaged crypto still fails");
  });

  it("tallies acknowledgement per FINDING, not per row (one finding × two mandates)", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0", "nist-ir-8547"], DUE_NOW, permitRsa);
    assert.equal(ev.findings.length, 2, "two verdict rows (one per mandate)");
    assert.equal(ev.acknowledged, 1, "but one distinct acknowledged finding");
    assert.ok(
      ev.findings.every((v) => v.acknowledged),
      "every row still carries the flag",
    );
  });
});

describe("mandateGateFails (deadline-aware default)", () => {
  it("does not fail while every deadline is ahead", () => {
    assert.equal(mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW)), false);
  });
  it("does not fail on the deprecated warn tier by default", () => {
    // Past the deprecate date but before disallow: surface, warn, don't fail.
    assert.equal(mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], DEPRECATED_NOW)), false);
  });
  it("fails once the disallow deadline has passed", () => {
    assert.equal(mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], VIOLATION_NOW)), true);
  });
  it("failNow fails on any prohibited finding, but not on conformant-only scans", () => {
    assert.equal(
      mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW), { failNow: true }),
      true,
    );
    assert.equal(
      mandateGateFails(evaluateMandates([f("X25519", 5)], ["cnsa-2.0"], DUE_NOW), {
        failNow: true,
      }),
      false,
    );
  });
  it("leadMonths measures to the DISALLOW date, not the deprecate date", () => {
    // 2029-08-01: ~17 months to deprecate (2030-12-31) but ~77 to disallow
    // (2035-12-31). A 24-month lead window must NOT fail (disallow is far out).
    const due = evaluateMandates([rsa], ["cnsa-2.0"], new Date("2029-08-01"));
    assert.equal(mandateGateFails(due, { leadMonths: 24 }), false);
    assert.equal(mandateGateFails(due, { leadMonths: 80 }), true);
  });
  it("leadMonths fails a deprecated finding when disallow is within the window", () => {
    // 2035-08-01: deprecated (past 2030-12-31), ~5 months to 2035-12-31.
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], new Date("2035-08-01"));
    assert.equal(ev.findings[0].status, "deprecated");
    assert.equal(mandateGateFails(ev, { leadMonths: 6 }), true);
    assert.equal(mandateGateFails(ev, { leadMonths: 3 }), false);
  });
});

describe("mandateGateFails + org policy composition", () => {
  it("failNow exempts a policy-acknowledged finding but not an unacknowledged one", () => {
    // inTransition RSA → acknowledged → --fail-now must not trip on it.
    const ack = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, transitionRsa);
    assert.equal(mandateGateFails(ack, { failNow: true }), false);
    // prohibited RSA → not acknowledged → --fail-now still fails.
    const unack = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, prohibitRsa);
    assert.equal(mandateGateFails(unack, { failNow: true }), true);
  });

  it("leadMonths exempts a policy-acknowledged finding", () => {
    // A wide window that would otherwise trip (permitted → acknowledged → exempt).
    const ack = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW, permitRsa);
    assert.equal(mandateGateFails(ack, { leadMonths: 240 }), false);
    const unack = evaluateMandates([rsa], ["cnsa-2.0"], DUE_NOW);
    assert.equal(mandateGateFails(unack, { leadMonths: 240 }), true);
  });

  it("still fails a passed DISALLOW deadline even when the policy acknowledges it", () => {
    // An org cannot self-exempt from a dated legal disallow: the hard floor wins.
    const ack = evaluateMandates([rsa], ["cnsa-2.0"], VIOLATION_NOW, permitRsa);
    assert.equal(ack.findings[0].acknowledged, true);
    assert.equal(mandateGateFails(ack), true);
    assert.equal(mandateGateFails(ack, { failNow: true }), true);
    // ...and under every early-gate option, including leadMonths.
    assert.equal(mandateGateFails(ack, { leadMonths: 6 }), true);
  });
});
