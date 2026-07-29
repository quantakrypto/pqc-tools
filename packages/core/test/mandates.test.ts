import { describe, it, expect } from "vitest";
import { evaluateMandates, mandateGateFails, getMandate, mandateIds } from "../src/mandates.js";
import type { Finding } from "../src/types.js";

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

describe("mandate catalog", () => {
  it("bundles the dated mandates", () => {
    expect(mandateIds()).toEqual(expect.arrayContaining(["cnsa-2.0", "nist-ir-8547"]));
    expect(getMandate("cnsa-2.0")?.rules.length).toBe(2);
    expect(getMandate("nope")).toBeUndefined();
  });
});

describe("evaluateMandates", () => {
  it("marks a prohibited family DUE before the deadline", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], new Date("2026-01-01"));
    expect(ev.summary).toEqual({ conformant: 0, due: 1, violation: 0 });
    expect(ev.hasViolation).toBe(false);
    expect(ev.findings[0].status).toBe("due");
    expect(ev.findings[0].effective).toBe("2030-01-01");
    expect(ev.findings[0].monthsUntil).toBeGreaterThan(0);
    expect(ev.nextDeadline).toBe("2030-01-01");
  });

  it("marks it a VIOLATION once the deadline has passed", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], new Date("2031-01-01"));
    expect(ev.summary.violation).toBe(1);
    expect(ev.hasViolation).toBe(true);
    expect(ev.findings[0].status).toBe("violation");
    expect(ev.findings[0].monthsUntil).toBeLessThan(0);
  });

  it("leaves a non-prohibited family conformant with no row", () => {
    const ev = evaluateMandates([f("unknown", 3)], ["cnsa-2.0"], new Date("2026-01-01"));
    expect(ev.summary.conformant).toBe(1);
    expect(ev.findings).toEqual([]);
  });

  it("emits one row per prohibited finding x mandate", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0", "nist-ir-8547"], new Date("2026-01-01"));
    expect(ev.findings.length).toBe(2);
    expect(ev.summary.due).toBe(1);
  });

  it("ignores unknown mandate ids", () => {
    const ev = evaluateMandates([rsa], ["bogus"], new Date("2026-01-01"));
    expect(ev.mandates).toEqual([]);
    expect(ev.findings).toEqual([]);
    expect(ev.summary.conformant).toBe(1);
  });
});

describe("mandateGateFails (deadline-aware default)", () => {
  it("does not fail on a future deadline", () => {
    expect(mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], new Date("2026-01-01")))).toBe(
      false,
    );
  });
  it("fails once a deadline has passed", () => {
    expect(mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], new Date("2031-01-01")))).toBe(
      true,
    );
  });
  it("failNow fails on any prohibited finding", () => {
    expect(
      mandateGateFails(evaluateMandates([rsa], ["cnsa-2.0"], new Date("2026-01-01")), {
        failNow: true,
      }),
    ).toBe(true);
  });
  it("leadMonths fails when the deadline is within the window", () => {
    const ev = evaluateMandates([rsa], ["cnsa-2.0"], new Date("2029-08-01"));
    expect(mandateGateFails(ev, { leadMonths: 6 })).toBe(true);
    expect(mandateGateFails(ev, { leadMonths: 3 })).toBe(false);
  });
});
