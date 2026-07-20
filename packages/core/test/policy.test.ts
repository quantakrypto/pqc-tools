/**
 * Tests for the cryptography-policy → per-finding verdicts (A.8.24 evidence §4):
 * the mapping logic, the strict policy parser, and that the verdicts are part of
 * the attested (hashed) evidence body.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildPolicyMapping, buildReadinessReport, parseCryptoPolicy } from "../src/index.js";
import { verdictForAlgorithm } from "../src/policy.js";
import type { CryptoPolicy, Finding, ScanResult } from "../src/index.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "node-crypto-keygen",
    title: "RSA key generation",
    category: "kem",
    severity: "high",
    confidence: "high",
    algorithm: "RSA",
    hndl: true,
    message: "RSA is not quantum-safe.",
    location: { file: "src/a.ts", line: 1, snippet: "x" },
    ...over,
  };
}

test("verdictForAlgorithm resolves prohibited / in-transition / permitted / default", () => {
  const policy: CryptoPolicy = {
    prohibited: ["RSA"],
    inTransition: ["ECDH"],
    permitted: ["EdDSA"],
  };
  assert.equal(verdictForAlgorithm("RSA", policy).verdict, "violation");
  assert.equal(verdictForAlgorithm("ECDH", policy).verdict, "transition-pending");
  assert.equal(verdictForAlgorithm("EdDSA", policy).verdict, "conformant");
  // Unnamed family → default (permit-list posture): violation.
  assert.equal(verdictForAlgorithm("DSA", policy).verdict, "violation");
  // Configurable default.
  assert.equal(
    verdictForAlgorithm("DSA", { ...policy, defaultVerdict: "transition-pending" }).verdict,
    "transition-pending",
  );
});

test("prohibited wins over in-transition and permitted for the same family", () => {
  const policy: CryptoPolicy = { prohibited: ["RSA"], inTransition: ["RSA"], permitted: ["RSA"] };
  assert.equal(verdictForAlgorithm("RSA", policy).verdict, "violation");
});

test("buildPolicyMapping tallies verdicts and records policy metadata", () => {
  const policy: CryptoPolicy = {
    name: "p1",
    prohibited: ["RSA", "DH"],
    inTransition: ["ECDH"],
    transitionDeadline: "2030-01-01",
  };
  const findings = [
    finding({ algorithm: "RSA" }),
    finding({ algorithm: "DH", ruleId: "node-crypto-dh" }),
    finding({ algorithm: "ECDH", ruleId: "node-crypto-ecdh" }),
  ];
  const pm = buildPolicyMapping(findings, policy);
  assert.equal(pm.policyName, "p1");
  assert.equal(pm.transitionDeadline, "2030-01-01");
  assert.deepEqual(pm.summary, { conformant: 0, violation: 2, "transition-pending": 1 });
  assert.equal(pm.findings.length, 3);
  assert.equal(pm.findings[0].verdict, "violation");
});

test("a finding with no algorithm maps as 'unknown'", () => {
  const pm = buildPolicyMapping([finding({ algorithm: undefined })], { prohibited: ["unknown"] });
  assert.equal(pm.findings[0].algorithm, "unknown");
  assert.equal(pm.findings[0].verdict, "violation");
});

test("parseCryptoPolicy validates families and rejects malformed input", () => {
  const ok = parseCryptoPolicy({ name: "x", prohibited: ["RSA"], defaultVerdict: "conformant" });
  assert.deepEqual(ok.prohibited, ["RSA"]);
  assert.equal(ok.defaultVerdict, "conformant");
  assert.throws(() => parseCryptoPolicy([]), /must be a JSON object/);
  assert.throws(() => parseCryptoPolicy({ prohibited: ["BOGUS"] }), /unknown algorithm family/);
  assert.throws(() => parseCryptoPolicy({ permitted: "RSA" }), /must be an array/);
  assert.throws(() => parseCryptoPolicy({ defaultVerdict: "maybe" }), /defaultVerdict/);
});

function scanResult(findings: Finding[]): ScanResult {
  return {
    root: ".",
    findings,
    filesScanned: 1,
    inventory: {
      byAlgorithm: {},
      byCategory: {},
      bySeverity: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0 },
      hndlCount: findings.length,
      readinessScore: 50,
    },
    startedAt: "2024-01-01T00:00:00.000Z",
    finishedAt: "2024-01-01T00:00:01.000Z",
    toolVersion: "0.0.0",
  };
}

test("evidence report includes policyMapping only when a policy is supplied", () => {
  const result = scanResult([finding({ algorithm: "RSA" })]);
  assert.equal(buildReadinessReport(result).policyMapping, undefined);
  const withPolicy = buildReadinessReport(result, { policy: { prohibited: ["RSA"] } });
  assert.ok(withPolicy.policyMapping);
  assert.equal(withPolicy.policyMapping.summary.violation, 1);
});

test("the policy verdict is part of the attested content hash", () => {
  // Same scan, different policy → different attested hash (the verdict is evidence).
  const result = scanResult([finding({ algorithm: "RSA" })]);
  const asViolation = buildReadinessReport(result, { policy: { prohibited: ["RSA"] } });
  const asConformant = buildReadinessReport(result, { policy: { permitted: ["RSA"] } });
  assert.notEqual(asViolation.attestation.contentHash, asConformant.attestation.contentHash);
  // And it stays deterministic for the same (result, policy).
  const again = buildReadinessReport(result, { policy: { prohibited: ["RSA"] } });
  assert.equal(asViolation.attestation.contentHash, again.attestation.contentHash);
});
