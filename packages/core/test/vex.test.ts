/**
 * OpenVEX export: one statement per rule, `affected` status, deterministic doc,
 * and `--triage` verdicts surfaced in `status_notes`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toOpenVex } from "../src/index.js";
import type { Finding, ScanResult, TriageAnnotation } from "../src/index.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "rsa-keygen",
    title: "RSA key generation",
    category: "kem",
    severity: "high",
    confidence: "high",
    algorithm: "RSA",
    hndl: true,
    message: "RSA is not quantum-safe.",
    remediation: "Use ML-KEM-768 (hybrid X25519MLKEM768).",
    location: { file: "src/a.ts", line: 3 },
    ...over,
  };
}

function resultWith(findings: Finding[], finishedAt = "2026-01-01T00:00:01Z"): ScanResult {
  return {
    root: "/repo",
    findings,
    filesScanned: findings.length,
    inventory: {
      byAlgorithm: {},
      byCategory: {},
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      hndlCount: 0,
      readinessScore: 0,
    },
    startedAt: "2026-01-01T00:00:00Z",
    finishedAt,
    toolVersion: "1.0.0",
  };
}

test("emits a valid OpenVEX 0.2.0 envelope", () => {
  const doc = toOpenVex(resultWith([finding()]));
  assert.equal(doc["@context"], "https://openvex.dev/ns/v0.2.0");
  assert.match(doc["@id"], /^https:\/\/quantakrypto\.com\/vex\/[0-9a-f]{16}$/);
  assert.equal(doc.author, "qScan");
  assert.equal(doc.timestamp, "2026-01-01T00:00:01Z");
  assert.equal(doc.version, 1);
});

test("one statement per rule, status affected, remediation as action_statement", () => {
  const doc = toOpenVex(resultWith([finding()]));
  assert.equal(doc.statements.length, 1);
  const s = doc.statements[0]!;
  assert.equal(s.vulnerability.name, "QK-rsa-keygen");
  assert.equal(s.vulnerability.description, "RSA is not quantum-safe.");
  assert.equal(s.status, "affected");
  assert.match(s.action_statement ?? "", /ML-KEM-768/);
  assert.equal(s.status_notes, undefined, "no triage → no status_notes");
});

test("products are de-duplicated, sorted, and cover every occurrence of the rule", () => {
  const doc = toOpenVex(
    resultWith([
      finding({ location: { file: "src/b.ts", line: 9 } }),
      finding({ location: { file: "src/a.ts", line: 3 } }),
      finding({ location: { file: "src/a.ts", line: 3 } }), // duplicate
    ]),
  );
  assert.deepEqual(
    doc.statements[0]!.products.map((p) => p["@id"]),
    ["src/a.ts:3", "src/b.ts:9"],
    "products deduped and sorted",
  );
});

test("statements are grouped by rule and sorted by vulnerability name", () => {
  const doc = toOpenVex(
    resultWith([
      finding({ ruleId: "ecdh-usage", category: "key-exchange", algorithm: "ECDH" }),
      finding({ ruleId: "rsa-keygen" }),
    ]),
  );
  assert.deepEqual(
    doc.statements.map((s) => s.vulnerability.name),
    ["QK-ecdh-usage", "QK-rsa-keygen"],
  );
});

test("a --triage verdict is surfaced in status_notes (most-exposed wins)", () => {
  const triage = (
    exposureScore: number,
    priority: TriageAnnotation["priority"],
  ): TriageAnnotation => ({
    exposureScore,
    priority,
    rationale: `exposure ${exposureScore}`,
  });
  const doc = toOpenVex(
    resultWith([
      finding({ location: { file: "src/a.ts", line: 3 }, triage: triage(20, "later") }),
      finding({ location: { file: "src/b.ts", line: 9 }, triage: triage(80, "now") }),
    ]),
  );
  const s = doc.statements[0]!;
  assert.match(s.status_notes ?? "", /exposure 80\/100/, "the most-exposed verdict is reported");
  assert.match(s.status_notes ?? "", /priority now/);
});

test("VEX export is deterministic across scan time but changes with the finding set", () => {
  const a = toOpenVex(resultWith([finding()], "2026-01-01T00:00:01Z"));
  const b = toOpenVex(resultWith([finding()], "2026-09-09T09:09:09Z"));
  const c = toOpenVex(resultWith([finding({ ruleId: "ecdsa-usage" })]));
  assert.equal(a["@id"], b["@id"], "same findings, different scan time → same @id");
  assert.notEqual(a["@id"], c["@id"], "different findings → different @id");
});

test("a clean scan yields an empty statements array (still a valid VEX doc)", () => {
  const doc = toOpenVex(resultWith([]));
  assert.deepEqual(doc.statements, []);
  assert.equal(doc["@context"], "https://openvex.dev/ns/v0.2.0");
});

test("a finding without remediation falls back to a generic PQC action_statement", () => {
  const doc = toOpenVex(resultWith([finding({ remediation: undefined })]));
  assert.match(doc.statements[0]!.action_statement ?? "", /FIPS 203\/204\/205/);
});
