/**
 * ISO A.8.24 readiness-report evidence: the report is well-formed, embeds the
 * inventory + CBOM, and its attestation content hash is DETERMINISTIC per
 * (commit, config) — the volatile scan time is excluded so re-running the same
 * scan on the same commit yields a verifiable, reproducible hash.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildReadinessReport,
  buildInventory,
  evaluateMandates,
  signReadinessReport,
  verifyReadinessReport,
} from "../src/index.js";
import type { EvidenceSigner, Finding, ReadinessReport, ScanResult } from "../src/index.js";

function resultWith(finishedAt: string): ScanResult {
  const finding: Finding = {
    ruleId: "rsa-keygen",
    title: "RSA",
    category: "kem",
    severity: "high",
    confidence: "high",
    hndl: true,
    algorithm: "RSA",
    message: "RSA is classical",
    location: { file: "a.ts", line: 1 },
  };
  return {
    root: "/repo",
    findings: [finding],
    filesScanned: 1,
    inventory: buildInventory([finding]),
    startedAt: "2026-01-01T00:00:00Z",
    finishedAt,
    toolVersion: "0.4.3",
  };
}

test("readiness report is well-formed and embeds inventory + CBOM", () => {
  const r = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), {
    repository: "quantakrypto/demo",
    commit: "abc",
  });
  assert.equal(r.reportType, "quantakrypto-readiness");
  assert.equal(r.subject.repository, "quantakrypto/demo");
  assert.equal(r.subject.commit, "abc");
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0]?.ruleId, "rsa-keygen");
  assert.ok(r.inventory.readinessScore >= 0);
  assert.ok(r.cbom, "CBOM is embedded");
  assert.match(r.attestation.contentHash, /^sha256:[0-9a-f]{64}$/);
  // Signing/timestamping is external (ADR-0004) — left null for a vetted signer.
  assert.equal(r.attestation.signature, null);
  assert.equal(r.attestation.timestamp, null);
});

test("content hash is reproducible across scan time but changes with the commit", () => {
  const a = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c1" });
  const b = buildReadinessReport(resultWith("2026-06-06T06:06:06Z"), { commit: "c1" });
  const c = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c2" });
  // Same commit, different scan time → identical hash (reproducible evidence).
  assert.equal(a.attestation.contentHash, b.attestation.contentHash);
  assert.notEqual(a.subject.scanTimeUtc, b.subject.scanTimeUtc);
  // Different commit → different hash.
  assert.notEqual(a.attestation.contentHash, c.attestation.contentHash);
});

test("mandateMapping is date-pinned, hashed, and reproducible across the whole day", () => {
  const result = resultWith("2026-01-01T00:00:01Z"); // RSA finding — mandate-prohibited.
  // 2026-01-14 is a month-rounding boundary day: before `now` was pinned to UTC
  // midnight, an early-morning and a late-evening run rounded monthsUntilDisallow
  // differently and produced DIFFERENT hashes. Use the two extremes of the day.
  const early = evaluateMandates(result.findings, ["cnsa-2.0"], new Date("2026-01-14T00:30:00Z"));
  const late = evaluateMandates(result.findings, ["cnsa-2.0"], new Date("2026-01-14T23:30:00Z"));
  const a = buildReadinessReport(result, { commit: "c1", mandate: early });
  const b = buildReadinessReport(
    resultWith("2026-06-06T06:06:06Z"), // different scan time, same commit + same mandate day
    { commit: "c1", mandate: late },
  );
  // The stored `now` is a plain date, not the full timestamp it was evaluated at.
  assert.equal(a.mandateMapping?.now, "2026-01-14");
  assert.match(a.mandateMapping?.now ?? "", /^\d{4}-\d{2}-\d{2}$/);
  // Same commit + same compliance DAY → identical attestation hash, at any hour.
  assert.equal(a.attestation.contentHash, b.attestation.contentHash);
  assert.equal(verifyReadinessReport(a).valid, true);
});

test("a mandateMapping changes the attestation hash and is tamper-evident", () => {
  const result = resultWith("2026-01-01T00:00:01Z");
  const withoutMandate = buildReadinessReport(result, { commit: "c1" });
  const ev = evaluateMandates(result.findings, ["cnsa-2.0"], new Date("2026-01-01"));
  const withMandate = buildReadinessReport(result, { commit: "c1", mandate: ev });
  // Adding the attested mandate verdicts changes the hashed body.
  assert.notEqual(withoutMandate.attestation.contentHash, withMandate.attestation.contentHash);
  // …and the mapping is covered by the hash: editing a verdict fails verification.
  const tampered = JSON.parse(JSON.stringify(withMandate)) as ReadinessReport;
  tampered.mandateMapping!.summary.violation = 99;
  assert.equal(verifyReadinessReport(tampered).valid, false);
});

test("a mandate evaluated after a deadline attests a different status + hash", () => {
  const result = resultWith("2026-01-01T00:00:01Z");
  const due = evaluateMandates(result.findings, ["cnsa-2.0"], new Date("2026-01-01")); // pre-deadline
  const violated = evaluateMandates(result.findings, ["cnsa-2.0"], new Date("2036-06-01")); // post-disallow
  const a = buildReadinessReport(result, { commit: "c1", mandate: due });
  const b = buildReadinessReport(result, { commit: "c1", mandate: violated });
  assert.equal(a.mandateMapping?.hasViolation, false);
  assert.equal(b.mandateMapping?.hasViolation, true);
  // A genuinely different compliance date → a different attestation hash.
  assert.notEqual(a.attestation.contentHash, b.attestation.contentHash);
});

/** A fake signer that records what it was asked to sign; no crypto, no I/O. */
function fakeSigner(label: string, sink?: { payload?: string }): EvidenceSigner {
  return {
    label,
    sign(payload) {
      if (sink) sink.payload = payload;
      return `SIG(${payload})`;
    },
  };
}

test("signReadinessReport fills the attestation from an external signer over the contentHash", async () => {
  const base = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c1" });
  assert.equal(base.attestation.signature, null);
  const seen = {};
  const signed = await signReadinessReport(base, { signer: fakeSigner("openssl", seen) });
  // The signer receives EXACTLY the contentHash and its output is recorded verbatim.
  assert.equal(seen.payload, base.attestation.contentHash);
  assert.equal(signed.attestation.signature, `SIG(${base.attestation.contentHash})`);
  assert.equal(signed.attestation.signedWith, "openssl");
  // Signing never changes the hashed body → contentHash is stable.
  assert.equal(signed.attestation.contentHash, base.attestation.contentHash);
  // The input report is not mutated.
  assert.equal(base.attestation.signature, null);
});

test("signReadinessReport can attach a timestamp independently of a signature", async () => {
  const base = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c1" });
  const tsOnly = await signReadinessReport(base, { timestamper: fakeSigner("openssl-ts") });
  assert.equal(tsOnly.attestation.timestamp, `SIG(${base.attestation.contentHash})`);
  assert.equal(tsOnly.attestation.timestampedWith, "openssl-ts");
  assert.equal(tsOnly.attestation.signature, null, "no --sign → signature stays null");
});

test("signReadinessReport with no signers is a no-op", async () => {
  const base = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c1" });
  const same = await signReadinessReport(base, {});
  assert.equal(same.attestation.signature, null);
  assert.equal(same.attestation.timestamp, null);
});

test("signReadinessReport awaits an ASYNC signer (KMS/TSA-over-HTTP shape)", async () => {
  const base = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c1" });
  const asyncSigner: EvidenceSigner = {
    label: "kms",
    sign: async (payload) => Promise.resolve(`ASYNC(${payload})`),
  };
  const signed = await signReadinessReport(base, { signer: asyncSigner });
  assert.equal(signed.attestation.signature, `ASYNC(${base.attestation.contentHash})`);
  assert.equal(signed.attestation.signedWith, "kms");
});

/* ----------------------------- verification ------------------------------- */

/** Deep-clone a report so a tamper test never mutates the original. */
function clone(r: ReadinessReport): ReadinessReport {
  return JSON.parse(JSON.stringify(r)) as ReadinessReport;
}

test("verifyReadinessReport accepts an untampered report", () => {
  const r = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), {
    repository: "quantakrypto/demo",
    commit: "abc",
  });
  const v = verifyReadinessReport(r);
  assert.equal(v.valid, true);
  assert.equal(v.computedHash, r.attestation.contentHash);
  assert.equal(v.claimedHash, r.attestation.contentHash);
  assert.equal(v.reason, undefined);
});

test("verifyReadinessReport still accepts a report after it is signed", async () => {
  // Signing mutates only the (excluded) attestation block, so verification of the
  // integrity hash must still pass on the signed artifact.
  const base = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "c1" });
  const signed = await signReadinessReport(base, { signer: fakeSigner("openssl") });
  assert.equal(verifyReadinessReport(signed).valid, true);
});

test("verifyReadinessReport REJECTS a report whose finding was tampered with", () => {
  const r = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "abc" });
  // Silently downgrade the recorded finding's severity while leaving the claimed
  // contentHash in place — the classic "edit the evidence" attack.
  const tampered = clone(r);
  assert.equal(tampered.findings[0]?.severity, "high");
  tampered.findings[0]!.severity = "low";
  const v = verifyReadinessReport(tampered);
  assert.equal(v.valid, false);
  assert.notEqual(v.computedHash, v.claimedHash);
  assert.equal(v.claimedHash, r.attestation.contentHash, "the stale claimed hash is preserved");
  assert.match(v.reason ?? "", /mismatch/i);
});

test("verifyReadinessReport REJECTS a tampered inventory or subject commit", () => {
  const r = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "abc" });

  const inv = clone(r);
  inv.inventory.readinessScore = 100;
  assert.equal(verifyReadinessReport(inv).valid, false, "inventory is covered by the hash");

  const commit = clone(r);
  commit.subject.commit = "def";
  assert.equal(verifyReadinessReport(commit).valid, false, "subject commit is covered by the hash");
});

test("verifyReadinessReport IGNORES changes to excluded fields (scan time, CBOM, attestation)", () => {
  const r = buildReadinessReport(resultWith("2026-01-01T00:00:01Z"), { commit: "abc" });

  const time = clone(r);
  time.subject.scanTimeUtc = "2030-12-31T23:59:59Z";
  assert.equal(verifyReadinessReport(time).valid, true, "scan time is excluded from the hash");

  const cbom = clone(r);
  cbom.cbom = { tampered: true };
  assert.equal(verifyReadinessReport(cbom).valid, true, "CBOM envelope is excluded from the hash");

  const att = clone(r);
  att.attestation.signature = "forged-signature";
  assert.equal(
    verifyReadinessReport(att).valid,
    true,
    "attestation block is excluded from the hash",
  );
});
