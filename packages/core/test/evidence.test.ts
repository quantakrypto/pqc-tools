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
