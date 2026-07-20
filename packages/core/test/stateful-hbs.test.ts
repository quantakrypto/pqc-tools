/**
 * Unit tests for the stateful hash-based signature detector (NIST SP 800-208:
 * LMS / HSS / XMSS / XMSSMT).
 *
 * These schemes are quantum-SAFE and NIST-approved, so — unlike every other
 * detector — a finding here is NOT a "broken crypto" verdict and is NEVER
 * harvest-now-decrypt-later (`hndl:false`). The hazard flagged is STATE reuse.
 * The tests pin that invariant, each distinctive token's rule, the SP 800-208
 * SHAKE256 / 192-bit variants, and the no-double-count boundary between XMSS
 * and XMSSMT.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function hbs(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.ruleId.startsWith("stateful-hbs-"));
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("LMS parameter sets fire (SHA-256, SP 800-208 SHAKE + 192-bit M24)", () => {
  assert.ok(rule(run("fw.c", "#define LMS_TYPE LMS_SHA256_M32_H10"), "stateful-hbs-lms-param"));
  // SP 800-208 additions: SHAKE256 and the 192-bit M24/N24 parameter sets.
  assert.ok(
    rule(run("fw.c", "use LMS_SHAKE256_M24_H10"), "stateful-hbs-lms-param"),
    "SHAKE256 M24",
  );
  assert.ok(
    rule(run("fw.c", "LMS_SHAKE_M32_W8"), "stateful-hbs-lms-param"),
    "SHAKE (RFC-8554 spelling)",
  );
});

test("HSS keygen and the pyhsslms library token fire", () => {
  assert.ok(
    rule(
      run("keys.py", "priv = pyhsslms.hss_generate_private_key(levels=2)"),
      "stateful-hbs-hss-keygen",
    ),
  );
  assert.ok(rule(run("keys.py", "import pyhsslms"), "stateful-hbs-pyhsslms"));
});

test("XMSS parameter sets fire (SHA2 + SP 800-208 SHAKE256, 256- and 192-bit)", () => {
  assert.ok(rule(run("boot.go", 'algo := "XMSS-SHA2_10_256"'), "stateful-hbs-xmss-param"));
  assert.ok(
    rule(run("boot.go", "XMSS-SHAKE256_16_192"), "stateful-hbs-xmss-param"),
    "SHAKE256 192-bit",
  );
});

test("XMSSMT fires as XMSSMT — NOT double-counted as XMSS", () => {
  const findings = run("boot.rs", 'let p = "XMSSMT-SHA2_20/2_256";');
  assert.ok(rule(findings, "stateful-hbs-xmssmt-param"), "the XMSSMT rule fires");
  assert.equal(
    rule(findings, "stateful-hbs-xmss-param"),
    undefined,
    "the XMSS rule must NOT also match an XMSSMT string",
  );
});

test("XMSS keypair generation call fires", () => {
  assert.ok(rule(run("sig.c", "xmss_keypair(pk, sk, oid);"), "stateful-hbs-xmss-keypair"));
});

test("every stateful-HBS finding is quantum-safe-but-stateful: signature, medium, NOT hndl", () => {
  // Fold every rule's trigger into one file and assert the shared invariant.
  const content = [
    "LMS_SHA256_M32_H10",
    "hss_generate_private_key",
    "pyhsslms",
    "XMSS-SHA2_10_256",
    "XMSSMT-SHAKE256_20/2_256",
    "xmss_keypair",
  ].join("\n");
  const found = hbs(run("all.txt", content));
  const ids = found.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, [
    "stateful-hbs-hss-keygen",
    "stateful-hbs-lms-param",
    "stateful-hbs-pyhsslms",
    "stateful-hbs-xmss-keypair",
    "stateful-hbs-xmss-param",
    "stateful-hbs-xmssmt-param",
  ]);
  for (const f of found) {
    assert.equal(f.category, "signature", `${f.ruleId} is a signature finding`);
    assert.equal(f.severity, "medium", `${f.ruleId} is medium (approved but stateful)`);
    assert.equal(f.hndl, false, `${f.ruleId} is NOT harvest-now-decrypt-later`);
    assert.equal(f.algorithm, "unknown", `${f.ruleId} does not claim a broken algorithm`);
    assert.match(f.remediation ?? "", /SP 800-208|never reuse|ML-DSA|SLH-DSA/i);
  }
});

test("bare prose mentioning XMSS/LMS without a parameter string does NOT fire", () => {
  // The word 'XMSS'/'LMS' alone is not a parameter set or an API call.
  assert.deepEqual(hbs(run("notes.md", "We evaluated XMSS and LMS for firmware signing.")), []);
  // A near-miss that is not a valid SP 800-208 parameter shape stays silent.
  assert.deepEqual(hbs(run("notes.md", "LMS_MD5_M32_H10 is not a real parameter set")), []);
});

test("the detector runs on any file type, including docs (tokens are language-agnostic)", () => {
  // Unlike doc-gated detectors, stateful-HBS deliberately fires in prose too: an
  // SP 800-208 parameter string in a design doc is still worth surfacing.
  assert.ok(
    rule(
      run("design.md", "Boot uses `LMS_SHA256_M32_H10` for firmware."),
      "stateful-hbs-lms-param",
    ),
    "an LMS parameter string in Markdown is flagged",
  );
});
