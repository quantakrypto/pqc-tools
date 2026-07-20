/**
 * Tests for the Swift (CryptoKit + Security framework) detector.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectFile, detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function scan1(file: string, content: string): Finding[] {
  return detectFile(file, content, detectors, { source: true, config: true, deps: true });
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("CryptoKit P-curve keys split into ECDSA (sign) vs ECDH (agreement)", () => {
  const sign = rule(run("a.swift", "let k = P256.Signing.PrivateKey()"), "swift-ecdsa");
  assert.equal(sign?.algorithm, "ECDSA");
  assert.equal(sign?.hndl, false);
  const kex = rule(run("a.swift", "let k = P521.KeyAgreement.PrivateKey()"), "swift-ecdh");
  assert.equal(kex?.algorithm, "ECDH");
  assert.equal(kex?.hndl, true);
  // SecureEnclave-prefixed P-curve keys are covered too.
  assert.ok(rule(run("a.swift", "let k = SecureEnclave.P256.Signing.PrivateKey()"), "swift-ecdsa"));
});

test("CryptoKit Curve25519 splits into Ed25519 (sign) vs X25519 (agreement)", () => {
  const ed = rule(run("a.swift", "let k = Curve25519.Signing.PrivateKey()"), "swift-ed25519");
  assert.equal(ed?.algorithm, "EdDSA");
  assert.equal(ed?.hndl, false);
  const x = rule(run("a.swift", "let k = Curve25519.KeyAgreement.PrivateKey()"), "swift-x25519");
  assert.equal(x?.algorithm, "X25519");
  assert.equal(x?.hndl, true);
});

test("Security-framework RSA / EC key types are flagged", () => {
  assert.equal(
    rule(run("a.swift", "let a = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA]"), "swift-rsa")
      ?.algorithm,
    "RSA",
  );
  const ec = rule(
    run("a.swift", "let a = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom]"),
    "swift-sec-ec",
  );
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
});

test("symmetric / hashing CryptoKit APIs do not fire", () => {
  assert.deepEqual(run("a.swift", "let box = try AES.GCM.seal(data, using: key)"), []);
  assert.deepEqual(run("a.swift", "let h = SHA256.hash(data: data)"), []);
});

test("commented-out Swift crypto is suppressed", () => {
  assert.equal(
    rule(scan1("a.swift", "// let k = P256.Signing.PrivateKey()"), "swift-ecdsa"),
    undefined,
  );
  assert.ok(rule(scan1("a.swift", "let k = P256.Signing.PrivateKey()"), "swift-ecdsa"));
});

test("swift detector is gated to .swift files", () => {
  assert.deepEqual(
    run("a.kt", "let k = P256.Signing.PrivateKey()").filter((f) => f.ruleId.startsWith("swift-")),
    [],
  );
});
