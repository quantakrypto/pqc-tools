/**
 * Tests for the Dart / Flutter classical-crypto source detector. Imports the
 * detector directly (not through the registry) so the assertions pin this pack's
 * behaviour in isolation: one positive per rule with realistic pointycastle /
 * cryptography snippets, plus negatives for symmetric-only code, commented-out
 * crypto, and non-Dart files.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { dartDetector } from "../src/detectors/dart.js";
import type { Finding } from "../src/types.js";

/** Run the detector only when it applies to the given path (mirrors the scanner). */
function run(file: string, content: string): Finding[] {
  return dartDetector.appliesTo(file) ? dartDetector.detect({ file, content }) : [];
}

/** Find the single finding for a rule id, asserting exactly one is present. */
function only(findings: Finding[], ruleId: string): Finding {
  const hits = findings.filter((f) => f.ruleId === ruleId);
  assert.equal(hits.length, 1, `expected exactly one ${ruleId}, got ${hits.length}`);
  return hits[0];
}

test("dart-rsa-keygen: RSAKeyGenerator → RSA / kem / hndl", () => {
  const f = only(run("keys.dart", "final gen = RSAKeyGenerator();"), "dart-rsa-keygen");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "kem");
  assert.equal(f.hndl, true);
});

test("dart-rsa-keygen: RSAEngine (encryption) → RSA / kem / hndl", () => {
  const f = only(
    run("cipher.dart", "final engine = RSAEngine()..init(true, pub);"),
    "dart-rsa-keygen",
  );
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "kem");
  assert.equal(f.hndl, true);
});

test("dart-rsa-sign: RSASigner → RSA / signature / not hndl", () => {
  const f = only(
    run("sign.dart", "final signer = RSASigner(SHA256Digest(), '0609...');"),
    "dart-rsa-sign",
  );
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("dart-rsa-sign: cryptography RsaPss → RSA / signature", () => {
  const f = only(run("sign2.dart", "final algo = RsaPss(Sha256());"), "dart-rsa-sign");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("dart-rsa-sign: cryptography RsaSsaPkcs1v15 → RSA / signature", () => {
  const f = only(run("sign3.dart", "final algo = RsaSsaPkcs1v15(Sha256());"), "dart-rsa-sign");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "signature");
});

test("dart-ecdsa: ECDSASigner → ECDSA / signature / not hndl", () => {
  const f = only(run("ec.dart", "final signer = ECDSASigner(SHA256Digest());"), "dart-ecdsa");
  assert.equal(f.algorithm, "ECDSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("dart-ec-keygen: ECKeyGenerator (ambiguous) → ECDH / key-exchange / hndl:true", () => {
  // An EC key at generation can feed ECDH agreement, so it's classified HNDL-safe
  // (key-exchange/ECDH/hndl:true), matching the fleet convention — NOT the sign rule.
  const f = only(run("eckeys.dart", "final gen = ECKeyGenerator();"), "dart-ec-keygen");
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
});

test("dart-ecdsa: cryptography Ecdsa → ECDSA / signature", () => {
  const f = only(run("ecdsa.dart", "final algo = Ecdsa.p256(Sha256());"), "dart-ecdsa");
  assert.equal(f.algorithm, "ECDSA");
  assert.equal(f.category, "signature");
});

test("dart-ecdh: ECDHBasicAgreement → ECDH / key-exchange / hndl", () => {
  const f = only(run("dh.dart", "final agreement = ECDHBasicAgreement();"), "dart-ecdh");
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
});

test("dart-ecdh: cryptography Ecdh → ECDH / key-exchange / hndl", () => {
  const f = only(run("ecdh.dart", "final algo = Ecdh.p256(length: 32);"), "dart-ecdh");
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
});

test("dart-ed25519: Ed25519 → EdDSA / signature / not hndl", () => {
  const f = only(run("ed.dart", "final algo = Ed25519();"), "dart-ed25519");
  assert.equal(f.algorithm, "EdDSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("dart-x25519: X25519 → X25519 / key-exchange / hndl", () => {
  const f = only(run("kx.dart", "final kx = X25519();"), "dart-x25519");
  assert.equal(f.algorithm, "X25519");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
});

test("negative: symmetric-only Dart (AES / Hmac) yields no findings", () => {
  const src = [
    "final cipher = AESEngine();",
    "final gcm = GCMBlockCipher(AESEngine());",
    "final mac = Hmac(Sha256());",
  ].join("\n");
  assert.deepEqual(run("sym.dart", src), []);
});

test("negative: commented-out crypto is not reported", () => {
  const src = [
    "// final gen = RSAKeyGenerator();",
    "/* final kx = X25519();",
    "   final signer = ECDSASigner(SHA256Digest()); */",
    "final aes = AESEngine();",
  ].join("\n");
  assert.deepEqual(run("commented.dart", src), []);
});

test("negative: non-Dart files are not scanned by this detector", () => {
  const src = "const gen = RSAKeyGenerator(); const kx = X25519();";
  assert.deepEqual(run("app.ts", src), []);
  assert.deepEqual(run("app.js", src), []);
});
