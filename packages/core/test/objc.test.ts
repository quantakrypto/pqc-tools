/**
 * Tests for the Objective-C (Apple Security framework / SecKey) detector.
 * Imports the detector directly so the pack is exercised in isolation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { objcDetector } from "../src/detectors/objc.js";
import type { Finding } from "../src/types.js";

function run(file: string, content: string): Finding[] {
  return objcDetector.appliesTo(file) ? objcDetector.detect({ file, content }) : [];
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("RSA key generation via kSecAttrKeyTypeRSA is flagged (kem, hndl:true)", () => {
  const src =
    `NSDictionary *attrs = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,\n` +
    `                         (id)kSecAttrKeySizeInBits: @2048 };\n` +
    `SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);`;
  const f = rule(run("keys.m", src), "objc-seckey-rsa");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "kem");
  assert.equal(f?.hndl, true);
  assert.equal(f?.severity, "high");
});

test("EC key generation via kSecAttrKeyTypeECSECPrimeRandom is flagged (signature, hndl:false)", () => {
  const src =
    `NSDictionary *attrs = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,\n` +
    `                         (id)kSecAttrKeySizeInBits: @256 };\n` +
    `SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);`;
  const f = rule(run("keys.m", src), "objc-seckey-ec");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  // legacy kSecAttrKeyTypeEC alias also matches.
  assert.ok(
    rule(
      run("keys.mm", "NSDictionary *a = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC };"),
      "objc-seckey-ec",
    ),
  );
});

test("RSA signing algorithm is flagged (signature, hndl:false)", () => {
  const src =
    `CFDataRef sig = SecKeyCreateSignature(privateKey,\n` +
    `    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, (__bridge CFDataRef)data, &error);`;
  const f = rule(run("sign.m", src), "objc-rsa-sign");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  assert.equal(f?.severity, "medium");
});

test("RSA encryption algorithm is flagged (kem, hndl:true)", () => {
  const src =
    `CFDataRef ct = SecKeyCreateEncryptedData(publicKey,\n` +
    `    kSecKeyAlgorithmRSAEncryptionOAEPSHA256, (__bridge CFDataRef)plain, &error);`;
  const f = rule(run("enc.mm", src), "objc-rsa-encrypt");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "kem");
  assert.equal(f?.hndl, true);
  assert.equal(f?.severity, "high");
});

test("ECDSA signing algorithm is flagged (signature, hndl:false)", () => {
  const src =
    `CFDataRef sig = SecKeyCreateSignature(privateKey,\n` +
    `    kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)data, &error);`;
  const f = rule(run("sign.m", src), "objc-ecdsa-sign");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("ECDH key exchange algorithm is flagged (key-exchange, hndl:true)", () => {
  const src =
    `CFDataRef shared = SecKeyCopyKeyExchangeResult(privateKey,\n` +
    `    kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256, publicKey, params, &error);`;
  const f = rule(run("kex.m", src), "objc-ecdh");
  assert.equal(f?.algorithm, "ECDH");
  assert.equal(f?.category, "key-exchange");
  assert.equal(f?.hndl, true);
  assert.equal(f?.severity, "high");
});

test("symmetric-only Objective-C (AES / CommonCrypto) does not fire", () => {
  const src =
    `CCCryptorRef cryptor;\n` +
    `CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,\n` +
    `                keyBytes, kCCKeySizeAES256, iv, &cryptor);`;
  assert.deepEqual(run("aes.m", src), []);
});

test("commented-out SecKey crypto is suppressed", () => {
  // line comment
  assert.deepEqual(
    run("a.m", "// SecKeyRef k = SecKeyCreateRandomKey(attrsWith_kSecAttrKeyTypeRSA, &e);"),
    [],
  );
  // block comment
  assert.deepEqual(
    run("a.m", "/* NSDictionary *a = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA }; */"),
    [],
  );
  // sanity: the same live line DOES fire.
  assert.ok(
    rule(
      run("a.m", "NSDictionary *a = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA };"),
      "objc-seckey-rsa",
    ),
  );
});

test("header files (.h) are NOT scanned by the Objective-C detector", () => {
  const src = "NSDictionary *a = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA };";
  assert.equal(objcDetector.appliesTo("Crypto.h"), false);
  assert.deepEqual(run("Crypto.h", src), []);
});

test("Swift files (.swift) are NOT scanned by the Objective-C detector", () => {
  const src = "let a = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA]";
  assert.equal(objcDetector.appliesTo("a.swift"), false);
  assert.deepEqual(run("a.swift", src), []);
});
