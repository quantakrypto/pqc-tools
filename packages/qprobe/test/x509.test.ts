import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeOid, oidToSignatureFamily, certSignatureAlgorithm } from "../src/x509.js";

/** Build a short-form DER TLV (content length must be < 128 for these fixtures). */
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag, content.length]), content]);
}

test("decodeOid decodes well-known signature OIDs", () => {
  assert.equal(decodeOid(Buffer.from("2a864886f70d01010b", "hex")), "1.2.840.113549.1.1.11"); // sha256WithRSA
  assert.equal(decodeOid(Buffer.from("2a8648ce3d040302", "hex")), "1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
  assert.equal(decodeOid(Buffer.from("2b6570", "hex")), "1.3.101.112"); // Ed25519
});

test("oidToSignatureFamily maps OIDs to classical families", () => {
  assert.equal(oidToSignatureFamily("1.2.840.113549.1.1.11"), "RSA");
  assert.equal(oidToSignatureFamily("1.2.840.10045.4.3.2"), "ECDSA");
  assert.equal(oidToSignatureFamily("1.3.101.112"), "EdDSA");
  assert.equal(oidToSignatureFamily("2.999.1"), undefined);
});

test("certSignatureAlgorithm extracts the signatureAlgorithm from a DER certificate", () => {
  const oid = tlv(0x06, Buffer.from("2a864886f70d01010b", "hex")); // sha256WithRSA
  const nul = Buffer.from([0x05, 0x00]);
  const tbs = tlv(0x30, tlv(0x02, Buffer.from([0x00]))); // minimal tbsCertificate SEQUENCE{ INTEGER 0 }
  const sigAlg = tlv(0x30, Buffer.concat([oid, nul]));
  const sigValue = tlv(0x03, Buffer.from([0x00])); // BIT STRING
  const cert = tlv(0x30, Buffer.concat([tbs, sigAlg, sigValue]));

  const got = certSignatureAlgorithm(cert);
  assert.equal(got?.oid, "1.2.840.113549.1.1.11");
  assert.equal(got?.family, "RSA");
});

test("certSignatureAlgorithm returns undefined on garbage", () => {
  assert.equal(certSignatureAlgorithm(Buffer.from([0x01, 0x02, 0x03])), undefined);
});
