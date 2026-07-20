/**
 * Tests for the XML-DSig / XML-Enc (SAML, WS-Security) detector.
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
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("SAML RSA / ECDSA / DSA signature algorithm URIs classify correctly", () => {
  const rsa = rule(
    run(
      "sp.xml",
      '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>',
    ),
    "xmldsig-rsa-sign",
  );
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, false);
  assert.ok(
    rule(run("md.xml", "...xmldsig-more#ecdsa-sha384..."), "xmldsig-ecdsa-sign"),
    "ECDSA URI flagged",
  );
  assert.ok(rule(run("md.xml", "...xmldsig#dsa-sha1..."), "xmldsig-dsa-sign"), "DSA URI flagged");
});

test("XML-Enc RSA key transport (encrypted SAML assertion) is HNDL", () => {
  const f = rule(
    run("resp.xml", '<xenc:EncryptionMethod Algorithm=".../xmlenc#rsa-oaep-mgf1p"/>'),
    "xmlenc-rsa-keytransport",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, true);
  assert.equal(f?.category, "kem");
});

test("the URIs are caught in SAML library CODE too (not just .xml)", () => {
  assert.ok(
    rule(
      run("settings.py", 'signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"'),
      "xmldsig-rsa-sign",
    ),
  );
});

test("a benign `rsa-sha256` without the XML namespace fragment does not fire", () => {
  assert.deepEqual(
    run("notes.txt", "we use rsa-sha256 for JWTs").filter((f) => f.ruleId.startsWith("xml")),
    [],
  );
});

test("the same URI in prose docs (.md) is NOT flagged", () => {
  assert.deepEqual(
    run("saml-guide.md", "SAML uses xmldsig-more#rsa-sha256 by default.").filter((f) =>
      f.ruleId.startsWith("xml"),
    ),
    [],
  );
});
