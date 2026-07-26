/**
 * JS home-turf recall edge cases for the Node `crypto` detector: bracket
 * (computed-member) access to crypto methods, and `generateKeyPair` called with
 * a variable key type instead of a quoted literal. These forms defeat the
 * dotted-call / literal-argument regexes, so they are asserted directly here.
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

test("crypto['createSign'] bracket access is detected as a classical signature", () => {
  const f = rule(run("a.js", "const s = crypto['createSign']('RSA-SHA256');"), "node-crypto-sign");
  assert.ok(f, "bracket createSign flagged");
  assert.equal(f?.category, "signature");
});

test("bracket access to createVerify / createECDH / DH / RSA encrypt is routed correctly", () => {
  assert.ok(rule(run("a.js", 'crypto["createVerify"]("RSA-SHA256")'), "node-crypto-sign"));
  assert.ok(rule(run("a.js", "crypto['createECDH']('secp256k1')"), "node-crypto-ecdh"));
  assert.ok(rule(run("a.js", "crypto['createDiffieHellman'](2048)"), "node-crypto-dh"));
  assert.ok(rule(run("a.js", "crypto['publicEncrypt'](key, buf)"), "node-crypto-rsa-encrypt"));
  assert.ok(rule(run("a.js", "crypto['privateDecrypt'](key, buf)"), "node-crypto-rsa-encrypt"));
});

test("bracket createSign is not double-counted by the dotted-call rule", () => {
  const signs = run("a.js", "crypto['createSign']('RSA-SHA256')").filter(
    (f) => f.ruleId === "node-crypto-sign",
  );
  assert.equal(signs.length, 1);
});

test("generateKeyPair with a variable key type is detected (unknown family)", () => {
  const f = rule(
    run("a.js", "const kind = 'rsa';\ncrypto.generateKeyPairSync(kind, opts);"),
    "node-crypto-keygen",
  );
  assert.ok(f, "variable-typed generateKeyPair flagged");
  assert.equal(f?.algorithm, "unknown");
  assert.equal(f?.hndl, true);
  assert.ok(f?.title.includes("variable"));
});

test("bracket generateKeyPair with a literal key type keeps its concrete family", () => {
  const f = rule(
    run("a.js", "crypto['generateKeyPairSync']('rsa', { modulusLength: 2048 });"),
    "node-crypto-keygen",
  );
  assert.ok(f);
  assert.equal(f?.algorithm, "RSA");
});

test("a literal generateKeyPair call is NOT also matched by the variable-typed rule", () => {
  const keygens = run("a.js", "crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })").filter(
    (f) => f.ruleId === "node-crypto-keygen",
  );
  assert.equal(keygens.length, 1);
  assert.equal(keygens[0].algorithm, "ECDH");
});

test("a similarly-named function does not misfire the variable-typed keygen rule", () => {
  // `myGenerateKeyPair(kind)` is not Node's crypto API; the word boundary guard
  // must keep it from matching.
  const keygens = run("a.js", "myGenerateKeyPair(kind);").filter(
    (f) => f.ruleId === "node-crypto-keygen",
  );
  assert.equal(keygens.length, 0);
});
