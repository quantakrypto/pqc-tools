/**
 * Tests for comment-aware false-positive suppression (comments.ts), exercised
 * through `detectFile` (which applies the filter). Comments are suppressed;
 * strings are NOT (the JWT detector intentionally matches quoted alg literals).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectFile, detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function scan1(file: string, content: string): Finding[] {
  return detectFile(file, content, detectors, { source: true, config: true, deps: true });
}
const has = (findings: Finding[], ruleId: string): boolean =>
  findings.some((f) => f.ruleId === ruleId);

test("crypto in a // line comment is suppressed; the same call in code is not", () => {
  assert.equal(
    has(scan1("a.ts", "// migrated off crypto.createECDH('p256')"), "node-crypto-ecdh"),
    false,
  );
  assert.equal(
    has(scan1("a.ts", "const e = crypto.createECDH('p256');"), "node-crypto-ecdh"),
    true,
  );
});

test("crypto in a /* block comment */ is suppressed", () => {
  const src =
    "/*\n  legacy: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })\n*/\nexport {};";
  assert.equal(has(scan1("a.ts", src), "node-crypto-keygen"), false);
});

test("Python # comments are suppressed", () => {
  assert.equal(
    has(scan1("a.py", "# key = rsa.generate_private_key(key_size=2048)"), "python-rsa-keygen"),
    false,
  );
  assert.equal(
    has(scan1("a.py", "key = rsa.generate_private_key(key_size=2048)"), "python-rsa-keygen"),
    true,
  );
});

test("a // inside a string does not swallow following real code", () => {
  // If the lexer mis-parsed the string, it would treat the rest of the line as a
  // comment and drop the real createECDH call.
  const findings = scan1("a.ts", 'const u = "a//b"; const e = crypto.createECDH("p256");');
  assert.equal(has(findings, "node-crypto-ecdh"), true);
});

test("real code with a trailing comment is still detected", () => {
  assert.equal(
    has(scan1("a.ts", "crypto.createECDH('p256'); // deprecated"), "node-crypto-ecdh"),
    true,
  );
});

test("JWT alg string literals are NOT suppressed (they are the intended signal)", () => {
  assert.equal(
    has(scan1("a.ts", "jwt.sign(p, k, { algorithm: 'RS256' });"), "jwt-classical-alg"),
    true,
  );
  // …but a JWT alg mentioned in a comment IS suppressed.
  assert.equal(has(scan1("a.ts", "// do not use RS256 here"), "jwt-classical-alg"), false);
});

test("comment filtering does not touch dependency findings (manifests have no comments)", () => {
  const pkg = JSON.stringify({ dependencies: { "node-forge": "^1.0.0" } });
  assert.equal(has(scan1("package.json", pkg), "dep-vulnerable"), true);
});

test("inline qscan-ignore-line suppresses a finding on the same line", () => {
  assert.equal(
    has(
      scan1("a.ts", "const e = crypto.createECDH('p256'); // qscan-ignore-line"),
      "node-crypto-ecdh",
    ),
    false,
  );
});

test("inline qscan-ignore-next-line suppresses the following line only", () => {
  assert.equal(
    has(scan1("a.ts", "// qscan-ignore-next-line\ncrypto.createECDH('p256');"), "node-crypto-ecdh"),
    false,
  );
  // The directive only reaches the immediately-following line.
  assert.equal(
    has(
      scan1("a.ts", "// qscan-ignore-next-line\nconst ok = 1;\ncrypto.createECDH('p256');"),
      "node-crypto-ecdh",
    ),
    true,
  );
});

test("qscan-ignore is language-agnostic (works with # comments)", () => {
  assert.equal(
    has(
      scan1("a.py", "key = rsa.generate_private_key(key_size=2048)  # qscan-ignore-line"),
      "python-rsa-keygen",
    ),
    false,
  );
});
