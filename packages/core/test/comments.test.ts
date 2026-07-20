/**
 * Tests for comment-aware false-positive suppression (comments.ts), exercised
 * through `detectFile` (which applies the filter). Comments are suppressed;
 * strings are NOT (the JWT detector intentionally matches quoted alg literals).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectFile, detectors } from "../src/index.js";
import { commentSpans, stringSpans } from "../src/comments.js";
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

test("PHP/Scala // and Elixir # commented-out crypto is suppressed (but code fires)", () => {
  // Regression: these extensions were absent from the comment-style tables, so
  // commented-out code fired detectors as if it were live (P0 false positives).
  // Each assertion is paired with the CODE form to prove the rule id is real and the
  // suppression — not a typo'd rule id — is what makes the comment case false.
  assert.equal(
    has(
      scan1("a.php", "// $k = openssl_pkey_new(['private_key_bits' => 2048]);"),
      "php-openssl-keygen",
    ),
    false,
  );
  assert.equal(
    has(
      scan1("a.php", "$k = openssl_pkey_new(['private_key_bits' => 2048]);"),
      "php-openssl-keygen",
    ),
    true,
  );

  assert.equal(
    has(scan1("a.scala", '// val kp = KeyPairGenerator.getInstance("RSA")'), "java-rsa"),
    false,
  );
  assert.equal(
    has(scan1("a.scala", 'val kp = KeyPairGenerator.getInstance("RSA")'), "java-rsa"),
    true,
  );

  assert.equal(
    has(scan1("a.ex", "# key = :crypto.generate_key(:rsa, {2048, 65537})"), "elixir-crypto-keygen"),
    false,
  );
  assert.equal(
    has(scan1("a.ex", "key = :crypto.generate_key(:rsa, {2048, 65537})"), "elixir-crypto-keygen"),
    true,
  );
});

test("legacy PHP extensions (.php3/.php4/.php5) strip commented-out crypto", () => {
  assert.equal(
    has(scan1("legacy.php5", "// openssl_sign($d, $s, $k);"), "php-openssl-sign"),
    false,
  );
  assert.equal(has(scan1("legacy.php5", "openssl_sign($d, $s, $k);"), "php-openssl-sign"), true);
});

test("a standalone JWT alg is NOT over-suppressed by a distant unrelated JWK", () => {
  // Regression: the enclosingObject fallback must be a bounded ±window, so a top-level
  // `"RS256"` isn't suppressed just because a `"kty"` appears far below it.
  const py =
    'ALGORITHM = "RS256"\n' + "# padding line\n".repeat(40) + 'JWK = {"kty": "RSA", "n": "abc"}';
  assert.equal(
    has(scan1("a.py", py), "jwt-classical-alg"),
    true,
    "the standalone RS256 usage still fires despite a distant JWK",
  );
});

test("identifier-form JWT alg constants inside a string literal are suppressed", () => {
  // A Java/C#/Rust error message that NAMES (and rejects) the alg is prose, not usage.
  assert.equal(
    has(
      scan1(
        "A.java",
        'throw new IllegalArgumentException("SignatureAlgorithm.RS256 not allowed");',
      ),
      "java-jwt-alg",
    ),
    false,
  );
  assert.equal(
    has(scan1("A.java", "var a = SignatureAlgorithm.RS256;"), "java-jwt-alg"),
    true,
    "the real identifier usage still fires",
  );
  assert.equal(
    has(scan1("A.cs", 'Log.Warn("SecurityAlgorithms.RsaSha256 is weak");'), "csharp-jwt-alg"),
    false,
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

test("commentSpans handles Rust lifetimes without swallowing the file (verified lexer bug)", () => {
  // `<'a>` / `&'a` are lifetimes, not char literals; the old lexer started an
  // unterminated string on the ' and consumed the rest of the file, so the
  // trailing // comment was never recognized (FP suppression silently no-op'd).
  const src = "fn parse<'a>(x: &'a str) { let z = 1; } // migrated off createECDH()";
  const spans = commentSpans(src, "c");
  assert.ok(
    spans.some(([s, e]) => src.slice(s, e).includes("migrated off createECDH")),
    "the trailing line comment is found despite the lifetimes",
  );
});

test("stringSpans treats Go raw strings as raw, no escapes (verified lexer bug)", () => {
  // `C:\` is a Go RAW string; the old escape-aware scan treated \` as escaped and
  // consumed past the close, hiding the identifier after it from CODE_ONLY rules.
  const src = "x := " + "`" + "C:\\" + "`" + "\nSigningMethodRS256";
  const idIdx = src.indexOf("SigningMethodRS256");
  const spans = stringSpans(src, "c", true);
  assert.ok(
    !spans.some(([s, e]) => idIdx >= s && idIdx < e),
    "the identifier after the raw string is not inside a string span",
  );
});
