/**
 * Redactor tests: context levels are bounded as documented, and a `sensitive`
 * finding never emits code at any level (the hard privacy boundary).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildContext, renderPreflight } from "../src/redact.js";
import type { Finding } from "../src/index.js";

const FILE = ["import x", "const e = crypto.createECDH('p256');", "doThing(e)", "// tail"].join(
  "\n",
);
const finding: Finding = {
  ruleId: "node-crypto-ecdh",
  title: "ECDH",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  hndl: true,
  message: "ECDH is classical",
  location: { file: "a.ts", line: 2 },
};

test("metadata level sends no code", () => {
  const c = buildContext(finding, "metadata", FILE);
  assert.equal(c.code, null);
  assert.equal(c.meta.ruleId, "node-crypto-ecdh");
});

test("snippet level sends a bounded window including the match line", () => {
  const c = buildContext(finding, "snippet", FILE);
  assert.ok(c.code && c.code.includes("createECDH"));
});

test("file level sends the whole file", () => {
  const c = buildContext(finding, "file", FILE);
  assert.equal(c.code, FILE);
});

test("a sensitive finding is always redacted, even at file level", () => {
  const sensitive: Finding = { ...finding, sensitive: true, location: { file: "k.pem", line: 1 } };
  const c = buildContext(
    sensitive,
    "file",
    "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
  );
  assert.equal(c.code, null);
  assert.equal(c.redactedSecret, true);
});

test("a novel high-entropy token (no known vendor prefix) is caught by the entropy pass", () => {
  // 40 random chars in an array literal — too short for the base64 rule, no vendor
  // prefix, and `blob` is not a secret-keyword assignment, so only the entropy
  // catch-all can mask it.
  const tok = "Zx9Kq2Lm7Pw4Rt8Yu1Nv6Sd0Fg5Hj3Bc8De2Ai4";
  const f: Finding = { ...finding, location: { file: "cfg.ts", line: 2 } };
  const file = ["const blob = [", `  "${tok}",`, "];", "doThing(blob)"].join("\n");
  const c = buildContext(f, "file", file);
  assert.equal(c.redactedSecret, true);
  assert.ok(c.code && !c.code.includes(tok), "the high-entropy token is masked");
  assert.ok(c.code && c.code.includes("doThing(blob)"), "ordinary code around it survives");
});

test("embedded PEM secrets are masked from otherwise-shareable code", () => {
  const withKey = [
    "const k = `",
    "-----BEGIN PRIVATE KEY-----",
    "abc",
    "-----END PRIVATE KEY-----",
    "`;",
  ].join("\n");
  const f: Finding = { ...finding, location: { file: "a.ts", line: 1 } };
  const c = buildContext(f, "file", withKey);
  assert.ok(c.code && !c.code.includes("BEGIN PRIVATE KEY"));
  assert.equal(c.redactedSecret, true);
});

test("renderPreflight shows the exact payload per finding", () => {
  const c = buildContext(finding, "snippet", FILE);
  const out = renderPreflight([c]);
  assert.match(out, /node-crypto-ecdh a\.ts:2/);
  assert.match(out, /createECDH/);
});

// --- Hardened secret redaction (audit: appsec #1/#5, arch #2/#3) ---

function ctxCode(content: string): { code: string | null; redactedSecret: boolean } {
  const f: Finding = { ...finding, location: { file: "a.ts", line: 1 } };
  const c = buildContext(f, "file", content);
  return { code: c.code, redactedSecret: c.redactedSecret };
}

test("redacts common vendor tokens, JWTs, hex/base64 keys, and .env assignments", () => {
  // Fixtures are assembled at runtime from fragments so NO contiguous secret
  // literal sits in this source file — otherwise secret-scanning push protection
  // would (rightly) block the commit. None of these are real credentials.
  const j = (...parts: string[]) => parts.join("");
  const cases = [
    `const k = "${j("AKIA", "IOSFODNN7", "EXAMPLE")}";`,
    `const t = "${j("ghp", "_", "1234567890abcdefghijklmnopqrstuvwx")}";`,
    `const s = "${j("xox", "b-", "123456789012-abcdefghijklmnop")}";`,
    `const o = "${j("sk-", "proj-", "abcdefghijklmnopqrstuvwxyz012345")}";`,
    `const jwt = "${j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N")}";`,
    `const hex = "0123456789abcdef0123456789abcdef0123456789abcdef";`,
    `${j("AWS", "_SECRET_", "ACCESS_KEY")}=${j("wJalrXUtnFEMI", "K7MDENGbPxRfiCY", "EXAMPLEKEY")}`,
    `password: "hunter2-not-a-real-one"`,
  ];
  for (const src of cases) {
    const { code, redactedSecret } = ctxCode(src);
    assert.equal(redactedSecret, true, `should redact: ${src}`);
    assert.ok(code && code.includes("«redacted-secret»"), `placeholder present: ${src}`);
  }
});

test("a non-secret code line is NOT redacted (no over-trigger on ordinary code)", () => {
  const { redactedSecret } = ctxCode(`const e = crypto.createECDH('p256');\nreturn doThing(e);\n`);
  assert.equal(redactedSecret, false);
});

test("a truncated private key (missing END) is still fully redacted", () => {
  const src = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretkeymaterial\nmore\n";
  const { code, redactedSecret } = ctxCode(src);
  assert.equal(redactedSecret, true);
  assert.ok(code && !code.includes("secretkeymaterial"), "key body dropped even without END");
});

test("DoS: an unterminated PEM header over a large body does not hang (bounded/linear)", () => {
  const src = "-----BEGIN PRIVATE KEY-----\n" + "A".repeat(1_200_000);
  const start = Date.now();
  const { redactedSecret } = ctxCode(src);
  assert.equal(redactedSecret, true);
  assert.ok(Date.now() - start < 2000, "must be fast, not O(n^2)");
});

test("DoS: a multi-MB base64 run redacts without a stack overflow", () => {
  const src = "const x = '" + "A".repeat(9_000_000) + "';";
  const { redactedSecret } = ctxCode(src); // fail-closed (over MAX_SECRET_SCAN)
  assert.equal(redactedSecret, true);
});
