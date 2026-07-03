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
