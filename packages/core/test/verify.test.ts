/**
 * Tests for the snippet-level fix-verification helper shared by the MCP
 * verify_fix tool and the remediation pipeline.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyFix, languageToExtension } from "../src/verify.js";

test("verifyFix reports remaining classical crypto", () => {
  const r = verifyFix("const e = crypto.createECDH('p256');", { language: "js" });
  assert.equal(r.supported, true);
  assert.ok(r.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
});

test("verifyFix returns clean for PQC-only code", () => {
  const r = verifyFix("const x = mlkem768.keygen();", { language: "js" });
  assert.equal(r.supported, true);
  assert.equal(r.findings.length, 0);
});

test("verifyFix flags an unsupported language as not-a-verification", () => {
  const r = verifyFix("let x = 1", { language: "cobol" });
  assert.equal(r.supported, false);
  assert.equal(r.findings.length, 0);
});

test("verifyFix selects detectors from a filename extension", () => {
  const r = verifyFix("e = crypto.createECDH('p256')", { filename: "a.js" });
  assert.equal(r.supported, true);
});

test("languageToExtension maps names and bare extensions", () => {
  assert.equal(languageToExtension("python"), ".py");
  assert.equal(languageToExtension(".ts"), ".ts");
  assert.equal(languageToExtension("cobol"), null);
});
