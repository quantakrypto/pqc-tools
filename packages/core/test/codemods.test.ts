/**
 * Codemod tests. The load-bearing property: a codemod's output actually CLEARS
 * the finding — proven by running `verifyFix` on the patched content.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { codemodFor, configToggleCodemod, verifyFix } from "../src/index.js";
import type { Finding } from "../src/index.js";

function tlsFinding(ruleId: string, file = "server.ts"): Finding {
  return {
    ruleId,
    title: "t",
    category: "tls",
    severity: "medium",
    confidence: "high",
    hndl: false,
    message: "m",
    location: { file, line: 1 },
  };
}

test("config-toggle bumps a legacy TLS version and clears the finding", () => {
  const src = "const opts = { minVersion: 'TLSv1.1' };\n";
  // sanity: the original really trips the detector
  assert.ok(
    verifyFix(src, { filename: "server.ts" }).findings.some(
      (x) => x.ruleId === "tls-legacy-version",
    ),
  );
  const patch = configToggleCodemod.apply(src, tlsFinding("tls-legacy-version"));
  assert.ok(patch);
  assert.match(patch.newContent, /TLSv1\.3/);
  const remaining = verifyFix(patch.newContent, { filename: "server.ts" }).findings;
  assert.ok(!remaining.some((x) => x.ruleId === "tls-legacy-version"), "finding cleared");
});

test("config-toggle re-enables certificate verification and clears the finding", () => {
  const src = "const o = { rejectUnauthorized: false };\n";
  const patch = configToggleCodemod.apply(src, tlsFinding("tls-reject-unauthorized"));
  assert.ok(patch);
  assert.match(patch.newContent, /rejectUnauthorized: true/);
  const remaining = verifyFix(patch.newContent, { filename: "server.ts" }).findings;
  assert.ok(!remaining.some((x) => x.ruleId === "tls-reject-unauthorized"), "finding cleared");
});

test("codemodFor selects config-toggle for TLS findings and nothing for crypto findings", () => {
  assert.equal(codemodFor(tlsFinding("tls-legacy-version"))?.id, "config-toggle");
  assert.equal(codemodFor(tlsFinding("rsa-keygen")), undefined);
});

test("apply returns null when nothing changes", () => {
  assert.equal(configToggleCodemod.apply("const x = 1;\n", tlsFinding("tls-legacy-version")), null);
});

test("a file with BOTH TLS issues is fully fixed by a single patch", () => {
  const src = "const o = { minVersion: 'TLSv1.1', rejectUnauthorized: false };\n";
  // Either finding's patch must clear BOTH findings (the pipeline dedupes by file).
  for (const ruleId of ["tls-legacy-version", "tls-reject-unauthorized"]) {
    const patch = configToggleCodemod.apply(src, tlsFinding(ruleId));
    assert.ok(patch, `${ruleId} produces a patch`);
    const remaining = verifyFix(patch.newContent, { filename: "server.ts" }).findings.map(
      (f) => f.ruleId,
    );
    assert.ok(!remaining.includes("tls-legacy-version"), `${ruleId}: version fixed`);
    assert.ok(!remaining.includes("tls-reject-unauthorized"), `${ruleId}: reject fixed`);
  }
});
