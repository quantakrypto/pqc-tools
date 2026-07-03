import { test } from "node:test";
import assert from "node:assert/strict";

import { checkPatchPolicy } from "../src/patch-policy.js";
import type { Patch } from "../src/index.js";

function patch(path: string): Patch {
  return { path, newContent: "x", ruleId: "r", source: "codemod" };
}
const ctx = {
  findingFiles: new Set(["src/a.ts"]),
  manifestFiles: new Set(["package.json"]),
};

test("a patch to a file that has a finding is allowed", () => {
  assert.equal(checkPatchPolicy(patch("src/a.ts"), ctx).allowed, true);
});

test("a manifest patch is allowed", () => {
  assert.equal(checkPatchPolicy(patch("package.json"), ctx).allowed, true);
});

test("a patch to CI config is denied", () => {
  const d = checkPatchPolicy(patch(".github/workflows/ci.yml"), ctx);
  assert.equal(d.allowed, false);
  assert.match(d.reason ?? "", /protected/);
});

test("a patch to a lockfile is denied even though it looks manifest-adjacent", () => {
  assert.equal(checkPatchPolicy(patch("package-lock.json"), ctx).allowed, false);
});

test("a patch to a secret/env file is denied", () => {
  assert.equal(checkPatchPolicy(patch(".env"), ctx).allowed, false);
  assert.equal(checkPatchPolicy(patch("keys/server.pem"), ctx).allowed, false);
});

test("a patch to an unrelated file is denied", () => {
  const d = checkPatchPolicy(patch("src/unrelated.ts"), ctx);
  assert.equal(d.allowed, false);
  assert.match(d.reason ?? "", /no finding/);
});
