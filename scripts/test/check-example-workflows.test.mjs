import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { checkWorkflow, EXAMPLE_DIR } from "../check-example-workflows.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

test("the exact line that shipped is caught", () => {
  // What was actually committed: a step name merged into the key below it.
  // Valid YAML, so a parser sees nothing wrong; GitHub rejects the workflow.
  const problems = checkWorkflow(
    ["      - name: Upload SARIF", "        continue-on-error: true to code scanning"].join("\n"),
  );
  assert.equal(problems.length, 1);
  assert.match(problems[0], /continue-on-error must be true or false/);
});

test("booleans, expressions and quoted booleans all pass", () => {
  for (const value of ["true", "false", '"true"', "${{ github.event_name == 'schedule' }}"]) {
    assert.deepEqual(checkWorkflow(`        continue-on-error: ${value}`), [], value);
  }
});

test("our action must be pinned to a moving major", () => {
  for (const ref of ["v1.2.3", "main", "0.10.0"]) {
    const problems = checkWorkflow(`        uses: quantakrypto/pqc-tools/packages/action@${ref}`);
    assert.equal(problems.length, 1, ref);
    assert.match(problems[0], /moving major/);
  }
  // Both `uses:` coordinates of our action are accepted at a bare major.
  assert.deepEqual(checkWorkflow("        uses: quantakrypto/pqc-tools/packages/action@v1"), []);
  assert.deepEqual(checkWorkflow("        uses: quantakrypto/pqc-tools@v1"), []);
});

test("third-party actions are not held to our tag rule", () => {
  assert.deepEqual(checkWorkflow("        uses: github/codeql-action/upload-sarif@v4"), []);
  assert.deepEqual(checkWorkflow("        uses: actions/checkout@v4"), []);
});

test("an unpinned or malformed uses is rejected", () => {
  assert.match(checkWorkflow("        uses: actions/checkout")[0], /unpinned/);
  assert.match(checkWorkflow("        uses: actions/checkout@v4 extra")[0], /single ref/);
});

test("comments are not parsed as keys", () => {
  assert.deepEqual(checkWorkflow("      # continue-on-error: not a real setting here"), []);
});

test("every shipped example passes", () => {
  const dir = resolve(ROOT, EXAMPLE_DIR);
  const files = readdirSync(dir).filter((f) => f.endsWith(".yml"));
  assert.ok(files.length > 0, "found no examples to check");
  for (const file of files) {
    assert.deepEqual(checkWorkflow(readFileSync(join(dir, file), "utf8")), [], file);
  }
});
