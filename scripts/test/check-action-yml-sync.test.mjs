import assert from "node:assert/strict";
import { test } from "node:test";

import { diffActionMeta, parseActionMeta } from "../check-action-yml-sync.mjs";

/**
 * The gate is only worth having if it fails on real drift. A checker that
 * parses nothing, or compares nothing, passes forever and is worse than absent
 * because it looks like coverage.
 */

const SAMPLE = `name: "x"
description: "y"

inputs:
  checks:
    description: >-
      which checks
    required: false
    default: "scan"
  probe-target:
    description: "host"
    required: false
    default: ""
  github-token:
    description: "token"
    required: false

outputs:
  findings-count:
    description: "n"
  readiness-score:
    description: "n"

runs:
  using: "node20"
  main: "dist/index.js"
`;

test("reads every input and output, and their defaults", () => {
  const meta = parseActionMeta(SAMPLE);
  assert.deepEqual([...meta.inputs.keys()], ["checks", "probe-target", "github-token"]);
  assert.equal(meta.inputs.get("checks").default, "scan");
  assert.equal(meta.inputs.get("probe-target").default, "");
  // An input with no default is not the same as one defaulting to empty.
  assert.equal(meta.inputs.get("github-token").default, null);
  assert.deepEqual([...meta.outputs], ["findings-count", "readiness-score"]);
});

test("ignores keys outside inputs/outputs, including runs.main", () => {
  const meta = parseActionMeta(SAMPLE);
  assert.ok(!meta.inputs.has("using"));
  assert.ok(!meta.inputs.has("main"));
  assert.ok(!meta.outputs.has("main"));
});

test("identical files produce no problems", () => {
  const a = parseActionMeta(SAMPLE);
  const b = parseActionMeta(SAMPLE);
  assert.deepEqual(diffActionMeta(a, b), []);
});

test("catches an input added to only one file, in both directions", () => {
  const full = parseActionMeta(SAMPLE);
  const partial = parseActionMeta(SAMPLE.replace(/ {2}probe-target:\n(?: {4}.*\n)+/, ""));

  const missingFromRoot = diffActionMeta(partial, full);
  assert.equal(missingFromRoot.length, 1);
  assert.match(missingFromRoot[0], /input "probe-target" is missing from action\.yml/);

  const missingFromPkg = diffActionMeta(full, partial);
  assert.equal(missingFromPkg.length, 1);
  assert.match(missingFromPkg[0], /missing from packages\/action\/action\.yml/);
});

test("catches a default that drifted", () => {
  const a = parseActionMeta(SAMPLE);
  const b = parseActionMeta(SAMPLE.replace('default: "scan"', 'default: "scan,probe"'));
  const problems = diffActionMeta(a, b);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /input "checks" default differs/);
});

test("catches an output added to only one file", () => {
  const a = parseActionMeta(SAMPLE);
  const b = parseActionMeta(
    SAMPLE.replace("outputs:\n", 'outputs:\n  extra:\n    description: "x"\n'),
  );
  const problems = diffActionMeta(a, b);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /output "extra" is missing from action\.yml/);
});

/**
 * The real files, so this suite fails the moment someone edits one metadata
 * file and not the other — which is the whole point of the gate.
 */
test("the committed action.yml pair is in sync", async () => {
  const { readFileSync } = await import("node:fs");
  const { dirname, resolve } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

  const rootMeta = parseActionMeta(readFileSync(resolve(root, "action.yml"), "utf8"));
  const pkgMeta = parseActionMeta(
    readFileSync(resolve(root, "packages/action/action.yml"), "utf8"),
  );

  assert.ok(pkgMeta.inputs.size > 0, "parsed no inputs — the checker would pass vacuously");
  assert.deepEqual(diffActionMeta(rootMeta, pkgMeta), []);
});
