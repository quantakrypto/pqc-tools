/**
 * Tests for the human report's coverage-honesty behaviour: a 100/100 on a
 * codebase with zero analyzable source must NOT read as a clean bill of health.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { renderHuman } from "../src/index.js";
import { makeResult } from "./helpers.js";

test("renderHuman warns when no analyzable source was scanned", () => {
  const result = { ...makeResult([]), filesScanned: 12, analyzedFiles: 0 };
  const out = renderHuman(result);
  assert.match(out, /No analyzable source found/);
  assert.match(out, /none were in a supported language \(JS\/TS, Python, Go, Java\)/);
  assert.match(out, /NOT a clean bill of health/);
  // It must not claim the codebase is clean.
  assert.doesNotMatch(out, /No quantum-vulnerable cryptography detected/);
});

test("renderHuman reports a normal clean result when analyzable source was scanned", () => {
  const result = { ...makeResult([]), filesScanned: 12, analyzedFiles: 9 };
  const out = renderHuman(result);
  assert.match(out, /No quantum-vulnerable cryptography detected/);
  assert.doesNotMatch(out, /No analyzable source found/);
  // The header surfaces the analyzed count.
  assert.match(out, /analyzed: 9/);
});

test("renderHuman is unchanged (no coverage line) for results without analyzedFiles", () => {
  const out = renderHuman(makeResult([]));
  assert.match(out, /No quantum-vulnerable cryptography detected/);
  assert.doesNotMatch(out, /analyzed:/);
});
