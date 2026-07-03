/**
 * Tests for the human report's coverage-honesty behaviour: a 100/100 on a
 * codebase with zero analyzable source must NOT read as a clean bill of health.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { renderHuman } from "../src/index.js";
import { ANALYZABLE_LANGUAGES_LABEL } from "@quantakrypto/core";
import { makeResult } from "./helpers.js";

test("renderHuman warns when no analyzable source was scanned", () => {
  const result = { ...makeResult([]), filesScanned: 12, analyzedFiles: 0 };
  const out = renderHuman(result);
  assert.match(out, /No analyzable source found/);
  // Lists the supported languages (whatever the current set is).
  assert.ok(out.includes(`none were in a supported language (${ANALYZABLE_LANGUAGES_LABEL})`));
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

test("renderHuman surfaces coverage diagnostics when files were skipped", () => {
  const result = {
    ...makeResult([]),
    filesScanned: 10,
    analyzedFiles: 8,
    diagnostics: { unreadable: 2, skippedMinified: 3 },
  };
  const out = renderHuman(result);
  assert.match(out, /Coverage:/);
  assert.match(out, /2 unreadable/);
  assert.match(out, /3 skipped \(minified\)/);
  assert.match(out, /results may be incomplete/);
});

test("renderHuman shows no coverage line when nothing was skipped", () => {
  const result = { ...makeResult([]), diagnostics: { unreadable: 0, skippedMinified: 0 } };
  assert.doesNotMatch(renderHuman(result), /Coverage:/);
});
