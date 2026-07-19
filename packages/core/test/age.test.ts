/**
 * Tests for committed age identity (private key) detection.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

const AGE_SECRET = "AGE-SECRET-KEY-1QQZQZ9RY2H0Z8ZQ0V3W7X4A2B6C8D0E2F4G6H8J0K2L4M6N8P0Q2R4S6T8";

test("an age identity (AGE-SECRET-KEY-1) is flagged as X25519, HNDL, sensitive", () => {
  const f = rule(run("keys.txt", `# created by age\n${AGE_SECRET}\n`), "age-secret-key");
  assert.equal(f?.algorithm, "X25519");
  assert.equal(f?.hndl, true);
  assert.equal(f?.sensitive, true);
});

test("ordinary text with no age secret key produces no finding", () => {
  assert.deepEqual(
    run("notes.txt", "we use age for secrets, recipient age1abc...").filter((f) =>
      f.ruleId.startsWith("age-"),
    ),
    [],
  );
});
