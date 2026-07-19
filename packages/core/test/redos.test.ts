/**
 * ReDoS guard: `detectFile` (all detector regexes + the comment lexer) must run
 * in roughly linear time. Catastrophic backtracking would blow the time budget
 * by orders of magnitude, so a generous per-input ceiling reliably catches it
 * without being flaky on slow CI. Inputs are adversarial: long runs of each
 * regex's trigger prefix, near-misses, and comment/string-lexer stressors.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

import { detectFile, detectors } from "../src/index.js";

const BUDGET_MS = 2000;
const toggles = { source: true, config: true, deps: true };

function elapsed(file: string, content: string): number {
  const t = performance.now();
  detectFile(file, content, detectors, toggles);
  return performance.now() - t;
}

test("detectFile stays linear-time on adversarial inputs (no catastrophic backtracking)", () => {
  const N = 20_000;
  const inputs: Array<[string, string]> = [
    // Repeated trigger prefixes / near-misses across languages.
    ["a.ts", "createECDH ".repeat(N)],
    ["a.ts", "generateKeyPair(".repeat(N)],
    ["a.ts", "subtle.deriveBits(".repeat(N)],
    ["a.ts", "crypto.sign(".repeat(N)],
    ["a.ts", "new EC('secp" + "2".repeat(N)],
    ["a.ts", "ciphers: '" + "A".repeat(N) + "'"], // bounded cipher regex
    ["a.py", "rsa.generate_private_key(".repeat(N)],
    ["a.go", "rsa.GenerateKey(".repeat(N)],
    ["a.rs", "p256::ecdsa::SigningKey".repeat(N)],
    ["A.java", 'Signature.getInstance("SHA256withRSA")'.repeat(N / 4)],
    // Comment / string lexer stressors.
    ["q.ts", '"'.repeat(N)],
    ["q.ts", "/*".repeat(N)],
    ["q.ts", "//".repeat(N)],
    ["q.ts", "`".repeat(N)],
    ["q.py", "#".repeat(N)],
    // Config detectors: trigger prefixes with no terminating match (the bounded
    // scans must not backtrack over the whole line for each occurrence).
    ["server.properties", "ssl.protocol=".repeat(N)],
    ["server.properties", "ssl.cipher.suites=".repeat(N)],
    [".github/workflows/x.yml", "gpg ".repeat(N)],
    [".github/workflows/x.yml", "codesign ".repeat(N)],
  ];
  for (const [file, content] of inputs) {
    const ms = elapsed(file, content);
    assert.ok(
      ms < BUDGET_MS,
      `${file} (${content.length} chars) took ${ms.toFixed(0)}ms (budget ${BUDGET_MS}ms) — possible ReDoS`,
    );
  }
});
