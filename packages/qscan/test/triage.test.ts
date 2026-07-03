/**
 * Tests for `qscan --triage` wiring. The load-bearing guarantees: triage never
 * drops a finding, never changes severities (so it can't change the exit code),
 * attaches verdicts and re-sorts by exposure, degrades without a key, and
 * `--dry-run` shows the payload without calling the provider.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { runTriage } from "../src/triage-run.js";
import { fingerprintFinding } from "../src/index.js";
import { makeResult, makeFinding } from "./helpers.js";
import type { TriageVerdict } from "@quantakrypto/core";

test("triage never drops a finding and never changes the count", async () => {
  const result = makeResult([
    makeFinding({ severity: "high" }),
    makeFinding({ severity: "low", location: { file: "b.ts", line: 2 } }),
  ]);
  const before = result.findings.length;
  await runTriage(result, { level: "metadata", floor: "medium", triageFn: async () => new Map() });
  assert.equal(result.findings.length, before);
});

test("triage preserves every finding's severity (so the exit code can't change)", async () => {
  const result = makeResult([
    makeFinding({ severity: "high" }),
    makeFinding({ severity: "medium", location: { file: "b.ts", line: 2 } }),
  ]);
  const before = result.findings.map((f) => f.severity).sort();
  await runTriage(result, { level: "metadata", floor: "medium", triageFn: async () => new Map() });
  assert.deepEqual(result.findings.map((f) => f.severity).sort(), before);
});

test("triage attaches verdicts and re-sorts by exposure (highest first)", async () => {
  const lowExp = makeFinding({ severity: "high", location: { file: "a.ts", line: 1 } });
  const highExp = makeFinding({ severity: "high", location: { file: "b.ts", line: 2 } });
  const result = makeResult([lowExp, highExp]);
  const verdicts = new Map<string, TriageVerdict>([
    [
      fingerprintFinding(lowExp),
      {
        fingerprint: fingerprintFinding(lowExp),
        exposureScore: 10,
        priority: "later",
        rationale: "x",
      },
    ],
    [
      fingerprintFinding(highExp),
      {
        fingerprint: fingerprintFinding(highExp),
        exposureScore: 90,
        priority: "now",
        rationale: "y",
      },
    ],
  ]);
  await runTriage(result, { level: "metadata", triageFn: async () => verdicts });
  assert.equal(result.findings[0].triage?.exposureScore, 90);
  assert.equal(result.findings[0].location.file, "b.ts");
});

test("no key and no injected fn → degrade gracefully, findings unchanged, notice written", async () => {
  const result = makeResult([makeFinding({ severity: "high" })]);
  let err = "";
  const out = await runTriage(result, {
    level: "metadata",
    resolveKey: () => undefined,
    stderr: (s) => (err += s),
  });
  assert.equal(out.preflight, undefined);
  assert.equal(result.findings.length, 1);
  assert.match(err, /needs an API key/);
});

test("--dry-run returns a preflight and never calls the triage fn", async () => {
  const result = makeResult([
    makeFinding({ severity: "high", location: { file: "a.ts", line: 1 } }),
  ]);
  let called = false;
  const out = await runTriage(result, {
    level: "metadata",
    dryRun: true,
    triageFn: async () => {
      called = true;
      return new Map();
    },
  });
  assert.equal(called, false);
  assert.match(out.preflight ?? "", /a\.ts/);
});
