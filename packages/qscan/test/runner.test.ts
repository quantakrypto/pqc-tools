/**
 * runQscan policy tests: threshold → exit code, baseline integration, and the
 * --write-baseline early exit. Uses an injected scanner so it does not depend
 * on core's (stub) `scan`.
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { EXIT, renderReport, runQscan } from "../src/index.js";
import { fingerprint } from "../src/baseline.js";
import { makeFinding, makeResult } from "./helpers.js";
import type { Finding, TriageVerdict } from "@quantakrypto/core";

/** Build hooks whose scanner returns a fixed result. */
function scannerFor(...findings: Parameters<typeof makeFinding>[0][]) {
  const result = makeResult(findings.map((f) => makeFinding(f)));
  return { scanFn: async () => ({ ...result }) };
}

test("exit code 1 when a finding meets the threshold", async () => {
  const run = await runQscan(
    { path: ".", severityThreshold: "high" },
    scannerFor({ severity: "high" }),
  );
  assert.equal(run.exitCode, EXIT.FINDINGS);
});

test("exit code 0 when all findings are below the threshold", async () => {
  const run = await runQscan(
    { path: ".", severityThreshold: "high" },
    scannerFor({ severity: "medium" }, { severity: "low" }),
  );
  assert.equal(run.exitCode, EXIT.OK);
});

test("threshold boundary is inclusive", async () => {
  const atThreshold = await runQscan(
    { path: ".", severityThreshold: "medium" },
    scannerFor({ severity: "medium" }),
  );
  assert.equal(atThreshold.exitCode, EXIT.FINDINGS);

  const below = await runQscan(
    { path: ".", severityThreshold: "medium" },
    scannerFor({ severity: "low" }),
  );
  assert.equal(below.exitCode, EXIT.OK);
});

test("no findings → exit 0", async () => {
  const run = await runQscan({ path: ".", severityThreshold: "info" }, scannerFor());
  assert.equal(run.exitCode, EXIT.OK);
  assert.equal(run.result.findings.length, 0);
});

test("triage NEVER changes the exit code and NEVER drops a finding (invariant)", async () => {
  // Inject a triage fn that annotates every finding with a LOW priority — i.e.
  // the model tried to de-prioritize a blocking finding. The exit code is
  // computed from raw severities BEFORE triage runs, so the build must still
  // fail, and every finding must survive (triage re-ranks, never suppresses).
  const high = makeFinding({ severity: "high", location: { file: "src/x.ts", line: 1 } });
  const low = makeFinding({ severity: "low", location: { file: "src/y.ts", line: 2 } });
  const triageFn = async (findings: readonly Finding[]) => {
    const m = new Map<string, TriageVerdict>();
    for (const f of findings) {
      m.set(fingerprint(f), { exposureScore: 1, priority: "low", rationale: "looks dormant" });
    }
    return m;
  };
  const run = await runQscan(
    { path: ".", severityThreshold: "high", triage: true },
    { ...scannerFor({ severity: "high" }), scanFn: async () => makeResult([high, low]), triageFn },
  );
  assert.equal(run.exitCode, EXIT.FINDINGS, "a blocking finding still fails CI after triage");
  assert.equal(run.result.findings.length, 2, "triage dropped no findings");
  // Triage operates on findings at/above the floor (default: medium). The high is
  // annotated; the below-floor low survives un-annotated (never dropped). This matches
  // the production agent, which re-applies the floor internally.
  const annotatedHigh = run.result.findings.find((f) => f.severity === "high");
  assert.equal(annotatedHigh?.triage?.priority, "low", "the at-floor finding was annotated");
  const untouchedLow = run.result.findings.find((f) => f.severity === "low");
  assert.equal(untouchedLow?.triage, undefined, "the below-floor finding is left un-annotated");
});

test("baseline suppresses a finding and can flip the exit code to 0", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-run-"));
  try {
    const finding = makeFinding({ severity: "critical", location: { file: "src/x.ts", line: 3 } });
    const baselinePath = join(dir, "b.json");

    // First, write a baseline capturing the one (critical) finding.
    const write = await runQscan(
      { path: ".", writeBaseline: baselinePath },
      { scanFn: async () => makeResult([finding]) },
    );
    assert.equal(write.exitCode, EXIT.OK);
    assert.ok(write.baselineWritten);
    assert.deepEqual(write.baselineWritten?.fingerprints, [fingerprint(finding)]);
    assert.equal(write.report, undefined, "no report on baseline write");

    // Now scan again with that baseline: the critical finding is suppressed →
    // exit 0 despite a critical-severity match.
    const run = await runQscan(
      { path: ".", baseline: baselinePath, severityThreshold: "critical" },
      { scanFn: async () => makeResult([finding]) },
    );
    assert.equal(run.exitCode, EXIT.OK);
    assert.equal(run.result.findings.length, 0);
    assert.equal(run.suppressed.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("baseline only suppresses matching fingerprints", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-run-"));
  try {
    const known = makeFinding({ location: { file: "src/known.ts", line: 1 } });
    const fresh = makeFinding({ severity: "critical", location: { file: "src/new.ts", line: 2 } });
    const baselinePath = join(dir, "b.json");

    await runQscan(
      { path: ".", writeBaseline: baselinePath },
      { scanFn: async () => makeResult([known]) },
    );

    const run = await runQscan(
      { path: ".", baseline: baselinePath, severityThreshold: "high" },
      { scanFn: async () => makeResult([known, fresh]) },
    );
    assert.equal(run.suppressed.length, 1);
    assert.equal(run.result.findings.length, 1);
    assert.equal(run.result.findings[0]?.location.file, "src/new.ts");
    assert.equal(run.exitCode, EXIT.FINDINGS);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--write-baseline writes a valid file to disk", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-run-"));
  try {
    const path = join(dir, "out.json");
    await runQscan(
      { path: ".", writeBaseline: path },
      { scanFn: async () => makeResult([makeFinding(), makeFinding({ ruleId: "ecdh-usage" })]) },
    );
    const parsed = JSON.parse(await readFile(path, "utf8"));
    assert.equal(parsed.version, 1);
    assert.equal(parsed.fingerprints.length, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("renderReport produces the requested format", () => {
  const result = makeResult([makeFinding()]);
  assert.match(renderReport(result, "human"), /qScan/);
  const json = JSON.parse(renderReport(result, "json"));
  assert.ok(json, "json parses");
  const sarif = JSON.parse(renderReport(result, "sarif"));
  assert.ok(sarif, "sarif parses");
});

test("human report mentions readiness score and a next step", async () => {
  const run = await runQscan({ path: "." }, scannerFor({ severity: "high" }));
  assert.match(run.report ?? "", /Readiness score:/);
  assert.match(run.report ?? "", /Next step:/);
});

test("clean scan reports zero findings", async () => {
  const run = await runQscan({ path: "." }, scannerFor());
  assert.match(run.report ?? "", /No quantum-vulnerable cryptography detected/);
});
