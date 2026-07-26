/**
 * qScan HNDL wiring: `--hndl` threads exposure into the JSON/SARIF reports and
 * never changes the exit code; `qscan hndl init` scaffolds an hndl.yml.
 */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { parseArgs } from "../src/args.js";
import { EXIT, renderReport, runHndlInit, runQscan } from "../src/index.js";
import { makeFinding, makeResult } from "./helpers.js";

const HNDL_YML = `version: 1
horizon:
  quantum_threat_years: 10
  migration_horizon_years: 5
defaults:
  classification: internal
assets:
  - key: customer-pii
    name: Customer PII
    classification: regulated
    retention_years: 7
    secrecy_lifetime_years: 25
    paths:
      - "src/**"
`;

async function withRepo<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "qscan-hndl-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("parseArgs: --hndl sets the flag; hndl init dispatches to the subcommand", () => {
  const run = parseArgs(["--hndl", "."]);
  assert.equal(run.kind, "run");
  if (run.kind === "run") assert.equal(run.options.hndl, true);

  const init = parseArgs(["hndl", "init", "src"]);
  assert.equal(init.kind, "hndl-init");
  if (init.kind === "hndl-init") assert.equal(init.options.path, "src");

  assert.throws(() => parseArgs(["hndl", "bogus"]), /unknown hndl subcommand/);
  assert.throws(() => parseArgs(["hndl"]), /requires a subcommand/);
});

test("runQscan --hndl: exposure is added and the exit code is unchanged", async () => {
  await withRepo(async (dir) => {
    await writeFile(join(dir, "hndl.yml"), HNDL_YML);
    const f = makeFinding({
      ruleId: "cloud-kms-rsa",
      location: { file: "src/db/kms.ts", line: 3 },
    });
    const result = makeResult([f], dir);

    // Baseline (no --hndl) exit code, for comparison.
    const base = await runQscan(
      { path: dir, severityThreshold: "high" },
      { scanFn: async () => result },
    );
    const withHndl = await runQscan(
      { path: dir, severityThreshold: "high", hndl: true, format: "json" },
      { scanFn: async () => result },
    );
    // Additive: the exit code is identical with and without --hndl.
    assert.equal(withHndl.exitCode, base.exitCode);
    assert.equal(withHndl.exitCode, EXIT.FINDINGS);

    const json = JSON.parse(withHndl.report ?? "{}");
    assert.equal(json.hndl.summary.findingsScored, 1);
    assert.equal(json.hndl.summary.maxExposure, 53);
    assert.equal(json.findings[0].exposure.dataAsset, "customer-pii");
    assert.equal(json.findings[0].exposure.exposureScore, 53);
    assert.ok(typeof json.findings[0].exposure.fingerprint === "string");
  });
});

test("runQscan --hndl: a missing hndl.yml is a loud error", async () => {
  await withRepo(async (dir) => {
    const result = makeResult([makeFinding()], dir);
    await assert.rejects(
      () => runQscan({ path: dir, hndl: true }, { scanFn: async () => result }),
      /hndl\.yml not found/,
    );
  });
});

test("renderReport: SARIF carries the HNDL summary + per-result exposure", async () => {
  await withRepo(async (dir) => {
    await writeFile(join(dir, "hndl.yml"), HNDL_YML);
    const f = makeFinding({
      ruleId: "cloud-kms-rsa",
      location: { file: "src/db/kms.ts", line: 3 },
    });
    const run = await runQscan(
      { path: dir, hndl: true, format: "sarif" },
      { scanFn: async () => makeResult([f], dir) },
    );
    const sarif = JSON.parse(run.report ?? "{}");
    assert.equal(sarif.runs[0].properties.hndl.summary.maxExposure, 53);
    const props = sarif.runs[0].results[0].properties;
    assert.equal(props.exposureScore, 53);
    assert.equal(props.dataAsset, "customer-pii");
    assert.equal(props.exposureRationale.moscaBreach, true);
  });
});

test("renderReport: human output includes an HNDL exposure section", async () => {
  const f = makeFinding({ ruleId: "cloud-kms-rsa", location: { file: "src/db/kms.ts", line: 3 } });
  const result = makeResult([f]);
  const { computeHndl, parseHndlMap } = await import("@quantakrypto/core");
  const hndl = computeHndl(result.findings, parseHndlMap(HNDL_YML));
  const text = renderReport(result, "human", { hndl });
  assert.match(text, /HNDL exposure/);
  assert.match(text, /Top exposures/);
  assert.match(text, /customer-pii/);
  // The max-exposure score value is rendered (regression: it was dropped once).
  assert.match(text, /max exposure 53\/100/);
});

test("runHndlInit: scaffolds a file and reports the seed count", async () => {
  await withRepo(async (dir) => {
    const f = makeFinding({
      ruleId: "cloud-kms-rsa",
      location: { file: "src/db/kms.ts", line: 3 },
    });
    const init = await runHndlInit({ path: dir }, { scanFn: async () => makeResult([f], dir) });
    assert.equal(init.exists, false);
    assert.equal(init.seededFindings, 1);
    assert.ok(init.path.endsWith("hndl.yml"));
    assert.match(init.content, /assets:/);

    // Writing it and re-running init detects the existing file.
    await writeFile(init.path, init.content);
    const again = await runHndlInit({ path: dir }, { scanFn: async () => makeResult([f], dir) });
    assert.equal(again.exists, true);
    // The scaffold round-trips through the loader.
    const text = await readFile(init.path, "utf8");
    assert.match(text, /classification: confidential/);
  });
});
