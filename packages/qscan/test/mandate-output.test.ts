/**
 * runQscan --mandate wiring: the compliance evaluation must reach the
 * machine-readable JSON / SARIF / evidence outputs (not just the human block),
 * and the --policy composition must exempt acknowledged findings from the early
 * gate while a raw prohibited finding still trips --fail-now.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { EXIT, fingerprint, runQscan } from "../src/index.js";
import { makeResult, makeFinding } from "./helpers.js";
import type { ReadinessReport } from "@quantakrypto/core";

/** Inject a scanner returning a single RSA finding (a mandate-prohibited family). */
function rsaScanner() {
  return { scanFn: async () => makeResult([makeFinding({ algorithm: "RSA", severity: "high" })]) };
}

test("--mandate --format json carries a machine-readable mandateMapping", async () => {
  const run = await runQscan({ path: ".", mandates: ["cnsa-2.0"], format: "json" }, rsaScanner());
  const json = JSON.parse(run.report ?? "{}") as Record<string, any>;
  assert.ok(json.mandateMapping, "mandateMapping present in JSON output");
  assert.deepEqual(json.mandateMapping.mandates, ["cnsa-2.0"]);
  assert.equal(json.mandateMapping.findings.length, 1);
});

test("--mandate --format sarif carries the evaluation under run.properties", async () => {
  const run = await runQscan({ path: ".", mandates: ["cnsa-2.0"], format: "sarif" }, rsaScanner());
  const sarif = JSON.parse(run.report ?? "{}");
  const props = sarif.runs[0].properties;
  assert.ok(props?.mandate, "run.properties.mandate present");
  assert.deepEqual(props.mandate.mandates, ["cnsa-2.0"]);
});

test("--mandate --format evidence embeds a date-pinned, hashed mandateMapping", async () => {
  const run = await runQscan(
    { path: ".", mandates: ["cnsa-2.0"], format: "evidence" },
    rsaScanner(),
  );
  const report = JSON.parse(run.report ?? "{}") as ReadinessReport;
  assert.ok(report.mandateMapping, "evidence report carries mandateMapping");
  assert.match(report.mandateMapping.now, /^\d{4}-\d{2}-\d{2}$/, "now is date-pinned");
  assert.match(report.attestation.contentHash, /^sha256:[0-9a-f]{64}$/);
});

test("--baseline does NOT waive the mandate gate (evaluated on pre-baseline findings)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-mandate-bl-"));
  try {
    const finding = makeFinding({ algorithm: "RSA", severity: "high" });
    const baselinePath = join(dir, "baseline.json");
    // Baseline that suppresses exactly this finding.
    await writeFile(
      baselinePath,
      JSON.stringify({ version: 1, fingerprints: [fingerprint(finding)] }),
      "utf8",
    );
    const run = await runQscan(
      {
        path: ".",
        mandates: ["cnsa-2.0"],
        failNow: true,
        severityThreshold: "critical",
        baseline: baselinePath,
        format: "json",
      },
      { scanFn: async () => makeResult([finding]) },
    );
    // The finding is baselined out of the findings array...
    assert.equal(run.suppressed.length, 1, "finding suppressed by the baseline");
    assert.equal(run.result.findings.length, 0);
    // ...but the mandate gate still sees it (a deadline is not baseline-waivable):
    assert.equal(run.exitCode, EXIT.FINDINGS, "--fail-now still trips on the baselined finding");
    const json = JSON.parse(run.report ?? "{}") as Record<string, any>;
    assert.equal(
      json.mandateMapping.findings.length,
      1,
      "mandateMapping covers the baselined crypto",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--policy exempts an acknowledged family from --fail-now; raw crypto still trips it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qscan-mandate-"));
  try {
    const policyPath = join(dir, "policy.json");
    await writeFile(policyPath, JSON.stringify({ name: "org", inTransition: ["RSA"] }), "utf8");

    // severityThreshold "critical" so the lone high finding does not drive the
    // base exit code — only the mandate gate does. Without a policy, --fail-now
    // fails on the prohibited RSA finding.
    const noPolicy = await runQscan(
      { path: ".", mandates: ["cnsa-2.0"], failNow: true, severityThreshold: "critical" },
      rsaScanner(),
    );
    assert.equal(noPolicy.exitCode, EXIT.FINDINGS, "--fail-now trips on raw prohibited crypto");

    // With the org policy tracking RSA (inTransition → acknowledged), the same
    // --fail-now run is exempt.
    const withPolicy = await runQscan(
      {
        path: ".",
        mandates: ["cnsa-2.0"],
        failNow: true,
        severityThreshold: "critical",
        policy: policyPath,
      },
      rsaScanner(),
    );
    assert.equal(withPolicy.exitCode, EXIT.OK, "acknowledged family is exempt from --fail-now");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
