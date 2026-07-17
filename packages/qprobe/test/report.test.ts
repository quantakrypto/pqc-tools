import { test } from "node:test";
import assert from "node:assert/strict";
import { buildInventory } from "@quantakrypto/core";
import { classifyTls } from "../src/classify.js";
import { toSarifReport, toCbomReport, toJsonReport } from "../src/report.js";
import type { RunResult } from "../src/index.js";
import type { Target } from "../src/target.js";

const target: Target = { host: "example.com", port: 443 };

function sampleRun(): RunResult {
  const tls = {
    protocol: "TLSv1.3",
    cipher: "TLS_AES_128_GCM_SHA256",
    kexGroup: "X25519",
    certKeyType: "RSA",
    certKeyBits: 2048,
  };
  const hybrid = { hybridSelected: false };
  const findings = classifyTls(target, tls, hybrid);
  return {
    reports: [{ target, mode: "tls", tls, hybrid, positives: [], findings }],
    findings,
    inventory: buildInventory(findings),
  };
}

const T0 = "2026-07-17T00:00:00.000Z";
const T1 = "2026-07-17T00:00:01.000Z";

test("qprobe emits SARIF 2.1.0 with a rule per finding (no registry needed)", () => {
  const run = sampleRun();
  const sarif = toSarifReport(run, T0, T1);
  assert.equal(sarif.version, "2.1.0");
  const driverRun = sarif.runs[0];
  assert.equal(driverRun.results.length, run.findings.length);
  const ruleIds = driverRun.tool.driver.rules.map((r) => (r as { id: string }).id);
  assert.ok(ruleIds.includes("qprobe-tls-classical-kex"));
});

test("qprobe emits a CycloneDX 1.6 CBOM with crypto-asset components", () => {
  const cbom = toCbomReport(sampleRun(), T0, T1);
  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.equal(cbom.specVersion, "1.6");
  assert.ok(cbom.components.length > 0);
});

test("qprobe JSON report carries the shared inventory + per-endpoint detail", () => {
  const json = toJsonReport(sampleRun(), T0, T1) as {
    inventory?: { readinessScore?: number };
    endpoints?: unknown[];
  };
  assert.equal(typeof json.inventory?.readinessScore, "number");
  assert.equal(json.endpoints?.length, 1);
});
