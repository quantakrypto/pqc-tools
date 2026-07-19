/**
 * Tests for the human report's coverage-honesty behaviour: a 100/100 on a
 * codebase with zero analyzable source must NOT read as a clean bill of health.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { renderCbom, renderHuman, renderSarif } from "../src/index.js";
import { ANALYZABLE_LANGUAGES_LABEL } from "@quantakrypto/core";
import type { CycloneDxBom } from "@quantakrypto/core";
import { makeFinding, makeResult } from "./helpers.js";

test("renderCbom merges an external CBOM into the scan CBOM (combined code + infra)", () => {
  const result = makeResult([makeFinding()]); // one RSA component
  const scanOnly = JSON.parse(renderCbom(result)) as CycloneDxBom;
  const extra = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    components: [
      {
        type: "cryptographic-asset",
        "bom-ref": "infra-ecdsa-endpoint",
        name: "ECDSA",
        cryptoProperties: { assetType: "algorithm" },
      },
    ],
  } as unknown as CycloneDxBom;
  const merged = JSON.parse(renderCbom(result, [extra])) as CycloneDxBom;
  assert.equal(merged.bomFormat, "CycloneDX");
  assert.ok(
    merged.components.length > scanOnly.components.length,
    "merged CBOM has more components than the scan alone",
  );
  assert.ok(
    merged.components.some((c) => c["bom-ref"] === "infra-ecdsa-endpoint"),
    "the external infra component is present in the merged CBOM",
  );
});

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

test("renderHuman --tier category-5 surfaces the CNSA 2.0 migration targets", () => {
  const result = makeResult([makeFinding({ algorithm: "RSA" })]);
  const out = renderHuman(result, { tier: "category-5" });
  assert.match(out, /CNSA 2\.0 \(Category 5\) migration targets/);
  assert.match(out, /ML-KEM-1024/);
  // Without --tier the CNSA footer is absent (opt-in).
  assert.doesNotMatch(renderHuman(result), /CNSA 2\.0 \(Category 5\)/);
});

test("renderHuman surfaces the PQC standards-&-timeline footer when there are findings", () => {
  const out = renderHuman(makeResult([makeFinding({ algorithm: "RSA" })]));
  assert.match(out, /Standards & timeline/);
  // The IR 8547 deprecation deadline is the actionable long-horizon fact.
  assert.match(out, /IR 8547/);
  assert.match(out, /2035/);
});

test("renderHuman adds the stateful-HBS note only when a signature finding is present", () => {
  const sig = makeFinding({ category: "signature", algorithm: "ECDSA", ruleId: "ecdsa-sign" });
  const sigOut = renderHuman(makeResult([sig]));
  assert.match(sigOut, /SP 800-208/);
  assert.match(sigOut, /never reuse a one-time key index/);
  // A non-signature finding (KEM) gets the transition note but not the HBS one.
  const kemOut = renderHuman(makeResult([makeFinding({ algorithm: "RSA" })]));
  assert.match(kemOut, /Standards & timeline/);
  assert.doesNotMatch(kemOut, /SP 800-208/);
});

test("renderHuman omits the standards footer on a clean scan", () => {
  // No findings → no long-horizon footer (the clean-path early return).
  assert.doesNotMatch(renderHuman(makeResult([])), /Standards & timeline/);
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

test("renderHuman warns when the analyzable subset is a small slice of the scan", () => {
  // 200 scanned, only 8 analyzable (4%) with a finding present → the score
  // covers only that slice; say so.
  const result = {
    ...makeResult([makeFinding({ algorithm: "RSA" })]),
    filesScanned: 200,
    analyzedFiles: 8,
  };
  const out = renderHuman(result);
  assert.match(out, /score covers only 8 analyzable of 200 scanned files/);
  assert.match(out, /not reflected/);
});

test("renderHuman shows no partial-coverage caveat when most files are analyzable", () => {
  const result = {
    ...makeResult([makeFinding({ algorithm: "RSA" })]),
    filesScanned: 10,
    analyzedFiles: 9,
  };
  assert.doesNotMatch(renderHuman(result), /score covers only/);
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

test("next step for a dependency finding says 'replace', not 'migrate package.json'", () => {
  const dep = makeFinding({
    ruleId: "dep-vulnerable",
    category: "dependency",
    title: "Quantum-vulnerable dependency: node-forge",
    message: "node-forge — classical RSA/ECDSA.",
    location: { file: "package.json", line: 4 },
  });
  const out = renderHuman(makeResult([dep]));
  assert.match(out, /replace the vulnerable dependency in package\.json/);
  assert.doesNotMatch(out, /migrate package\.json/);
});

test("SARIF advertises a GENERIC dep-vulnerable rule (no per-package leak)", () => {
  // Two dependency findings with distinct package-specific titles. The shared
  // rule's shortDescription must be generic, not either package's title.
  const findings = [
    makeFinding({
      ruleId: "dep-vulnerable",
      category: "dependency",
      title: "Quantum-vulnerable dependency: node-forge",
      message: "node-forge — classical RSA.",
      location: { file: "package.json", line: 3 },
    }),
    makeFinding({
      ruleId: "dep-vulnerable",
      category: "dependency",
      title: "Quantum-vulnerable dependency: elliptic",
      message: "elliptic — classical ECDSA.",
      location: { file: "package.json", line: 5 },
    }),
  ];
  const sarif = JSON.parse(renderSarif(makeResult(findings))) as {
    runs: { tool: { driver: { rules: { id: string; shortDescription: { text: string } }[] } } }[];
  };
  const rules = sarif.runs[0].tool.driver.rules;
  const depRule = rules.find((r) => r.id === "dep-vulnerable");
  assert.ok(depRule, "the dep-vulnerable rule is advertised");
  assert.equal(depRule.shortDescription.text, "Quantum-vulnerable dependency");
  // It must not carry either finding's package-specific title.
  assert.doesNotMatch(depRule.shortDescription.text, /node-forge|elliptic/);
});
