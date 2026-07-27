/**
 * Tests for the HNDL (harvest-now-decrypt-later) data-risk quantifier: the
 * hand-rolled hndl.yml parser, glob matching, finding→asset binding, the Mosca
 * exposure math, the repo summary, and the `hndl init` scaffold.
 */
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  computeHndl,
  globMatch,
  loadHndlMap,
  moscaFactor,
  parseHndlMap,
  scaffoldHndlYaml,
  vulnerabilityFactor,
  HndlError,
  DEFAULT_QUANTUM_THREAT_YEARS,
  DEFAULT_MIGRATION_HORIZON_YEARS,
} from "../src/hndl.js";
import type { Finding, HndlMap } from "../src/index.js";

/** A minimal finding builder. */
function finding(over: Partial<Finding> & { ruleId: string; file: string }): Finding {
  return {
    ruleId: over.ruleId,
    title: over.title ?? over.ruleId,
    category: over.category ?? "kem",
    severity: over.severity ?? "high",
    confidence: over.confidence ?? "high",
    hndl: over.hndl ?? true,
    message: over.message ?? "test finding",
    location: { file: over.file, line: over.location?.line ?? 1, snippet: over.location?.snippet },
    ...(over.algorithm ? { algorithm: over.algorithm } : {}),
  } as Finding;
}

/* -------------------------------------------------------------------------- */
/* Parser                                                                     */
/* -------------------------------------------------------------------------- */

test("parseHndlMap: full document with horizon, defaults, assets, scopes", () => {
  const map = parseHndlMap(`
version: 1
horizon:
  quantum_threat_years: 12
  migration_horizon_years: 4
defaults:
  classification: confidential
assets:
  - key: customer-pii
    name: Customer PII store
    classification: regulated
    retention_years: 7
    secrecy_lifetime_years: 25
    paths:
      - "src/db/**"
      - "services/pii/**"
    scopes:
      - config
      - source
  - key: logs
    name: Application logs
    classification: internal
    retention_years: 1
    secrecy_lifetime_years: 2
    paths:
      - "logs/**"
`);
  assert.equal(map.version, 1);
  assert.deepEqual(map.horizon, { quantumThreatYears: 12, migrationHorizonYears: 4 });
  assert.equal(map.defaults.classification, "confidential");
  assert.equal(map.assets.length, 2);
  const pii = map.assets[0]!;
  assert.equal(pii.key, "customer-pii");
  assert.equal(pii.name, "Customer PII store");
  assert.equal(pii.classification, "regulated");
  assert.equal(pii.retentionYears, 7);
  assert.equal(pii.secrecyLifetimeYears, 25);
  assert.deepEqual(pii.paths, ["src/db/**", "services/pii/**"]);
  assert.deepEqual(pii.scopes, ["config", "source"]);
  assert.equal(map.assets[1]!.scopes, undefined);
});

test("parseHndlMap: applies defaults when horizon/defaults/version omitted", () => {
  const map = parseHndlMap(`
assets:
  - key: a
    name: A
    classification: internal
    retention_years: 3
    secrecy_lifetime_years: 3
    paths:
      - "*"
`);
  assert.equal(map.version, 1);
  assert.equal(map.horizon.quantumThreatYears, DEFAULT_QUANTUM_THREAT_YEARS);
  assert.equal(map.horizon.migrationHorizonYears, DEFAULT_MIGRATION_HORIZON_YEARS);
  assert.equal(map.defaults.classification, "internal");
});

test("parseHndlMap: comments, blank lines, and inline comments are ignored", () => {
  const map = parseHndlMap(`
# top comment
version: 1   # inline
assets:
  # asset comment
  - key: a
    name: "A # not a comment"
    classification: public
    retention_years: 0
    secrecy_lifetime_years: 0
    paths:
      - "a/**"
`);
  assert.equal(map.assets[0]!.name, "A # not a comment");
});

test("parseHndlMap: empty assets list is valid", () => {
  const map = parseHndlMap(`version: 1\nassets: []`);
  assert.deepEqual(map.assets, []);
});

test("parseHndlMap: rejects unknown classification", () => {
  assert.throws(
    () =>
      parseHndlMap(`
assets:
  - key: a
    name: A
    classification: secret
    retention_years: 1
    secrecy_lifetime_years: 1
    paths:
      - "a"
`),
    HndlError,
  );
});

test("parseHndlMap: rejects duplicate asset keys", () => {
  assert.throws(
    () =>
      parseHndlMap(`
assets:
  - key: a
    name: A
    classification: public
    retention_years: 1
    secrecy_lifetime_years: 1
    paths: ["a"]
  - key: a
    name: B
    classification: public
    retention_years: 1
    secrecy_lifetime_years: 1
    paths: ["b"]
`),
    /duplicate asset key/,
  );
});

test("parseHndlMap: rejects negative retention and missing paths", () => {
  assert.throws(
    () =>
      parseHndlMap(
        `assets:\n  - key: a\n    name: A\n    classification: public\n    retention_years: -1\n    secrecy_lifetime_years: 1\n    paths: ["a"]`,
      ),
    /retention_years/,
  );
  assert.throws(
    () =>
      parseHndlMap(
        `assets:\n  - key: a\n    name: A\n    classification: public\n    retention_years: 1\n    secrecy_lifetime_years: 1\n    paths: []`,
      ),
    /at least one glob/,
  );
});

test("parseHndlMap: inline-flow list syntax parses for paths", () => {
  const map = parseHndlMap(
    `assets:\n  - key: a\n    name: A\n    classification: public\n    retention_years: 1\n    secrecy_lifetime_years: 1\n    paths: ["src/**", "lib/**"]`,
  );
  assert.deepEqual(map.assets[0]!.paths, ["src/**", "lib/**"]);
});

test("parseHndlMap: rejects tab indentation", () => {
  assert.throws(() => parseHndlMap("assets:\n\t- key: a"), /tabs are not allowed/);
});

/* -------------------------------------------------------------------------- */
/* Glob matching                                                              */
/* -------------------------------------------------------------------------- */

test("globMatch: * does not cross path separators, ** does", () => {
  assert.equal(globMatch("src/*.ts", "src/a.ts"), true);
  assert.equal(globMatch("src/*.ts", "src/nested/a.ts"), false);
  assert.equal(globMatch("src/**", "src/nested/deep/a.ts"), true);
  assert.equal(globMatch("src/**/a.ts", "src/a.ts"), true);
  assert.equal(globMatch("src/**/a.ts", "src/x/y/a.ts"), true);
  assert.equal(globMatch("*", "top.ts"), true);
  assert.equal(globMatch("*", "src/top.ts"), false);
  assert.equal(globMatch("db?.sql", "db1.sql"), true);
  assert.equal(globMatch("db?.sql", "db12.sql"), false);
});

test("globMatch: regex metacharacters in the glob are literal", () => {
  assert.equal(globMatch("a.b+c", "a.b+c"), true);
  assert.equal(globMatch("a.b+c", "axbxc"), false);
});

/* -------------------------------------------------------------------------- */
/* Mosca math                                                                 */
/* -------------------------------------------------------------------------- */

test("moscaFactor: fraction of protection horizon past the threat", () => {
  // X=25, Y=5, Z=10 → (25+5-10)/(25+5) = 20/30 ≈ 0.667
  assert.equal(
    Math.round(moscaFactor(25, { quantumThreatYears: 10, migrationHorizonYears: 5 }) * 1000),
    667,
  );
  // Threat beyond the whole horizon → 0 (no HNDL risk).
  assert.equal(moscaFactor(2, { quantumThreatYears: 30, migrationHorizonYears: 3 }), 0);
  // Threat already here → 1.
  assert.equal(moscaFactor(5, { quantumThreatYears: 0, migrationHorizonYears: 5 }), 1);
  // Degenerate zero horizon → 0 (no divide-by-zero).
  assert.equal(moscaFactor(0, { quantumThreatYears: 0, migrationHorizonYears: 0 }), 0);
});

test("vulnerabilityFactor: severity x confidence, discounted when not HNDL", () => {
  assert.equal(vulnerabilityFactor(finding({ ruleId: "r", file: "a", severity: "critical" })), 1);
  assert.equal(
    vulnerabilityFactor(
      finding({ ruleId: "r", file: "a", severity: "high", confidence: "medium" }),
    ),
    0.8 * 0.85,
  );
  // A non-HNDL (e.g. signature) finding is heavily discounted.
  const sig = finding({ ruleId: "r", file: "a", severity: "high", hndl: false });
  assert.ok(vulnerabilityFactor(sig) < 0.2);
});

/* -------------------------------------------------------------------------- */
/* Binding + exposure                                                         */
/* -------------------------------------------------------------------------- */

const MOSCA_MAP: HndlMap = {
  version: 1,
  horizon: { quantumThreatYears: 10, migrationHorizonYears: 5 },
  defaults: { classification: "internal" },
  assets: [
    {
      key: "customer-pii",
      name: "Customer PII",
      classification: "regulated",
      retentionYears: 7,
      secrecyLifetimeYears: 25,
      paths: ["src/db/**"],
    },
    {
      key: "public-site",
      name: "Public marketing site",
      classification: "public",
      retentionYears: 1,
      secrecyLifetimeYears: 1,
      paths: ["www/**"],
    },
  ],
};

test("computeHndl: the worked Mosca example scores 53", () => {
  const f = finding({ ruleId: "cloud-kms-rsa", file: "src/db/kms.ts", severity: "high" });
  const report = computeHndl([f], MOSCA_MAP);
  const exp = report.exposures[0]!;
  // V=0.8, S=1.0, M=20/30=0.667 → round(100*0.533)=53.
  assert.equal(exp.exposureScore, 53);
  assert.equal(exp.dataAsset, "customer-pii");
  assert.equal(exp.rationale.moscaBreach, true);
  assert.equal(exp.rationale.moscaMarginYears, 20);
  assert.equal(exp.rationale.bound, true);
});

test("computeHndl: low-sensitivity asset that outlives nothing scores near zero", () => {
  const f = finding({ ruleId: "cloud-kms-rsa", file: "www/index.ts", severity: "high" });
  const report = computeHndl([f], MOSCA_MAP);
  const exp = report.exposures[0]!;
  // X=1, Y=5, Z=10 → margin -4 → M=0 → score 0.
  assert.equal(exp.exposureScore, 0);
  assert.equal(exp.rationale.moscaBreach, false);
  assert.equal(exp.dataAsset, "public-site");
});

test("computeHndl: unbound finding uses defaults and is flagged bound:false", () => {
  const f = finding({ ruleId: "cloud-kms-rsa", file: "misc/other.ts", severity: "high" });
  const report = computeHndl([f], MOSCA_MAP);
  const exp = report.exposures[0]!;
  assert.equal(exp.dataAsset, null);
  assert.equal(exp.rationale.bound, false);
  assert.equal(exp.rationale.classification, "internal");
  // Unbound findings assume the minimum-concern horizon X = Z (secrecy lifetime =
  // quantumThreatYears), so `defaults.classification` yields a real, rankable
  // exposure instead of a dead 0. Here Z=10, Y=5: X=10, retention=0, secrecy=10,
  // margin = 10+5-10 = 5 (Mosca breached), M = 5/15 = 0.333. V=0.8, S=0.4 (internal)
  // → round(100 · 0.8 · 0.4 · 0.333) = 11.
  assert.equal(exp.rationale.secrecyLifetimeYears, 10);
  assert.equal(exp.rationale.retentionYears, 0);
  assert.equal(exp.rationale.secrecyHorizonYears, 10);
  assert.equal(exp.rationale.moscaMarginYears, 5);
  assert.equal(exp.rationale.moscaBreach, true);
  assert.equal(exp.exposureScore, 11);
});

test("computeHndl: overlapping assets pick the worst-case (highest) exposure", () => {
  const map: HndlMap = {
    ...MOSCA_MAP,
    assets: [
      { ...MOSCA_MAP.assets[0]!, paths: ["src/**"] },
      {
        key: "low",
        name: "Low",
        classification: "public",
        retentionYears: 1,
        secrecyLifetimeYears: 1,
        paths: ["src/**"],
      },
    ],
  };
  const f = finding({ ruleId: "cloud-kms-rsa", file: "src/db/kms.ts", severity: "high" });
  const report = computeHndl([f], map);
  assert.equal(report.exposures[0]!.dataAsset, "customer-pii");
  assert.equal(report.exposures[0]!.exposureScore, 53);
});

test("computeHndl: scope-bound asset only binds matching-scope findings", () => {
  const map: HndlMap = {
    ...MOSCA_MAP,
    assets: [{ ...MOSCA_MAP.assets[0]!, paths: ["src/**"], scopes: ["source"] }],
  };
  // cloud-kms-rsa is a config-scope rule; the source-only asset must NOT bind it.
  const f = finding({ ruleId: "cloud-kms-rsa", file: "src/db/kms.ts" });
  const report = computeHndl([f], map);
  assert.equal(report.exposures[0]!.dataAsset, null);
  assert.equal(report.exposures[0]!.rationale.bound, false);
});

test("computeHndl: summary rolls up max/mean/breaches and top exposures", () => {
  const findings = [
    finding({ ruleId: "cloud-kms-rsa", file: "src/db/a.ts", severity: "critical" }),
    finding({ ruleId: "cloud-kms-rsa", file: "src/db/b.ts", severity: "low" }),
    finding({ ruleId: "cloud-kms-rsa", file: "www/c.ts", severity: "high" }),
  ];
  const report = computeHndl(findings, MOSCA_MAP);
  assert.equal(report.summary.findingsScored, 3);
  assert.equal(report.summary.assetsDeclared, 2);
  assert.equal(report.summary.assetsWithFindings, 2);
  assert.equal(report.summary.assetsOutlivingHorizon, 1); // only PII (25 > 10)
  assert.equal(report.summary.maxExposure, report.summary.topExposures[0]!.exposureScore);
  assert.ok(report.summary.moscaBreaches >= 1);
  // byFingerprint indexes every exposure.
  for (const e of report.exposures) {
    assert.equal(report.byFingerprint.get(e.fingerprint), e);
  }
});

/* -------------------------------------------------------------------------- */
/* Scaffold + load                                                            */
/* -------------------------------------------------------------------------- */

test("scaffoldHndlYaml: seeds an asset per data-adjacent directory and round-trips", () => {
  // Both rules are config-scope (cloud-KMS) so they seed a per-directory stub.
  const findings = [
    finding({ ruleId: "cloud-kms-rsa", file: "src/db/kms.ts", category: "kem", hndl: true }),
    finding({
      ruleId: "cloud-kms-ec",
      file: "config/infra.tf",
      category: "key-exchange",
      hndl: true,
    }),
  ];
  const yaml = scaffoldHndlYaml(findings);
  const map = parseHndlMap(yaml); // must be valid hndl.yml
  const keys = map.assets.map((a) => a.key).sort();
  assert.deepEqual(keys, ["config", "src"]);
  assert.equal(map.horizon.quantumThreatYears, DEFAULT_QUANTUM_THREAT_YEARS);
});

test("scaffoldHndlYaml: emits a manual example when nothing data-adjacent is found", () => {
  const yaml = scaffoldHndlYaml([]);
  const map = parseHndlMap(yaml);
  assert.equal(map.assets.length, 1);
  assert.equal(map.assets[0]!.key, "customer-pii");
});

test("loadHndlMap: reads and validates a file; missing file throws HndlError", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hndl-"));
  try {
    await writeFile(
      join(dir, "hndl.yml"),
      `assets:\n  - key: a\n    name: A\n    classification: public\n    retention_years: 1\n    secrecy_lifetime_years: 1\n    paths: ["a/**"]`,
    );
    const { map, path } = await loadHndlMap(dir);
    assert.equal(map.assets[0]!.key, "a");
    assert.ok(path.endsWith("hndl.yml"));
    await assert.rejects(() => loadHndlMap(join(dir, "missing")), HndlError);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
