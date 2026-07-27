/**
 * Tests for the crypto-agility manifest: the emit shape (derived from a scan) and
 * the local validator (accept a good manifest, reject malformed ones).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildCryptoAgilityManifest,
  buildInventory,
  CRYPTO_AGILITY_MANIFEST_VERSION,
  validateCryptoAgilityManifest,
} from "../src/index.js";
import type { CryptoAgilityManifest, Finding, ScanResult } from "../src/index.js";

function result(findings: Finding[]): ScanResult {
  return {
    root: "/repo",
    findings,
    filesScanned: 3,
    inventory: buildInventory(findings),
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    toolVersion: "0.1.0",
  };
}

function f(over: Partial<Finding>): Finding {
  return {
    ruleId: "node-crypto-ecdh",
    title: "ECDH",
    category: "key-exchange",
    severity: "high",
    confidence: "high",
    algorithm: "ECDH",
    hndl: true,
    message: "ecdh",
    cwe: "CWE-327",
    location: { file: "src/a.ts", line: 10, snippet: "createECDH()" },
    ...over,
  };
}

const GENERATED_AT = "2026-07-27T12:00:00.000Z";

test("buildCryptoAgilityManifest derives posture + CBOM summary from the scan", () => {
  const findings = [
    f({ ruleId: "node-crypto-ecdh", algorithm: "ECDH", severity: "high" }),
    f({
      ruleId: "node-crypto-keygen",
      algorithm: "RSA",
      category: "signature",
      severity: "critical",
      location: { file: "src/b.ts", line: 4, snippet: "generateKeyPairSync('rsa')" },
    }),
  ];
  const m = buildCryptoAgilityManifest(result(findings), { generatedAt: GENERATED_AT });

  assert.equal(m.version, CRYPTO_AGILITY_MANIFEST_VERSION);
  assert.equal(m.manifestType, "crypto-agility");
  assert.equal(m.generatedAt, GENERATED_AT);
  assert.equal(m.generator.name, "qScan");
  assert.equal(m.generator.version, "0.1.0");
  assert.equal(m.subject.root, "/repo");
  assert.equal(m.subject.repository, null);
  assert.equal(m.subject.commit, null);

  // Posture mirrors the inventory.
  assert.equal(m.posture.readinessScore, result(findings).inventory.readinessScore);
  assert.equal(m.posture.quantumVulnerable.total, 2);
  assert.equal(m.posture.quantumVulnerable.bySeverity.critical, 1);
  assert.equal(m.posture.quantumVulnerable.bySeverity.high, 1);
  assert.equal(m.posture.hndlExposedCount, 2);
  // hybrid-KEX is undetermined by a static scan unless the operator asserts it.
  assert.equal(m.posture.hybridKexInUse, null);

  // CBOM summary: families in use + a link to the full CBOM by serial number.
  const families = m.cbomSummary.algorithmFamilies.map((x) => x.family).sort();
  assert.deepEqual(families, ["ECDH", "RSA"]);
  assert.ok(m.cbomSummary.algorithmFamilies.every((x) => x.quantumVulnerable === true));
  assert.match(m.cbomSummary.serialNumber, /^urn:uuid:[0-9a-f-]+$/);
  assert.ok(m.cbomSummary.assetCount >= 2);

  // Default policy: the NIST IR 8547 transition timeline.
  assert.equal(m.policy.deprecateClassicalAfter, 2030);
  assert.equal(m.policy.disallowClassicalAfter, 2035);
  assert.equal(m.policy.transitionDeadline, null);
  assert.match(m.policy.source, /IR 8547/);

  // No attestation unless supplied.
  assert.equal(m.attestation, undefined);
});

test("buildCryptoAgilityManifest records attestation, hybrid-KEX, and operator policy", () => {
  const m = buildCryptoAgilityManifest(result([f({})]), {
    generatedAt: GENERATED_AT,
    attestationUrl: "https://quantakrypto.com/attest/acme",
    hybridKexInUse: true,
    policy: { transitionDeadline: "2028-01-01" },
    repository: "github.com/acme/app",
    commit: "abc123",
  });
  assert.deepEqual(m.attestation, { url: "https://quantakrypto.com/attest/acme" });
  assert.equal(m.posture.hybridKexInUse, true);
  assert.equal(m.policy.source, "operator-declared");
  assert.equal(m.policy.transitionDeadline, "2028-01-01");
  assert.equal(m.subject.repository, "github.com/acme/app");
  assert.equal(m.subject.commit, "abc123");
});

test("a freshly-built manifest validates clean", () => {
  const m = buildCryptoAgilityManifest(result([f({}), f({ algorithm: "RSA" })]), {
    generatedAt: GENERATED_AT,
    attestationUrl: "https://example.com/cred",
  });
  const v = validateCryptoAgilityManifest(m);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
});

test("an empty scan yields a valid manifest (readiness 100, no families)", () => {
  const m = buildCryptoAgilityManifest(result([]), { generatedAt: GENERATED_AT });
  assert.equal(m.posture.quantumVulnerable.total, 0);
  assert.deepEqual(m.cbomSummary.algorithmFamilies, []);
  assert.equal(validateCryptoAgilityManifest(m).valid, true);
});

test("validate rejects a non-object", () => {
  for (const bad of [null, 42, "x", [], true]) {
    const v = validateCryptoAgilityManifest(bad);
    assert.equal(v.valid, false);
    assert.ok(v.errors.length > 0);
  }
});

test("validate rejects a wrong / missing version", () => {
  const base = buildCryptoAgilityManifest(result([f({})]), { generatedAt: GENERATED_AT });
  const wrong = { ...base, version: 99 } as CryptoAgilityManifest;
  const v = validateCryptoAgilityManifest(wrong);
  assert.equal(v.valid, false);
  assert.ok(v.errors.some((e) => e.includes("unsupported version 99")));

  const missing = { ...base } as Partial<CryptoAgilityManifest>;
  delete missing.version;
  const v2 = validateCryptoAgilityManifest(missing);
  assert.equal(v2.valid, false);
  assert.ok(v2.errors.some((e) => e.includes("missing required field: version")));
});

test("validate reports each structural / type problem", () => {
  const base = buildCryptoAgilityManifest(result([f({})]), { generatedAt: GENERATED_AT });

  // Missing required top-level blocks.
  for (const key of ["generatedAt", "posture", "cbomSummary", "policy", "subject"] as const) {
    const broken = { ...base } as Record<string, unknown>;
    delete broken[key];
    const v = validateCryptoAgilityManifest(broken);
    assert.equal(v.valid, false, `deleting ${key} should invalidate`);
    assert.ok(
      v.errors.some((e) => e.includes(`missing required field: ${key}`)),
      `expected a missing-${key} error, got ${JSON.stringify(v.errors)}`,
    );
  }

  // Bad field types.
  const badScore = structuredClone(base);
  badScore.posture.readinessScore = 250;
  assert.ok(
    validateCryptoAgilityManifest(badScore).errors.some((e) =>
      e.includes("posture.readinessScore"),
    ),
  );

  const badHybrid = structuredClone(base) as unknown as Record<string, { hybridKexInUse: unknown }>;
  (badHybrid.posture as { hybridKexInUse: unknown }).hybridKexInUse = "yes";
  assert.ok(
    validateCryptoAgilityManifest(badHybrid).errors.some((e) =>
      e.includes("posture.hybridKexInUse"),
    ),
  );

  const badSeverity = structuredClone(base);
  delete (badSeverity.posture.quantumVulnerable.bySeverity as Record<string, number>).critical;
  assert.ok(
    validateCryptoAgilityManifest(badSeverity).errors.some((e) =>
      e.includes("bySeverity.critical"),
    ),
  );

  const badAttestation = structuredClone(base) as CryptoAgilityManifest & {
    attestation: { url: unknown };
  };
  badAttestation.attestation = { url: 123 as unknown as string };
  assert.ok(
    validateCryptoAgilityManifest(badAttestation).errors.some((e) => e.includes("attestation.url")),
  );

  const badFamily = structuredClone(base);
  badFamily.cbomSummary.algorithmFamilies = [
    { family: 1 as unknown as string, count: -1, quantumVulnerable: "x" as unknown as boolean },
  ];
  const fv = validateCryptoAgilityManifest(badFamily);
  assert.ok(fv.errors.some((e) => e.includes("algorithmFamilies[0].family")));
  assert.ok(fv.errors.some((e) => e.includes("algorithmFamilies[0].count")));
  assert.ok(fv.errors.some((e) => e.includes("algorithmFamilies[0].quantumVulnerable")));
});

test("validate accepts a hand-written minimal manifest", () => {
  const minimal = {
    version: 1,
    manifestType: "crypto-agility",
    generatedAt: "2026-07-27T00:00:00.000Z",
    generator: { name: "qScan", version: "0.1.0" },
    subject: { root: ".", repository: null, commit: null },
    posture: {
      readinessScore: 100,
      hybridKexInUse: null,
      quantumVulnerable: {
        total: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      },
      hndlExposedCount: 0,
    },
    cbomSummary: { serialNumber: "urn:uuid:0", assetCount: 0, algorithmFamilies: [] },
    policy: {
      source: "NIST IR 8547",
      deprecateClassicalAfter: 2030,
      disallowClassicalAfter: 2035,
      transitionDeadline: null,
      citation: "NIST IR 8547",
    },
  };
  assert.equal(validateCryptoAgilityManifest(minimal).valid, true);
});
