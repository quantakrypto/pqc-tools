/**
 * Tests for the CycloneDX 1.6 CBOM export.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toCbom, buildInventory } from "../src/index.js";
import type { CbomComponent, Finding, ScanResult } from "../src/index.js";

/** Read a namespaced CycloneDX component property (the quantum posture flags). */
function prop(c: CbomComponent, name: string): string | undefined {
  return c.properties?.find((p) => p.name === name)?.value;
}

function result(findings: Finding[]): ScanResult {
  return {
    root: "/repo",
    findings,
    filesScanned: 1,
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

test("toCbom emits a CycloneDX 1.6 cryptographic BOM", () => {
  const bom = toCbom(result([f({})]));
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]+$/);
  assert.equal(bom.components.length, 1);
  const comp = bom.components[0];
  assert.equal(comp.type, "cryptographic-asset");
  // The quantum posture is carried as CycloneDX component `properties` (name/value),
  // not inside `cryptoProperties` (whose 1.6 schema is additionalProperties:false).
  assert.equal(prop(comp, "quantakrypto:quantumVulnerable"), "true");
  assert.equal(prop(comp, "quantakrypto:harvestNowDecryptLater"), "true");
});

test("toCbom reports a per-family classical security level (quantum level stays 0)", () => {
  const levelOf = (findings: Finding[]) => {
    const props = (
      toCbom(result(findings)).components[0].cryptoProperties as {
        algorithmProperties: { classicalSecurityLevel: number; nistQuantumSecurityLevel: number };
      }
    ).algorithmProperties;
    return props;
  };
  // ECDH (P-256 class) ≈ 128-bit classical, RSA-2048 ≈ 112-bit; quantum = 0 for both.
  const ecdh = levelOf([f({})]);
  assert.equal(ecdh.classicalSecurityLevel, 128);
  assert.equal(ecdh.nistQuantumSecurityLevel, 0);
  const rsa = levelOf([f({ ruleId: "node-crypto-keygen", category: "kem", algorithm: "RSA" })]);
  assert.equal(rsa.classicalSecurityLevel, 112);
});

test("toCbom groups by algorithm + primitive and records occurrences", () => {
  const bom = toCbom(
    result([
      f({ location: { file: "src/a.ts", line: 1, snippet: "x" } }),
      f({ location: { file: "src/b.ts", line: 2, snippet: "y" } }),
      f({ ruleId: "jwt-classical-alg", category: "signature", algorithm: "RSA", hndl: false }),
    ]),
  );
  // ECDH/key-agree is one component; RSA/signature is another.
  assert.equal(bom.components.length, 2);
  const ecdh = bom.components.find((c) => c.name.startsWith("ECDH"))!;
  const occ = (ecdh.evidence as { occurrences: Array<{ location: string }> }).occurrences;
  assert.deepEqual(
    occ.map((o) => o.location),
    ["src/a.ts:1", "src/b.ts:2"],
  );
});

test("toCbom is deterministic for the same result", () => {
  const r = result([
    f({}),
    f({ ruleId: "x", category: "signature", algorithm: "ECDSA", hndl: false }),
  ]);
  assert.deepEqual(toCbom(r), toCbom(r));
});

test("CBOM cryptoProperties carries no non-schema keys; key-agree cryptoFunction is valid", () => {
  // cryptoProperties in CycloneDX 1.6 is additionalProperties:false — the quantum
  // flags must NOT appear there (they live in component.properties), and
  // "keyagree" is not a valid cryptoFunction enum member ("other" is).
  const bom = toCbom(result([f({})])); // ECDH / key-agree
  const cp = bom.components[0].cryptoProperties as Record<string, unknown>;
  assert.equal(cp.quantumVulnerable, undefined, "flag not inside cryptoProperties");
  assert.equal(cp.harvestNowDecryptLater, undefined, "flag not inside cryptoProperties");
  assert.deepEqual(Object.keys(cp).sort(), ["algorithmProperties", "assetType"]);
  const fns = (cp.algorithmProperties as { cryptoFunctions: string[] }).cryptoFunctions;
  assert.ok(!fns.includes("keyagree"), 'no invalid "keyagree" cryptoFunction');
  assert.deepEqual(fns, ["other"], "key-agree maps to the valid 'other' cryptoFunction");
});

test("CBOM classifies PKI trust material (ACM/Vault/SPIFFE-style) as assetType certificate", () => {
  // Category-'certificate' rules whose ids don't spell 'cert' (cfn-acm, vault-pki,
  // spire SVIDs) must still be certificates, not related-crypto-material 'key'.
  const bom = toCbom(
    result([
      f({ ruleId: "cfn-acm-rsa", category: "certificate", algorithm: "RSA" }),
      f({
        ruleId: "spire-rsa-key",
        category: "certificate",
        algorithm: "RSA",
        location: { file: "b", line: 1 },
      }),
    ]),
  );
  for (const c of bom.components) {
    assert.equal(
      (c.cryptoProperties as { assetType: string }).assetType,
      "certificate",
      `${c.name} is a certificate asset`,
    );
  }
});

test("CBOM refines assetType: certificate, key material, and protocol are not 'algorithm'", () => {
  const bom = toCbom(
    result([
      f({ ruleId: "pem-rsa-private-key", category: "certificate", algorithm: "RSA" }),
      f({
        ruleId: "pem-public-key",
        category: "certificate",
        algorithm: "RSA",
        location: { file: "p.pub", line: 1 },
      }),
      f({
        ruleId: "pem-certificate",
        category: "certificate",
        algorithm: "unknown",
        location: { file: "c.pem", line: 1 },
      }),
      f({
        ruleId: "tls-weak-cipher",
        category: "tls",
        algorithm: "unknown",
        location: { file: "nginx.conf", line: 1 },
      }),
      f({
        ruleId: "node-crypto-keygen",
        category: "kem",
        algorithm: "RSA",
        location: { file: "k.ts", line: 1 },
      }),
    ]),
  );
  const byAsset = (t: string) =>
    bom.components.filter((c) => (c.cryptoProperties as { assetType: string }).assetType === t);

  // A private key and a public key are related-crypto-material, typed accordingly.
  const material = byAsset("related-crypto-material");
  assert.equal(material.length, 2);
  const types = material
    .map(
      (c) =>
        (c.cryptoProperties as { relatedCryptoMaterialProperties: { type: string } })
          .relatedCryptoMaterialProperties.type,
    )
    .sort();
  assert.deepEqual(types, ["private-key", "public-key"]);

  // An X.509 certificate is assetType "certificate" (no algorithmProperties).
  const certs = byAsset("certificate");
  assert.equal(certs.length, 1);
  assert.equal(
    (certs[0].cryptoProperties as { algorithmProperties?: unknown }).algorithmProperties,
    undefined,
  );

  // A TLS finding is a protocol asset.
  const protos = byAsset("protocol");
  assert.equal(protos.length, 1);
  assert.equal(
    (protos[0].cryptoProperties as { protocolProperties: { type: string } }).protocolProperties
      .type,
    "tls",
  );

  // The keygen usage stays an algorithm asset.
  assert.equal(byAsset("algorithm").length, 1);

  // Every asset — whatever its type — still reports the quantum posture.
  for (const c of bom.components) {
    assert.equal(prop(c, "quantakrypto:quantumVulnerable"), "true");
  }
});

test("CBOM uses valid primitives and marks classical unknown-family findings vulnerable (audit)", () => {
  const bom = toCbom(
    result([
      f({
        ruleId: "cert-signature-algorithm",
        category: "certificate",
        algorithm: "unknown",
        hndl: false,
      }),
      f({
        ruleId: "node-crypto-sign",
        category: "signature",
        algorithm: "unknown",
        hndl: false,
        location: { file: "b.ts", line: 1 },
      }),
    ]),
  );
  const VALID_PRIMITIVES = new Set([
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "other",
    "unknown",
  ]);
  for (const c of bom.components) {
    const prim = (c.cryptoProperties?.algorithmProperties as { primitive?: string })?.primitive;
    assert.ok(
      !prim || VALID_PRIMITIVES.has(prim),
      `primitive "${prim}" is a valid CycloneDX 1.6 enum`,
    );
    assert.notEqual(prim, "pki");
  }
  // The signature finding's asset must report quantumVulnerable = true.
  const anyVulnerable = bom.components.some(
    (c) => prop(c, "quantakrypto:quantumVulnerable") === "true",
  );
  assert.ok(anyVulnerable, "classical findings report quantumVulnerable:true");
});
