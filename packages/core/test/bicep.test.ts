/**
 * Tests for the Azure Bicep (.bicep) IaC detector.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

const KV_RSA = [
  "resource key 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {",
  "  name: 'signing'",
  "  properties: {",
  "    kty: 'RSA'",
  "    keySize: 2048",
  "  }",
  "}",
].join("\n");

test("Bicep Key Vault RSA key is flagged (KEM, HNDL)", () => {
  const f = rule(run("keyvault.bicep", KV_RSA), "bicep-keyvault-rsa");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, true);
});

test("Bicep Key Vault EC / EC-HSM key is flagged (ECDH, HNDL)", () => {
  const ec = KV_RSA.replace("kty: 'RSA'", "kty: 'EC-HSM'");
  const f = rule(run("keyvault.bicep", ec), "bicep-keyvault-ec");
  assert.equal(f?.algorithm, "ECDH");
  assert.equal(f?.hndl, true);
});

test("Bicep legacy minimumTlsVersion is flagged; TLS 1.2/1.3 is not", () => {
  assert.ok(rule(run("storage.bicep", "  minimumTlsVersion: 'TLS1_0'\n"), "bicep-min-tls-legacy"));
  assert.ok(rule(run("storage.bicep", "  minimumTlsVersion: 'TLS1_1'\n"), "bicep-min-tls-legacy"));
  assert.equal(
    rule(run("storage.bicep", "  minimumTlsVersion: 'TLS1_2'\n"), "bicep-min-tls-legacy"),
    undefined,
  );
});

test("a bare kty outside a Microsoft.KeyVault resource does not fire", () => {
  // A generic `kty` (e.g. a JWK-shaped config value) must not fire without the marker.
  assert.deepEqual(
    run("other.bicep", "var jwk = {\n  kty: 'RSA'\n}\n").filter((f) =>
      f.ruleId.startsWith("bicep-"),
    ),
    [],
  );
});

test("a commented-out Bicep key declaration does not fire", () => {
  const commented = [
    "resource key 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {",
    "  properties: {",
    "    // kty: 'RSA'  (migrated to a managed HSM PQC key)",
    "  }",
    "}",
  ].join("\n");
  assert.equal(rule(run("keyvault.bicep", commented), "bicep-keyvault-rsa"), undefined);
});

test("bicep detector is gated to .bicep files", () => {
  assert.deepEqual(
    run("main.tf", KV_RSA).filter((f) => f.ruleId.startsWith("bicep-")),
    [],
  );
});
