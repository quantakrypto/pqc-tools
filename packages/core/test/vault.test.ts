/**
 * Tests for native HashiCorp Vault (HCL) transit/pki key detection.
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

test("Vault transit RSA / ECDSA keys classify correctly", () => {
  const hcl = 'path "transit/keys/app" {\n  type = "rsa-4096"\n}\n';
  assert.equal(rule(run("vault.hcl", hcl), "vault-transit-rsa")?.algorithm, "RSA");
  const ec = 'path "transit/keys/sig" {\n  type = "ecdsa-p256"\n}\n';
  assert.equal(rule(run("vault.hcl", ec), "vault-transit-ecdsa")?.algorithm, "ECDSA");
});

test("Vault PKI role key_type is flagged", () => {
  const hcl = 'path "pki/roles/web" {\n  key_type = "rsa"\n  key_bits = 2048\n}\n';
  assert.equal(rule(run("policy.hcl", hcl), "vault-pki-rsa")?.category, "certificate");
});

test("gating: an HCL type = rsa-* with no transit/pki context does not fire", () => {
  assert.deepEqual(
    run("other.hcl", 'resource "x" {\n  type = "rsa-2048"\n}\n').filter((f) =>
      f.ruleId.startsWith("vault-"),
    ),
    [],
  );
});

test("Vault detector does not run on Terraform .tf (terraform detector owns that)", () => {
  // appliesTo is .hcl only — a .tf file with the same syntax isn't double-counted here.
  const tf = 'path "transit/keys/app" {\n  type = "rsa-4096"\n}\n';
  assert.deepEqual(
    run("main.tf", tf).filter((f) => f.ruleId.startsWith("vault-")),
    [],
  );
});
