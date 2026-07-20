/**
 * Tests for Terraform / OpenTofu (IaC) crypto detection — keys and CMKs
 * provisioned by infrastructure code, a surface the language packs never see.
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

test("tls_private_key RSA / ECDSA classify correctly", () => {
  const rsa = rule(
    run("main.tf", 'resource "tls_private_key" "k" {\n  algorithm = "RSA"\n  rsa_bits = 2048\n}'),
    "tf-rsa-key",
  );
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);
  const ec = rule(
    run("main.tf", 'resource "tls_private_key" "k" {\n  algorithm = "ECDSA"\n}'),
    "tf-ecdsa-key",
  );
  assert.equal(ec?.algorithm, "ECDSA");
  assert.equal(ec?.hndl, false);
});

test("Google KMS RSA_SIGN_* / EC_SIGN_* algorithm strings are caught", () => {
  assert.ok(rule(run("kms.tf", 'algorithm = "RSA_SIGN_PKCS1_2048_SHA256"'), "tf-rsa-key"));
  assert.equal(
    rule(run("kms.tf", 'algorithm = "EC_SIGN_P256_SHA256"'), "tf-ecdsa-key")?.algorithm,
    "ECDSA",
  );
});

test("AWS KMS customer_master_key_spec RSA_* / ECC_* classify correctly", () => {
  const rsa = rule(run("kms.tf", 'customer_master_key_spec = "RSA_3072"'), "tf-kms-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);
  const ec = rule(run("kms.tf", 'customer_master_key_spec = "ECC_NIST_P384"'), "tf-kms-ec");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
});

test("Azure Key Vault key_type RSA / EC (incl. -HSM) classify correctly", () => {
  assert.equal(rule(run("kv.tf", 'key_type = "RSA-HSM"'), "tf-keyvault-rsa")?.algorithm, "RSA");
  assert.equal(rule(run("kv.tf", 'key_type = "EC"'), "tf-keyvault-ec")?.algorithm, "ECDH");
});

test("HashiCorp Vault PKI lowercase key_type = rsa / ec is caught (case-insensitive value)", () => {
  assert.equal(rule(run("vault.tf", 'key_type = "rsa"'), "tf-keyvault-rsa")?.algorithm, "RSA");
  assert.equal(rule(run("vault.tf", 'key_type = "ec"'), "tf-keyvault-ec")?.algorithm, "ECDH");
  // The `"…"` bound keeps `"ec"` from matching a longer value like `"ecc"`.
  assert.deepEqual(
    run("vault.tf", 'other = "ecc"').filter((f) => f.ruleId.startsWith("tf-")),
    [],
  );
});

test("Terraform detector is gated to .tf / .tf.json (not arbitrary files)", () => {
  // The same HCL text in a .txt file must not fire.
  assert.deepEqual(
    run("notes.txt", 'algorithm = "RSA"').filter((f) => f.ruleId.startsWith("tf-")),
    [],
  );
  // .tf.json (JSON syntax variant) is in scope.
  assert.ok(rule(run("main.tf.json", '{ "algorithm": "RSA" }'), "tf-rsa-key"));
});

test("clean Terraform (symmetric KMS, no asymmetric keys) produces no findings", () => {
  // A symmetric default CMK and an AES setting must stay silent.
  const clean = 'resource "aws_kms_key" "k" {\n  description = "symmetric default"\n}';
  assert.deepEqual(
    run("main.tf", clean).filter((f) => f.ruleId.startsWith("tf-")),
    [],
  );
});

test("a COMMENTED HCL argument (# or //) is NOT flagged", () => {
  const commented =
    'resource "tls_private_key" "k" {\n  # algorithm = "RSA" (migrated to ML-DSA)\n  // algorithm = "ECDSA"\n}';
  assert.deepEqual(
    run("main.tf", commented).filter((f) => f.ruleId.startsWith("tf-")),
    [],
  );
});

test("a resource inside a /* … */ HCL block comment is NOT flagged", () => {
  const blocked =
    '/*\nresource "tls_private_key" "old" {\n  algorithm = "RSA"\n}\n*/\nvariable "x" {}';
  assert.deepEqual(
    run("main.tf", blocked).filter((f) => f.ruleId.startsWith("tf-")),
    [],
  );
});

test("tls_private_key ED25519 is flagged as EdDSA (signature, not HNDL)", () => {
  const tf = 'resource "tls_private_key" "k" {\n  algorithm = "ED25519"\n}';
  const f = rule(run("main.tf", tf), "tf-ed25519-key");
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.hndl, false);
});

test("aws_kms_key modern `key_spec` alias is flagged (RSA/ECC), counted once", () => {
  const rsa = 'resource "aws_kms_key" "k" {\n  key_spec = "RSA_2048"\n}';
  assert.ok(rule(run("kms.tf", rsa), "tf-kms-rsa"), "modern key_spec RSA flagged");
  const ec = 'resource "aws_kms_key" "k" {\n  key_spec = "ECC_NIST_P256"\n}';
  assert.ok(rule(run("kms.tf", ec), "tf-kms-ec"), "modern key_spec ECC flagged");
  // The legacy attribute name must still match exactly once (no double-count on the
  // `key_spec` suffix inside `customer_master_key_spec`).
  const legacy = 'resource "aws_kms_key" "k" {\n  customer_master_key_spec = "RSA_4096"\n}';
  assert.equal(
    run("kms.tf", legacy).filter((f) => f.ruleId === "tf-kms-rsa").length,
    1,
    "legacy customer_master_key_spec counted exactly once",
  );
});
