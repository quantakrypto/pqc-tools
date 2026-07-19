/**
 * Tests for cloud-KMS SDK detection — classical asymmetric keys minted at runtime
 * via the AWS KMS SDK (the app-code counterpart to the Terraform IaC detector).
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

test("AWS KMS CreateKey KeySpec RSA / ECC classify correctly", () => {
  const rsa = rule(
    run("kms.ts", 'new CreateKeyCommand({ KeySpec: "RSA_3072", KeyUsage: "ENCRYPT_DECRYPT" });'),
    "cloud-kms-rsa",
  );
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);
  const ec = rule(run("kms.py", 'kms.create_key(KeySpec="ECC_NIST_P384")'), "cloud-kms-ec");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
});

test("KeyPairSpec (GenerateDataKeyPair) and legacy CustomerMasterKeySpec are caught", () => {
  assert.ok(
    rule(
      run("a.js", 'new GenerateDataKeyPairCommand({ KeyPairSpec: "RSA_2048" });'),
      "cloud-kms-rsa",
    ),
  );
  assert.ok(rule(run("a.json", '{ "CustomerMasterKeySpec": "ECC_SECG_P256K1" }'), "cloud-kms-ec"));
});

test("cloud-KMS does NOT double-count the Terraform (snake_case) spec on a .tf file", () => {
  // Terraform's `customer_master_key_spec` is snake_case; the KMS SDK detector's
  // fast-reject is case-sensitive on the PascalCase field, so only the Terraform
  // rule fires — not both.
  const findings = run(
    "main.tf",
    'resource "aws_kms_key" "k" {\n  customer_master_key_spec = "RSA_3072"\n}',
  );
  assert.equal(rule(findings, "cloud-kms-rsa"), undefined, "cloud-kms must not fire on .tf");
  assert.ok(rule(findings, "tf-kms-rsa"), "the Terraform rule fires instead");
});

test("a symmetric KMS key (default) and unrelated JSON produce no KMS findings", () => {
  // AWS KMS default is symmetric (no KeySpec, or KeySpec SYMMETRIC_DEFAULT) — must
  // stay silent, as must ordinary JSON.
  assert.deepEqual(
    run("a.js", 'new CreateKeyCommand({ KeySpec: "SYMMETRIC_DEFAULT" });').filter((f) =>
      f.ruleId.startsWith("cloud-kms-"),
    ),
    [],
  );
  assert.deepEqual(
    run("cfg.json", '{ "name": "svc", "KeySpecVersion": 2 }').filter((f) =>
      f.ruleId.startsWith("cloud-kms-"),
    ),
    [],
  );
});

test("a KeySpec RSA_2048 in prose docs (.md) is NOT flagged", () => {
  // A tutorial describing the KMS API is not a live key-minting call.
  assert.deepEqual(
    run("kms-guide.md", 'Set KeySpec: "RSA_2048" to create an asymmetric CMK.').filter((f) =>
      f.ruleId.startsWith("cloud-kms-"),
    ),
    [],
  );
});

test("cloud-kms STILL fires in a .ts SDK file that merely mentions a CFN marker string", () => {
  // The template-deferral is gated to CFN extensions, so an SDK call in code that
  // has an `AWS::KMS` comment is not silently dropped (cloudformation never scans .ts).
  const f = rule(
    run("kms.ts", '// creates an AWS::KMS::Key\nnew CreateKeyCommand({ KeySpec: "RSA_2048" });'),
    "cloud-kms-rsa",
  );
  assert.equal(f?.algorithm, "RSA");
});
