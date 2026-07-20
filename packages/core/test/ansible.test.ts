/**
 * Tests for Ansible community.crypto key detection.
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

test("community.crypto openssl_privatekey RSA / ECC classify correctly", () => {
  const rsa =
    "- name: key\n  community.crypto.openssl_privatekey:\n    path: /k.pem\n    type: RSA\n";
  assert.equal(rule(run("play.yml", rsa), "ansible-openssl-rsa")?.algorithm, "RSA");
  const ecc = "- community.crypto.openssl_privatekey:\n    type: ECC\n    curve: secp256r1\n";
  assert.equal(rule(run("play.yml", ecc), "ansible-openssl-ecc")?.algorithm, "ECDH");
});

test("openssl_privatekey X25519 / X448 report their own curve algorithm", () => {
  const x25519 = "- community.crypto.openssl_privatekey:\n    type: X25519\n";
  assert.equal(rule(run("play.yml", x25519), "ansible-openssl-xdh")?.algorithm, "X25519");
  const x448 = "- community.crypto.openssl_privatekey:\n    type: X448\n";
  assert.equal(
    rule(run("play.yml", x448), "ansible-openssl-xdh")?.algorithm,
    "X448",
    "X448 reports X448, not the rule's default X25519 label",
  );
});

test("gating: type: RSA with no community.crypto/openssl_privatekey marker does not fire", () => {
  assert.deepEqual(
    run("vars.yml", "database:\n  type: RSA\n").filter((f) => f.ruleId.startsWith("ansible-")),
    [],
  );
});

test("a commented `# type: RSA` inside a crypto task does not fire", () => {
  const y = "- community.crypto.openssl_privatekey:\n    # type: RSA (old)\n    type: ED25519\n";
  assert.deepEqual(
    run("play.yml", y).filter((f) => f.ruleId.startsWith("ansible-")),
    [],
  );
});
