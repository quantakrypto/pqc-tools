/**
 * Tests for the PKCS#11 (HSM / token) detector.
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

test("pkcs11-tool --key-type rsa/EC keygen invocations are flagged", () => {
  const rsa = rule(
    run("provision.sh", "pkcs11-tool --keypairgen --key-type rsa:4096 --label ca-root"),
    "pkcs11-rsa",
  );
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);
  assert.ok(
    rule(run("provision.sh", "pkcs11-tool --keypairgen --key-type EC:secp384r1"), "pkcs11-ec"),
  );
});

test("PKCS#11 mechanism constants (CKM_*) classify by algorithm", () => {
  assert.equal(
    rule(run("hsm.js", "session.generateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, ...)"), "pkcs11-rsa")
      ?.algorithm,
    "RSA",
  );
  assert.equal(rule(run("hsm.py", "Mechanism(CKM_ECDSA_SHA256)"), "pkcs11-ec")?.algorithm, "ECDH");
  assert.ok(rule(run("hsm.c", "CKM_DSA_SHA256"), "pkcs11-dsa"));
  assert.ok(rule(run("hsm.c", "CKM_DH_PKCS_DERIVE"), "pkcs11-dh"));
});

test("symmetric / hashing PKCS#11 mechanisms do not fire", () => {
  assert.deepEqual(
    run("hsm.c", "CKM_AES_GCM; CKM_SHA256_HMAC; CKM_AES_KEY_GEN").filter((f) =>
      f.ruleId.startsWith("pkcs11-"),
    ),
    [],
  );
});

test("a doc describing CKM_RSA_PKCS is NOT flagged", () => {
  assert.deepEqual(
    run("hsm-guide.md", "Use the CKM_RSA_PKCS_KEY_PAIR_GEN mechanism to make a key.").filter((f) =>
      f.ruleId.startsWith("pkcs11-"),
    ),
    [],
  );
});
