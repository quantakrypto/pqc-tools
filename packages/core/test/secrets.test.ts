/**
 * Tests for secrets-at-rest detection — classical asymmetric key wrapping (the
 * strongest harvest-now-decrypt-later story, since ciphertext is often in git).
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

test("an age/SOPS recipient is flagged as X25519 and HNDL", () => {
  const sops = "creation_rules:\n  - age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n";
  const f = rule(run(".sops.yaml", sops), "secrets-age-recipient");
  assert.equal(f?.algorithm, "X25519");
  assert.equal(f?.category, "key-exchange");
  assert.equal(f?.hndl, true);
});

test("a PGP MESSAGE block is flagged as RSA/ElGamal KEM", () => {
  const f = rule(
    run("secret.enc", "-----BEGIN PGP MESSAGE-----\nhQEMA...\n-----END PGP MESSAGE-----\n"),
    "secrets-pgp-message",
  );
  assert.equal(f?.category, "kem");
  assert.equal(f?.hndl, true);
});

test("a SealedSecret is flagged as RSA-OAEP", () => {
  const f = rule(
    run("sealed.yaml", "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: db\n"),
    "secrets-sealed-secret",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, true);
});

test("symmetric ansible-vault and ordinary text produce no secrets- findings", () => {
  // ansible-vault is AES (symmetric) — intentionally out of scope.
  assert.deepEqual(
    run("vault.yml", "$ANSIBLE_VAULT;1.1;AES256\n33633...").filter((f) => f.ruleId.startsWith("secrets-")),
    [],
  );
  // A word starting with "age1" that is not a full recipient must not fire.
  assert.deepEqual(
    run("notes.txt", "the message age1 is short").filter((f) => f.ruleId.startsWith("secrets-")),
    [],
  );
});
