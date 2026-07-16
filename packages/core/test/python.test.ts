/**
 * Tests for the Python source detector. Each detector is exercised against a
 * small inline fixture, asserting the ruleId, algorithm family, and HNDL flag.
 * Mirrors detectors.test.ts for the JS detectors.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

/** Run every applicable detector over a fixture and flatten the findings. */
function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}

function byRule(findings: Finding[], ruleId: string): Finding | undefined {
  return findings.find((f) => f.ruleId === ruleId);
}

test("cryptography: RSA key generation", () => {
  const src = [
    "from cryptography.hazmat.primitives.asymmetric import rsa",
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
  ].join("\n");
  const f = byRule(run("keys.py", src), "python-rsa-keygen");
  assert.ok(f, "rsa keygen detected");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.category, "kem");
  assert.equal(f.hndl, true);
  assert.equal(f.location.line, 2);
});

test("module-alias: `import rsa as _rsa` then `_rsa.generate_private_key` resolves", () => {
  const src = [
    "from cryptography.hazmat.primitives.asymmetric import rsa as _rsa",
    "key = _rsa.generate_private_key(public_exponent=65537, key_size=3072)",
  ].join("\n");
  const f = byRule(run("keys.py", src), "python-rsa-keygen");
  assert.ok(f, "aliased rsa keygen detected");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.hndl, true);
  assert.equal(f.location.line, 2, "location points at the aliased call, not the import");
});

test("module-alias: comma-separated `ec as _ec` resolves keygen/ECDSA/ECDH", () => {
  const src = [
    "from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec",
    "sk = _ec.generate_private_key(_ec.SECP256R1())",
    "sig = _ec.ECDSA(hashes.SHA256())",
    "shared = priv.exchange(_ec.ECDH(), peer)",
  ].join("\n");
  const findings = run("k.py", src);
  assert.equal(byRule(findings, "python-ec-keygen")?.hndl, true);
  assert.equal(byRule(findings, "python-ecdsa")?.algorithm, "ECDSA");
  assert.equal(byRule(findings, "python-ecdh")?.hndl, true);
});

test("module-alias: PyCryptodome `import ...RSA as _R` then `_R.generate` resolves", () => {
  const src = ["import Crypto.PublicKey.RSA as _R", "k = _R.generate(2048)"].join("\n");
  assert.equal(byRule(run("k.py", src), "python-rsa-keygen")?.algorithm, "RSA");
});

test("module-alias: an alias bound to a NON-crypto module does not fire (precision)", () => {
  // `_rsa` here is a stats module, not the crypto one — `_rsa.generate_private_key`
  // is not a real call, but even a coincidental `.generate(` must stay silent.
  const src = ["import numpy as _rsa", "x = _rsa.generate(2048)"].join("\n");
  // numpy is not aliasable, so nothing binds `_rsa` to a crypto module.
  assert.equal(byRule(run("k.py", src), "python-rsa-keygen"), undefined);
});

test("module-alias: a non-aliased call is NOT double-counted by the alias pass", () => {
  const src = [
    "from cryptography.hazmat.primitives.asymmetric import rsa",
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
  ].join("\n");
  const hits = run("keys.py", src).filter((f) => f.ruleId === "python-rsa-keygen");
  assert.equal(hits.length, 1, "one call → exactly one finding");
});

test("PyCryptodome: RSA.generate and ECC.generate", () => {
  const rsa = byRule(run("a.py", "key = RSA.generate(2048)"), "python-rsa-keygen");
  assert.equal(rsa?.algorithm, "RSA");
  const ecc = byRule(run("a.py", "key = ECC.generate(curve='P-256')"), "python-ec-keygen");
  assert.equal(ecc?.algorithm, "ECDH");
  assert.equal(ecc?.hndl, true, "EC keygen is conservatively HNDL-exposed");
});

test("cryptography: EC key generation is HNDL-exposed", () => {
  const f = byRule(
    run("a.py", "key = ec.generate_private_key(ec.SECP256R1())"),
    "python-ec-keygen",
  );
  assert.ok(f);
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.category, "key-exchange");
  assert.equal(f.hndl, true);
});

test("cryptography: ECDSA signature", () => {
  const f = byRule(run("a.py", "sig = key.sign(data, ec.ECDSA(hashes.SHA256()))"), "python-ecdsa");
  assert.ok(f);
  assert.equal(f.algorithm, "ECDSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("DSA and Diffie-Hellman", () => {
  assert.equal(byRule(run("a.py", "key = DSA.generate(2048)"), "python-dsa")?.algorithm, "DSA");
  const dh = byRule(
    run("a.py", "params = dh.generate_parameters(generator=2, key_size=2048)"),
    "python-dh",
  );
  assert.equal(dh?.algorithm, "DH");
  assert.equal(dh?.hndl, true);
});

test("RSA-OAEP encryption padding", () => {
  const f = byRule(
    run(
      "a.py",
      "ct = public_key.encrypt(msg, padding.OAEP(mgf=MGF1(SHA256()), algorithm=SHA256(), label=None))",
    ),
    "python-rsa-encrypt",
  );
  assert.ok(f);
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.hndl, true);
});

test("modern-but-classical curves: X25519, X448, Ed25519", () => {
  assert.equal(
    byRule(run("a.py", "k = X25519PrivateKey.generate()"), "python-x25519")?.algorithm,
    "X25519",
  );
  assert.equal(
    byRule(run("a.py", "k = X448PrivateKey.generate()"), "python-x448")?.algorithm,
    "X448",
  );
  const ed = byRule(run("a.py", "k = Ed25519PrivateKey.generate()"), "python-eddsa");
  assert.equal(ed?.algorithm, "EdDSA");
  assert.equal(ed?.hndl, false);
});

test("paramiko SSH keys map to their families", () => {
  assert.equal(
    byRule(run("a.py", "k = paramiko.RSAKey.generate(2048)"), "python-rsa-keygen")?.algorithm,
    "RSA",
  );
  assert.equal(
    byRule(run("a.py", "k = paramiko.Ed25519Key(filename='id')"), "python-eddsa")?.algorithm,
    "EdDSA",
  );
  assert.equal(
    byRule(run("a.py", "k = paramiko.DSSKey.generate()"), "python-dsa")?.algorithm,
    "DSA",
  );
});

test("PyJWT: the JWT detector is un-gated to Python", () => {
  const f = byRule(
    run("auth.py", 'token = jwt.encode(payload, key, algorithm="RS256")'),
    "jwt-classical-alg",
  );
  assert.ok(f, "quoted RS256 in a .py file is detected");
  assert.equal(f.algorithm, "RSA");
});

test("clean Python source produces no findings (no false positives)", () => {
  const src = [
    "import os",
    "rsa_config = {'rotate': True}  # not a crypto call",
    "def generate_report(ec_data):",
    "    return dsa_summary(ec_data)",
    "value = 'ec generate private key'  # a string, not code",
  ].join("\n");
  const findings = run("clean.py", src);
  assert.deepEqual(
    findings,
    [],
    `expected no findings, got ${findings.map((f) => f.ruleId).join(", ")}`,
  );
});

test("Python detectors do not run on non-Python files", () => {
  // A .go file with Python-looking text must not trigger the Python detector.
  const findings = run("main.go", "rsa.generate_private_key()");
  assert.equal(byRule(findings, "python-rsa-keygen"), undefined);
});
