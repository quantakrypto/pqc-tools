/**
 * Tests for the Go source detector. Go's crypto lives in the standardized
 * crypto/* stdlib, so package-qualified calls are precise signals.
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

function byRule(findings: Finding[], ruleId: string): Finding | undefined {
  return findings.find((f) => f.ruleId === ruleId);
}

test("crypto/rsa: keygen, encrypt, sign", () => {
  const keygen = byRule(run("m.go", "k, _ := rsa.GenerateKey(rand.Reader, 2048)"), "go-rsa-keygen");
  assert.equal(keygen?.algorithm, "RSA");
  assert.equal(keygen?.hndl, true);
  assert.equal(
    byRule(run("m.go", "rsa.EncryptOAEP(h, r, pub, m, nil)"), "go-rsa-encrypt")?.hndl,
    true,
  );
  const sign = byRule(run("m.go", "rsa.SignPSS(rand.Reader, k, hash, digest, nil)"), "go-rsa-sign");
  assert.equal(sign?.algorithm, "RSA");
  assert.equal(sign?.hndl, false, "signing is not HNDL");
});

test("crypto/ecdsa is signature-specific (hndl false)", () => {
  const f = byRule(
    run("m.go", "k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)"),
    "go-ecdsa",
  );
  assert.ok(f);
  assert.equal(f.algorithm, "ECDSA");
  assert.equal(f.category, "signature");
  assert.equal(f.hndl, false);
});

test("crypto/ecdh is key agreement (hndl true)", () => {
  assert.equal(byRule(run("m.go", "c := ecdh.P256()"), "go-ecdh")?.hndl, true);
  const x = byRule(run("m.go", "c := ecdh.X25519()"), "go-ecdh");
  assert.equal(x?.algorithm, "ECDH");
  assert.equal(x?.category, "key-exchange");
});

test("crypto/ed25519 and crypto/dsa", () => {
  assert.equal(
    byRule(run("m.go", "pub, priv, _ := ed25519.GenerateKey(rand.Reader)"), "go-ed25519")
      ?.algorithm,
    "EdDSA",
  );
  assert.equal(
    byRule(run("m.go", "dsa.GenerateKey(&params, rand.Reader)"), "go-dsa")?.algorithm,
    "DSA",
  );
});

test("clean Go source produces no findings (comments/imports don't FP)", () => {
  const src = [
    "package main",
    'import "crypto/rsa"  // imported but not the call pattern',
    "// historically called ecdsa.GenerateKey here, now removed",
    "func rsaSummary(ecData string) string { return ecData }",
  ].join("\n");
  const findings = run("clean.go", src);
  assert.deepEqual(findings, [], `expected none, got ${findings.map((f) => f.ruleId).join(", ")}`);
});

test("Go detector does not run on non-Go files", () => {
  assert.equal(
    byRule(run("m.py", "rsa.GenerateKey(rand.Reader, 2048)"), "go-rsa-keygen"),
    undefined,
  );
});
