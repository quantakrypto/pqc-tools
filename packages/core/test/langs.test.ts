/**
 * Focused unit tests for the C# / Rust / Ruby / C-OpenSSL detectors. The labeled
 * benchmark corpus is the exhaustive end-to-end check (positive + negative per
 * language); these pin a few key classifications and the extension gating.
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

test("C#: RSA.Create / ECDsa / ECDiffieHellman / DSA classify correctly", () => {
  assert.equal(rule(run("A.cs", "var k = RSA.Create(2048);"), "csharp-rsa")?.hndl, true);
  assert.equal(rule(run("A.cs", "var s = ECDsa.Create();"), "csharp-ecdsa")?.algorithm, "ECDSA");
  const dh = rule(run("A.cs", "var d = ECDiffieHellman.Create();"), "csharp-ecdh");
  assert.equal(dh?.algorithm, "ECDH");
  assert.equal(dh?.hndl, true);
  assert.equal(
    rule(run("A.cs", "var d = new DSACryptoServiceProvider();"), "csharp-dsa")?.algorithm,
    "DSA",
  );
  // Symmetric factory must not fire.
  assert.deepEqual(run("A.cs", "var a = Aes.Create();"), []);
});

test("Rust: rsa / p256 ecdsa+ecdh / dalek ed25519+x25519", () => {
  assert.equal(
    rule(run("m.rs", "let k = RsaPrivateKey::new(rng, 2048);"), "rust-rsa")?.algorithm,
    "RSA",
  );
  assert.equal(
    rule(run("m.rs", "let s = p256::ecdsa::SigningKey::random(r);"), "rust-ecdsa")?.hndl,
    false,
  );
  assert.equal(
    rule(run("m.rs", "let e = p256::ecdh::EphemeralSecret::random(r);"), "rust-ecdh")?.hndl,
    true,
  );
  assert.equal(
    rule(run("m.rs", "let e = ed25519_dalek::SigningKey::generate(r);"), "rust-ed25519")?.algorithm,
    "EdDSA",
  );
  assert.equal(
    rule(run("m.rs", "let x = x25519_dalek::StaticSecret::random();"), "rust-x25519")?.algorithm,
    "X25519",
  );
});

test("Ruby: OpenSSL::PKey::{RSA,EC,DSA,DH}", () => {
  assert.equal(rule(run("k.rb", "k = OpenSSL::PKey::RSA.new(2048)"), "ruby-rsa")?.hndl, true);
  const ec = rule(run("k.rb", 'k = OpenSSL::PKey::EC.generate("prime256v1")'), "ruby-ec");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true, "EC keygen is conservatively HNDL-exposed");
  assert.equal(rule(run("k.rb", "k = OpenSSL::PKey::DSA.new(2048)"), "ruby-dsa")?.algorithm, "DSA");
});

test("C/OpenSSL: RSA_generate_key / EC_KEY / ECDSA_sign / DH", () => {
  assert.equal(
    rule(run("a.c", "RSA_generate_key(2048, e, 0, 0);"), "c-rsa-keygen")?.algorithm,
    "RSA",
  );
  const ec = rule(run("a.c", "EC_KEY_generate_key(key);"), "c-ec-keygen");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
  assert.equal(rule(run("a.c", "ECDSA_sign(0, d, n, s, &sl, k);"), "c-ecdsa")?.hndl, false);
  assert.equal(rule(run("a.cpp", "DH_generate_key(dh);"), "c-dh")?.algorithm, "DH");
});

test("each detector is gated to its own extensions", () => {
  // C# call text in a .rs file must not trigger the C# detector, and vice versa.
  assert.equal(rule(run("x.rs", "RSA.Create(2048);"), "csharp-rsa"), undefined);
  assert.equal(rule(run("x.cs", "OpenSSL::PKey::RSA.new(2048)"), "ruby-rsa"), undefined);
  assert.equal(rule(run("x.py", "RSA_generate_key(2048);"), "c-rsa-keygen"), undefined);
});

test("clean sources across the four languages produce no findings", () => {
  assert.deepEqual(run("A.cs", "var a = Aes.Create(); var h = SHA256.Create();"), []);
  assert.deepEqual(run("m.rs", "let x = hmac_sign(rsa_config); // rsa crate not used"), []);
  assert.deepEqual(run("k.rb", "d = OpenSSL::Digest::SHA256.new"), []);
  assert.deepEqual(run("a.c", "SHA256_Init(&ctx); AES_encrypt(a, b, &k);"), []);
});
