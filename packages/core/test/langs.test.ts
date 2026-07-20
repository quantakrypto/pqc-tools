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

test("C#: certificate PINNING does not fire the TLS cert-validation-disabled rule", () => {
  // Regression: pinning compares the presented cert to a known one and returns the
  // result — it is NOT `=> true`. The old regex matched any `ServerCertificateCustom
  // ValidationCallback =` and flagged a security control as a vulnerability.
  const pinning =
    "handler.ServerCertificateCustomValidationCallback = (m, cert, chain, errors) => cert.Thumbprint == Pinned;";
  assert.equal(rule(run("Pin.cs", pinning), "csharp-tls-cert-validation"), undefined);
  // But an actual disable (`=> true`) still fires.
  const disabled =
    "handler.ServerCertificateCustomValidationCallback = (m, cert, chain, errors) => true;";
  assert.ok(rule(run("Bad.cs", disabled), "csharp-tls-cert-validation"));
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

test("Rust type-alias: braced `use ... as` resolves x25519 / x448 / ed25519", () => {
  // The braced+renamed `use` defeats the ::-qualified rules; alias resolution
  // recovers the classification from the construction call.
  const x25519 = [
    "use x25519_dalek::{EphemeralSecret as MontgomerySecret, PublicKey as MP};",
    "let m = MontgomerySecret::random_from_rng(OsRng);",
  ].join("\n");
  assert.equal(rule(run("h.rs", x25519), "rust-x25519")?.algorithm, "X25519");

  const x448 = ["use x448::{Secret as WideSecret};", "let w = WideSecret::new(&mut OsRng);"].join(
    "\n",
  );
  const w = rule(run("h.rs", x448), "rust-x448");
  assert.equal(w?.algorithm, "X448");
  assert.equal(w?.hndl, true);

  const ed = [
    "use ed25519_dalek::SigningKey as Signer;",
    "let s = Signer::generate(&mut OsRng);",
  ].join("\n");
  assert.equal(rule(run("h.rs", ed), "rust-ed25519")?.algorithm, "EdDSA");
});

test("Rust type-alias: a non-crypto `use ... as` (e.g. Mutex) does not fire", () => {
  const src = ["use std::sync::Mutex as WideLock;", "let g = WideLock::new(());"].join("\n");
  assert.deepEqual(
    run("h.rs", src).filter((f) => f.ruleId.startsWith("rust-")),
    [],
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

test("C/Mbed TLS (embedded): rsa / ecp / ecdsa / ecdh / dhm classify correctly", () => {
  assert.equal(
    rule(run("fw.c", "mbedtls_rsa_gen_key(&rsa, rng, p, 2048, 65537);"), "c-mbedtls-rsa-keygen")
      ?.algorithm,
    "RSA",
  );
  const ec = rule(run("fw.c", "mbedtls_ecp_gen_key(id, &grp, rng, p);"), "c-mbedtls-ec-keygen");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
  assert.equal(
    rule(
      run("fw.c", "mbedtls_ecdsa_write_signature(&ctx, md, h, hl, s, &sl, rng, p);"),
      "c-mbedtls-ecdsa",
    )?.hndl,
    false,
  );
  assert.equal(
    rule(run("fw.c", "mbedtls_ecdh_compute_shared(&grp, &z, &qp, &d, rng, p);"), "c-mbedtls-ecdh")
      ?.hndl,
    true,
  );
  assert.equal(
    rule(run("fw.c", "mbedtls_dhm_calc_secret(&dhm, out, olen, &n, rng, p);"), "c-mbedtls-dh")
      ?.algorithm,
    "DH",
  );
});

test("C/wolfSSL (embedded): rsa / ecc / ecdh / dh / x25519 / ed25519 classify correctly", () => {
  assert.equal(
    rule(run("iot.c", "wc_MakeRsaKey(&key, 2048, 65537, &rng);"), "c-wolfssl-rsa")?.hndl,
    true,
  );
  const ecc = rule(run("iot.c", "wc_ecc_make_key(&rng, 32, &key);"), "c-wolfssl-ecc-keygen");
  assert.equal(ecc?.algorithm, "ECDH");
  assert.equal(ecc?.hndl, true);
  assert.equal(
    rule(run("iot.c", "wc_ecc_sign_hash(h, hl, s, &sl, &rng, &key);"), "c-wolfssl-ecdsa")?.hndl,
    false,
  );
  assert.equal(
    rule(run("iot.c", "wc_ecc_shared_secret(&priv, &pub, out, &olen);"), "c-wolfssl-ecdh")?.hndl,
    true,
  );
  assert.equal(
    rule(run("iot.c", "wc_DhAgree(&dh, z, &zl, priv, pl, pub, publ);"), "c-wolfssl-dh")?.algorithm,
    "DH",
  );
  assert.equal(
    rule(
      run("iot.c", "wc_curve25519_shared_secret(&priv, &pub, out, &olen);"),
      "c-wolfssl-curve25519",
    )?.algorithm,
    "X25519",
  );
  assert.equal(
    rule(run("iot.c", "wc_ed25519_sign_msg(m, ml, s, &sl, &key);"), "c-wolfssl-ed25519")?.algorithm,
    "EdDSA",
  );
});

test("embedded C: distinctive prefixes don't fire on clean firmware code", () => {
  // Symmetric / hashing calls from the same libraries must stay silent.
  assert.deepEqual(run("fw.c", "mbedtls_aes_setkey_enc(&aes, key, 256);"), []);
  assert.deepEqual(run("iot.c", "wc_Sha256Update(&sha, data, len);"), []);
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

test("Java: ECIES / TLSv1.1 / new X448KeyPairGenerator are all caught", () => {
  const ecies = rule(run("A.java", 'Cipher c = Cipher.getInstance("ECIES");'), "java-ecdh");
  assert.ok(ecies, "ECIES (EC encryption) is flagged as HNDL key establishment");
  assert.equal(ecies.hndl, true);
  assert.ok(
    rule(run("A.java", 'SSLContext.getInstance("TLSv1.1");'), "java-tls-legacy-version"),
    "TLSv1.1 is flagged like TLSv1.0",
  );
  assert.ok(
    run("A.java", "var g = new X448KeyPairGenerator();").some((f) => f.ruleId.startsWith("java-")),
    "Java `new X448KeyPairGenerator()` is caught",
  );
  // TLS 1.2/1.3 must NOT fire.
  assert.deepEqual(
    run("A.java", 'SSLContext.getInstance("TLSv1.2");').filter((f) => f.category === "tls"),
    [],
  );
});

test("C#: SecurityAlgorithms.RsaSha256Signature (SigningCredentials constant) is caught", () => {
  assert.ok(
    rule(
      run("A.cs", "new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature)"),
      "csharp-jwt-alg",
    ),
  );
});

test("C#: block-body and delegate accept-any cert validators are flagged; pinning is not", () => {
  const cb = "handler.ServerCertificateCustomValidationCallback";
  assert.ok(
    rule(run("A.cs", `${cb} = (m,c,ch,e) => { return true; };`), "csharp-tls-cert-validation"),
    "block-body => { return true; } is flagged",
  );
  assert.ok(
    rule(run("B.cs", `${cb} = delegate { return true; };`), "csharp-tls-cert-validation"),
    "delegate { return true; } is flagged",
  );
  assert.equal(
    rule(
      run("C.cs", `${cb} = (m,c,ch,e) => { return c.Thumbprint == Pinned; };`),
      "csharp-tls-cert-validation",
    ),
    undefined,
    "block-body pinning (returns a comparison) is NOT flagged",
  );
});

test("C: a real RSA/ECDSA sign survives in a file that also uses HMAC (per-match guard)", () => {
  const mixed =
    "EVP_PKEY *mk = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, len);\n" +
    "EVP_DigestSignInit(c1, NULL, EVP_sha256(), NULL, mk);\n" +
    "int pad;\n".repeat(60) +
    "EVP_DigestSignInit(c2, NULL, EVP_sha256(), NULL, rsa_pkey);";
  assert.ok(rule(run("m.c", mixed), "c-evp-sign"), "the RSA sign far from the HMAC setup fires");
  // HMAC-only file stays silent.
  const hmacOnly =
    "EVP_PKEY *mk = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, len);\n" +
    "EVP_DigestSignInit(c1, NULL, EVP_sha256(), NULL, mk);";
  assert.equal(rule(run("h.c", hmacOnly), "c-evp-sign"), undefined);
});

test("TLS weak cipher: hardened full-suite exclusions are not flagged; enabled ones are", () => {
  const weak = (s: string) =>
    rule(run("t.ts", `const o = { ciphers: '${s}' };`), "tls-weak-cipher");
  assert.ok(weak("ECDHE-RSA-RC4-SHA:HIGH"), "an enabled weak suite fires");
  assert.equal(weak("HIGH:!ECDHE-RSA-RC4-SHA"), undefined, "an excluded full suite (!) does not");
  assert.equal(weak("HIGH:!aNULL:!MD5:!RC4"), undefined, "a hardened exclusion list does not");
});

test("Rust: qualified x448::Secret is caught", () => {
  assert.ok(rule(run("m.rs", "use x448::Secret;"), "rust-x448"), "x448::Secret flagged");
});

test("C: EVP_PKEY_derive on an HKDF context is NOT flagged; real ECDH still is", () => {
  const hkdf =
    "EVP_PKEY_CTX *p = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);\nEVP_PKEY_derive(p, out, &len);";
  assert.equal(rule(run("a.c", hkdf), "c-evp-derive"), undefined, "HKDF is not (EC)DH");
  const ecdh = "EVP_PKEY_derive_set_peer(ctx, peer);\nEVP_PKEY_derive(ctx, secret, &len);";
  assert.ok(rule(run("a.c", ecdh), "c-evp-derive"), "real ECDH (with set_peer) still flagged");
});

test("C: EVP_DigestSignInit for HMAC is NOT flagged as an asymmetric signature", () => {
  const hmac =
    "EVP_PKEY *k = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, len);\nEVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, k);";
  assert.equal(rule(run("a.c", hmac), "c-evp-sign"), undefined);
  // A plain EVP_DigestSignInit with no MAC context still fires (RSA/ECDSA/EdDSA sign).
  assert.ok(
    rule(run("a.c", "EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_key);"), "c-evp-sign"),
  );
});

test("no double-count: a JWK object in JS source is owned by jwk, not jwt-jose", () => {
  // `{ "kty":"RSA", "alg":"RS256" }` — jwk-rsa owns it; jwt-classical-alg must defer.
  const src = 'const k = { "kty": "RSA", "alg": "RS256" };';
  const found = run("a.ts", src);
  assert.ok(rule(found, "jwk-rsa"), "jwk-rsa fires");
  assert.equal(rule(found, "jwt-classical-alg"), undefined, "jwt-classical-alg defers on kty");
});

test("no double-count: subtle RSA-OAEP is owned by webcrypto, not jose-rsa-oaep", () => {
  const src = 'crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, data);';
  const found = run("a.ts", src);
  assert.ok(rule(found, "webcrypto-classical"), "webcrypto fires");
  assert.equal(rule(found, "jose-rsa-oaep"), undefined, "jose-rsa-oaep defers near a subtle call");
});

test("RSA1_5 near a subtle call still fires (webcrypto does not match RSA1_5)", () => {
  // Only RSA-OAEP is deferred to webcrypto; RSA1_5 must not be dropped, since
  // webCryptoDetector's regex has no RSA1_5 alternative.
  const src =
    'const k = await crypto.subtle.importKey("jwk", jwk, alg, false, ["decrypt"]);\n' +
    'const header = { alg: "RSA1_5", enc: "A128CBC-HS256" };';
  assert.ok(rule(run("j.ts", src), "jose-rsa-oaep"), "RSA1_5 legacy key transport still flagged");
});
