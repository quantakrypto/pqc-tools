/**
 * Tests for the PHP source detector — openssl, phpseclib3, and libsodium.
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

test("openssl_pkey_new defaults to RSA and classifies EC/DSA by OPENSSL_KEYTYPE_*", () => {
  const rsa = rule(
    run("k.php", '<?php $k = openssl_pkey_new(["private_key_bits" => 2048]);'),
    "php-openssl-keygen",
  );
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);
  const ec = rule(
    run("k.php", '<?php $k = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC]);'),
    "php-openssl-keygen",
  );
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
  const dsa = rule(
    run("k.php", '<?php $k = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_DSA]);'),
    "php-openssl-keygen",
  );
  assert.equal(dsa?.algorithm, "DSA");
  assert.equal(dsa?.hndl, false);
});

test("the openssl_pkey_new key-type window does not bleed into the next statement", () => {
  // Two calls: the first has no key type (→ RSA); the second is EC. The first
  // must NOT pick up the second statement's OPENSSL_KEYTYPE_EC.
  const src = [
    "<?php",
    '$a = openssl_pkey_new(["private_key_bits" => 2048]);',
    '$b = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC]);',
  ].join("\n");
  const keygens = run("k.php", src).filter((f) => f.ruleId === "php-openssl-keygen");
  assert.equal(keygens.length, 2);
  const line2 = keygens.find((f) => f.location.line === 2);
  assert.equal(line2?.algorithm, "RSA", "the RSA-default call is not misclassified as EC");
});

test("openssl encrypt / sign and phpseclib3 createKey classify correctly", () => {
  assert.equal(
    rule(run("a.php", "<?php openssl_public_encrypt($d, $o, $pub);"), "php-openssl-rsa-crypt")
      ?.hndl,
    true,
  );
  assert.equal(
    rule(run("a.php", "<?php openssl_sign($d, $s, $priv);"), "php-openssl-sign")?.category,
    "signature",
  );
  const ec = rule(run("a.php", '<?php $k = EC::createKey("Ed25519");'), "php-phpseclib-keygen");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(
    rule(run("a.php", "<?php $k = RSA::createKey(3072);"), "php-phpseclib-keygen")?.algorithm,
    "RSA",
  );
});

test("openssl_seal / openssl_open (RSA envelope) are flagged as RSA HNDL", () => {
  assert.equal(
    rule(run("a.php", "<?php openssl_seal($d, $s, $ek, $pubkeys);"), "php-openssl-rsa-crypt")?.hndl,
    true,
  );
  assert.equal(
    rule(run("a.php", "<?php openssl_open($s, $o, $ek, $priv);"), "php-openssl-rsa-crypt")
      ?.algorithm,
    "RSA",
  );
  // Must not over-broaden onto other openssl_* functions.
  assert.equal(
    rule(run("a.php", "<?php $c = openssl_x509_parse($cert);"), "php-openssl-rsa-crypt"),
    undefined,
  );
});

test("libsodium box/kx (X25519) and sign (Ed25519) key pairs are detected", () => {
  assert.equal(
    rule(run("a.php", "<?php $kp = sodium_crypto_box_keypair();"), "php-sodium-x25519")?.algorithm,
    "X25519",
  );
  assert.equal(
    rule(run("a.php", "<?php $kp = sodium_crypto_sign_keypair();"), "php-sodium-ed25519")
      ?.algorithm,
    "EdDSA",
  );
  // The explicit-algorithm variant with the `_ed25519_` infix is also caught.
  assert.equal(
    rule(run("a.php", "<?php $kp = sodium_crypto_sign_ed25519_keypair();"), "php-sodium-ed25519")
      ?.algorithm,
    "EdDSA",
  );
});

test("PHP detector is gated to .php and stays silent on clean/symmetric PHP", () => {
  // openssl call text in a non-.php file must not fire the PHP detector.
  assert.deepEqual(
    run("notes.txt", "<?php openssl_pkey_new(); ?>").filter((f) => f.ruleId.startsWith("php-")),
    [],
  );
  // Symmetric AEAD (not asymmetric) must stay silent.
  assert.deepEqual(
    run(
      "a.php",
      "<?php $c = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($m, $ad, $n, $k);",
    ).filter((f) => f.ruleId.startsWith("php-")),
    [],
  );
});

test("PHP JWT: firebase/php-jwt classical alg 'RS256' is flagged (shared jwt rule)", () => {
  // PHP is now a JWT_HOST_EXTENSION, so the language-agnostic quoted-alg rule fires.
  const f = run("auth.php", "<?php $t = \\Firebase\\JWT\\JWT::encode($p, $k, 'RS256');").find(
    (x) => x.ruleId === "jwt-classical-alg",
  );
  assert.ok(f, "firebase/php-jwt RS256 is flagged as a classical JWT alg");
  // A symmetric HS256 token must NOT fire.
  assert.equal(
    run("auth.php", "<?php $t = JWT::encode($p, $k, 'HS256');").find(
      (x) => x.ruleId === "jwt-classical-alg",
    ),
    undefined,
  );
});
