/**
 * Tests for the Elixir source detector — Erlang :crypto, the X509 hex package,
 * and erlang-jose.
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

test(":crypto.generate_key classifies rsa / dh and the ecdh curve variants", () => {
  assert.equal(
    rule(run("k.ex", ":crypto.generate_key(:rsa, {2048, 65537})"), "elixir-crypto-keygen")
      ?.algorithm,
    "RSA",
  );
  assert.equal(
    rule(run("k.ex", ":crypto.generate_key(:dh, params)"), "elixir-crypto-keygen")?.algorithm,
    "DH",
  );
  // ecdh with an X25519 curve atom → X25519; a NIST curve → generic ECDH.
  assert.equal(
    rule(run("k.ex", ":crypto.generate_key(:ecdh, :x25519)"), "elixir-crypto-keygen")?.algorithm,
    "X25519",
  );
  const ec = rule(run("k.ex", ":crypto.generate_key(:ecdh, :secp256r1)"), "elixir-crypto-keygen");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true);
});

test(":crypto.sign classifies the algorithm atom (ecdsa/rsa/eddsa/dss)", () => {
  assert.equal(
    rule(run("k.ex", ":crypto.sign(:ecdsa, :sha256, msg, key)"), "elixir-crypto-sign")?.algorithm,
    "ECDSA",
  );
  assert.equal(
    rule(run("k.ex", ":crypto.verify(:eddsa, :none, m, s, [k, :ed25519])"), "elixir-crypto-sign")
      ?.algorithm,
    "EdDSA",
  );
  // DSA: Erlang's algorithm atom is :dss — previously misclassified to nothing.
  assert.equal(
    rule(run("k.ex", ":crypto.sign(:dss, :sha256, msg, key)"), "elixir-crypto-sign")?.algorithm,
    "DSA",
  );
});

test("X509 and JOSE key generation are detected", () => {
  assert.equal(
    rule(run("k.ex", "X509.PrivateKey.new_rsa(2048)"), "elixir-x509-keygen")?.algorithm,
    "RSA",
  );
  const ec = rule(run("k.ex", "X509.PrivateKey.new_ec(:secp256r1)"), "elixir-x509-keygen");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(
    rule(run("k.ex", "JOSE.JWK.generate_key({:rsa, 2048})"), "elixir-jose-jwk")?.algorithm,
    "RSA",
  );
});

test("Elixir detector is gated to .ex/.exs and ignores symmetric/HMAC :crypto calls", () => {
  // Not an Elixir file → no Elixir findings.
  assert.deepEqual(
    run("notes.txt", ":crypto.generate_key(:rsa, x)").filter((f) => f.ruleId.startsWith("elixir-")),
    [],
  );
  // Symmetric / MAC :crypto calls must stay silent.
  assert.deepEqual(
    run("k.ex", ":crypto.mac(:hmac, :sha256, key, data)").filter((f) =>
      f.ruleId.startsWith("elixir-"),
    ),
    [],
  );
  // A :crypto.generate_key with a non-asymmetric type atom (srp) stays silent.
  assert.deepEqual(
    run("k.ex", ":crypto.generate_key(:srp, params)").filter((f) => f.ruleId.startsWith("elixir-")),
    [],
  );
});
