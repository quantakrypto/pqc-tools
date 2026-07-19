/**
 * Tests for JOSE/JWE key-management detection — classical asymmetric wrapping of
 * the content-encryption key (confidentiality → harvest-now-decrypt-later).
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

test("JWE alg RSA-OAEP-256 is flagged as RSA KEM, HNDL", () => {
  const f = rule(run("token.json", '{"alg":"RSA-OAEP-256","enc":"A256GCM"}'), "jose-jwe-rsa");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "kem");
  assert.equal(f?.hndl, true);
});

test("JWE alg ECDH-ES+A128KW is flagged as ECDH key agreement, HNDL", () => {
  const f = rule(
    run("header.json", '{ "alg": "ECDH-ES+A128KW", "enc": "A128GCM" }'),
    "jose-jwe-ecdh",
  );
  assert.equal(f?.algorithm, "ECDH");
  assert.equal(f?.category, "key-exchange");
  assert.equal(f?.hndl, true);
});

test("plain ECDH-ES without the +KW variant is also caught", () => {
  assert.ok(rule(run("h.json", '{"alg":"ECDH-ES"}'), "jose-jwe-ecdh"));
});

test("a JWS signature alg (RS256) does NOT trigger the JWE key-mgmt detector", () => {
  // This detector is confidentiality-only; RS256 is a signature and out of scope here.
  assert.deepEqual(
    run("jws.json", '{"alg":"RS256","typ":"JWT"}').filter((f) => f.ruleId.startsWith("jose-")),
    [],
  );
});

test("a JOSE alg shown in markdown prose is NOT flagged (docs are out of scope)", () => {
  assert.deepEqual(
    run("README.md", 'Example JWE header: `{"alg":"RSA-OAEP-256"}`.').filter((f) =>
      f.ruleId.startsWith("jose-"),
    ),
    [],
  );
});

test("jose defers to jwk when the alg belongs to a JWK object (no double-count)", () => {
  // A JWK that declares its `alg` — jwk owns the key; jose must stay silent.
  const jwk = '{"kty":"RSA","alg":"RSA-OAEP","n":"...","e":"AQAB"}';
  assert.deepEqual(
    run("key.json", jwk).filter((f) => f.ruleId.startsWith("jose-")),
    [],
  );
  // A standalone JWE header (no kty) is still flagged.
  assert.ok(rule(run("hdr.json", '{"alg":"RSA-OAEP","enc":"A256GCM"}'), "jose-jwe-rsa"));
});
