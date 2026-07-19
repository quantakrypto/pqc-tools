/**
 * Tests for JSON Web Key (JWK / JWKS) detection — classical key material in
 * JSON, the surface the source packs and the PEM detector both miss.
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

test("RSA JWK is detected as HNDL-exposed RSA", () => {
  const jwks = '{"keys":[{"kty":"RSA","n":"0vx7...","e":"AQAB","kid":"a"}]}';
  const f = rule(run("jwks.json", jwks), "jwk-rsa");
  assert.ok(f, "RSA JWK detected");
  assert.equal(f.algorithm, "RSA");
  assert.equal(f.hndl, true);
});

test("EC JWK (P-256) is detected as ambiguous EC (HNDL via the ECDH path)", () => {
  const jwk = '{"kty":"EC","crv":"P-256","x":"f83O...","y":"x_FEz..."}';
  const f = rule(run("key.json", jwk), "jwk-ec");
  assert.ok(f, "EC JWK detected");
  assert.equal(f.algorithm, "ECDH");
  assert.equal(f.hndl, true);
});

test("OKP JWKs split into EdDSA signatures vs X25519/X448 key agreement", () => {
  const ed = rule(run("k.json", '{"kty":"OKP","crv":"Ed25519","x":"11q..."}'), "jwk-eddsa");
  assert.equal(ed?.algorithm, "EdDSA");
  assert.equal(ed?.hndl, false);
  const x = rule(run("k.json", '{"kty":"OKP","crv":"X25519","x":"3p7..."}'), "jwk-xdh");
  assert.equal(x?.algorithm, "X25519");
  assert.equal(x?.hndl, true);
  // Ed448 / X448 are covered by the same rules.
  assert.ok(rule(run("k.json", '{"crv":"Ed448"}'), "jwk-eddsa"));
  assert.ok(rule(run("k.json", '{"crv":"X448"}'), "jwk-xdh"));
});

test("an EC JWK is counted once (crv-keyed), not double-counted with kty", () => {
  // A single EC JWK has both "kty":"EC" and a "crv" — it must produce exactly one
  // finding (the crv-keyed jwk-ec), not two.
  const findings = run("one.json", '{"kty":"EC","crv":"P-384","x":"a","y":"b"}');
  const jwk = findings.filter((f) => f.ruleId.startsWith("jwk-"));
  assert.equal(jwk.length, 1);
  assert.equal(jwk[0].ruleId, "jwk-ec");
});

test("ordinary JSON without JWK fields produces no JWK findings", () => {
  const config = '{"name":"app","version":"1.0.0","port":8080,"crvOptions":false}';
  assert.deepEqual(
    run("package.json", config).filter((f) => f.ruleId.startsWith("jwk-")),
    [],
  );
});

test("a symmetric/oct JWK is not flagged (no classical asymmetric exposure)", () => {
  // oct (symmetric) keys are not quantum-broken by Shor; they must not fire.
  const oct = '{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg","alg":"A256GCM"}';
  assert.deepEqual(
    run("sym.json", oct).filter((f) => f.ruleId.startsWith("jwk-")),
    [],
  );
});

test("an RSA SIGNING JWK is a signature (hndl:false); an encryption RSA JWK stays HNDL", () => {
  const sig = rule(run("jwks.json", '{"kty":"RSA","use":"sig","alg":"RS256"}'), "jwk-rsa");
  assert.equal(sig?.category, "signature");
  assert.equal(sig?.hndl, false);
  const enc = rule(run("k.json", '{"kty":"RSA","use":"enc"}'), "jwk-rsa");
  assert.equal(enc?.hndl, true);
});

test("jwk defers to cloudformation inside an ARM/CFN template (no double-count)", () => {
  const arm =
    '{"resources":[{"type":"Microsoft.KeyVault/vaults/keys","properties":{"kty":"RSA"}}]}';
  assert.deepEqual(
    run("azuredeploy.json", arm).filter((f) => f.ruleId.startsWith("jwk-")),
    [],
    "jwk stays silent; cfn-arm-keyvault-rsa owns the ARM key",
  );
});

test("jwk is skipped on doc extensions (a README JWK example is not live)", () => {
  assert.deepEqual(
    run("README.md", 'Example: {"kty":"RSA"}').filter((f) => f.ruleId.startsWith("jwk-")),
    [],
  );
});

test("in a packed JWKS, each key is classified by its OWN object (no window contamination)", () => {
  const jwks = `{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256"},{"kty":"EC","crv":"P-256","use":"enc","alg":"ECDH-ES"}]}`;
  const ecs = run("multi.jwks", jwks).filter((f) => f.ruleId === "jwk-ec");
  assert.equal(ecs.length, 2);
  // The sig key → signature/hndl:false; the enc key STAYS key-exchange/hndl:true.
  assert.ok(
    ecs.some((f) => f.category === "signature" && f.hndl === false),
    "sig key classified",
  );
  assert.ok(
    ecs.some((f) => f.category === "key-exchange" && f.hndl === true),
    "adjacent enc key NOT flipped to signature",
  );
});

test("an explicit `use:enc` on an RSA JWK stays HNDL even if a sig alg is present", () => {
  // A contradictory key still errs toward the harvestable (enc) classification.
  const f = rule(run("k.json", '{"kty":"RSA","use":"enc","alg":"RS256"}'), "jwk-rsa");
  assert.equal(f?.hndl, true);
});
