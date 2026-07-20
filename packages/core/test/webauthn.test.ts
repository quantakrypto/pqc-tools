/**
 * Tests for WebAuthn / FIDO2 / passkey classical COSE signature-algorithm
 * detection. WebAuthn relying parties pin COSE alg ids as NUMERIC values
 * (`alg: -7`, `supportedAlgorithmIDs: [-7, -257]`) and library ENUM
 * identifiers (`COSEAlgorithmIdentifier.EDDSA`, `webauthncose.AlgES256`) — a
 * surface the quoted-string JWT rule (`"ES256"`) misses entirely.
 *
 * The detector is imported DIRECTLY (not via the registry) so these assertions
 * exercise only its own gate + regexes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { webauthnDetector } from "../src/detectors/webauthn.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  return webauthnDetector.appliesTo(file) ? webauthnDetector.detect({ file, content }) : [];
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("@simplewebauthn registration options with pubKeyCredParams [{alg:-7},{alg:-257}] → ECDSA + RSA", () => {
  const content = [
    "import { generateRegistrationOptions } from '@simplewebauthn/server';",
    "const options = await generateRegistrationOptions({",
    "  rpName: 'Example',",
    "  userName: 'alice',",
    "  pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],",
    "});",
  ].join("\n");
  const findings = run("register.ts", content);

  const ec = rule(findings, "webauthn-ecdsa");
  assert.equal(ec?.algorithm, "ECDSA");
  assert.equal(ec?.category, "signature");
  assert.equal(ec?.hndl, false);

  const rsa = rule(findings, "webauthn-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.category, "signature");
  assert.equal(rsa?.hndl, false);
});

test("@simplewebauthn verify option supportedAlgorithmIDs: [-8, -257] → EdDSA + RSA", () => {
  const content = [
    "await verifyRegistrationResponse({",
    "  response,",
    "  expectedChallenge,",
    "  supportedAlgorithmIDs: [-8, -257],",
    "});",
  ].join("\n");
  const findings = run("verify.js", content);

  const ed = rule(findings, "webauthn-eddsa");
  assert.equal(ed?.algorithm, "EdDSA");
  assert.equal(ed?.category, "signature");
  assert.equal(ed?.hndl, false);

  const rsa = rule(findings, "webauthn-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, false);
});

test("py_webauthn COSEAlgorithmIdentifier.EDDSA enum → EdDSA, signature, hndl:false", () => {
  const content = [
    "from webauthn.helpers.structs import COSEAlgorithmIdentifier",
    "options = generate_registration_options(",
    "    rp_id='example.com',",
    "    supported_pub_key_algs=[COSEAlgorithmIdentifier.EDDSA],",
    ")",
  ].join("\n");
  const f = rule(run("register.py", content), "webauthn-eddsa");
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("py_webauthn COSEAlgorithmIdentifier.ECDSA_SHA_256 enum → ECDSA", () => {
  const content = [
    "from webauthn.helpers.structs import COSEAlgorithmIdentifier",
    "algs = [COSEAlgorithmIdentifier.ECDSA_SHA_256]",
  ].join("\n");
  const f = rule(run("cfg.py", content), "webauthn-ecdsa");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.hndl, false);
});

test("go-webauthn webauthncose.AlgES256 / AlgRS256 constants → ECDSA + RSA", () => {
  const content = [
    "package main",
    'import "github.com/go-webauthn/webauthn/protocol/webauthncose"',
    "var supported = []webauthncose.COSEAlgorithmIdentifier{",
    "  webauthncose.AlgES256,",
    "  webauthncose.AlgRS256,",
    "}",
  ].join("\n");
  const findings = run("auth.go", content);
  assert.equal(rule(findings, "webauthn-ecdsa")?.algorithm, "ECDSA");
  assert.equal(rule(findings, "webauthn-rsa")?.algorithm, "RSA");
});

test("webauthn4j COSEAlgorithmIdentifier.RS256 enum → RSA", () => {
  const content = [
    "import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;",
    "COSEAlgorithmIdentifier alg = COSEAlgorithmIdentifier.RS256;",
  ].join("\n");
  const f = rule(run("Rp.java", content), "webauthn-rsa");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, false);
});

// --- negatives -----------------------------------------------------------

test("a bare `alg: -7` with NO WebAuthn marker does not fire (marker gate)", () => {
  const content = ["const chart = {", "  align: 'left',", "  alg: -7,", "};"].join("\n");
  assert.deepEqual(run("chart.js", content), []);
});

test("a prose .md mentioning WebAuthn algorithms is excluded (DOC_EXTENSIONS)", () => {
  const prose =
    "## WebAuthn\n\nOur relying party pins `pubKeyCredParams` to ES256 (alg -7) and RS256 (alg -257).";
  assert.deepEqual(run("docs/webauthn.md", prose), []);
});

test("a commented-out options object does not fire (comment masking)", () => {
  const content = [
    "// Legacy config, no longer used:",
    "// const opts = { pubKeyCredParams: [{ alg: -7 }, { alg: -257 }] };",
    "const opts = { pubKeyCredParams: [{ alg: -8 }] };",
  ].join("\n");
  const findings = run("register.js", content);
  // Only the live EdDSA line fires; the commented ECDSA/RSA lines are masked.
  assert.equal(rule(findings, "webauthn-eddsa")?.algorithm, "EdDSA");
  assert.equal(rule(findings, "webauthn-ecdsa"), undefined);
  assert.equal(rule(findings, "webauthn-rsa"), undefined);
});

test("symmetric-ish / non-classical COSE values (HS256, alg -6) do not fire", () => {
  const content = [
    "const opts = {",
    "  pubKeyCredParams: [{ type: 'public-key', alg: -6 }],", // -6 = direct, not in our set
    "  jwtAlg: 'HS256',", // HMAC, symmetric
    "};",
  ].join("\n");
  assert.deepEqual(run("opts.js", content), []);
});

test('audit M2: the JSON-serialized quoted `"alg": -N` form is flagged', () => {
  // PublicKeyCredentialCreationOptions is JSON-serializable and frequently stored/
  // transmitted/tested as JSON with string keys — the quoted-key form was missed.
  const json =
    '{"pubKeyCredParams":[{"alg": -7,"type":"public-key"},{"alg": -257,"type":"public-key"}]}';
  const found = run("options.json", json).map((f) => f.ruleId);
  assert.deepEqual([...new Set(found)].sort(), ["webauthn-ecdsa", "webauthn-rsa"]);
});
