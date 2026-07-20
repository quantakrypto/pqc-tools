/**
 * Tests for the weak-hash-in-signature/certificate detector — SHA-1 / MD5 bound
 * to a digital-signature or X.509 certificate algorithm (quantum-adjacent: same
 * migration window as PQC). Imports the detector DIRECTLY so the test exercises
 * exactly this surface, not the whole registry.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { weakHashDetector } from "../src/detectors/weak-hash.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  if (!weakHashDetector.appliesTo(file)) return [];
  return weakHashDetector.detect({ file, content });
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

// --- Positives ---------------------------------------------------------------

test("Java SHA1withRSA signature algorithm is flagged (medium, hndl false)", () => {
  const f = rule(
    run("Sign.java", 'Signature s = Signature.getInstance("SHA1withRSA");'),
    "weak-hash-sha1-signature",
  );
  assert.ok(f, "SHA1withRSA flagged");
  assert.equal(f?.category, "hash");
  assert.equal(f?.severity, "medium");
  assert.equal(f?.hndl, false);
  assert.equal(f?.algorithm, "unknown");
});

test("Java MD5withRSA signature algorithm is flagged (high severity)", () => {
  const f = rule(
    run("Sign.java", 'Signature s = Signature.getInstance("MD5withRSA");'),
    "weak-hash-md5-signature",
  );
  assert.ok(f, "MD5withRSA flagged");
  assert.equal(f?.category, "hash");
  assert.equal(f?.severity, "high");
  assert.equal(f?.hndl, false);
});

test("X.509 cert signature-algorithm NAME sha1WithRSAEncryption in a .conf is flagged", () => {
  const f = rule(
    run("openssl.conf", "default_md = sha1WithRSAEncryption"),
    "weak-hash-sha1-signature",
  );
  assert.ok(f, "sha1WithRSAEncryption flagged");
  assert.equal(f?.category, "hash");
});

test("X.509 signature-algorithm OID 1.2.840.113549.1.1.5 is flagged as SHA-1 sig", () => {
  const f = rule(
    run("cert.txt", "Signature Algorithm: 1.2.840.113549.1.1.5"),
    "weak-hash-sha1-signature",
  );
  assert.ok(f, "sha1WithRSAEncryption OID flagged");
});

test("OpenSSL cert-signing CLI with -sha1 is flagged", () => {
  const f = rule(
    run("make-cert.sh", "openssl req -x509 -sha1 -key k.pem -out cert.pem"),
    "weak-hash-sha1-signature",
  );
  assert.ok(f, "openssl req -x509 -sha1 flagged");
  assert.equal(f?.category, "hash");
  assert.equal(f?.hndl, false);
});

test(".NET SignData with a weak hash is flagged", () => {
  assert.ok(
    rule(
      run(
        "Sign.cs",
        "var sig = rsa.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);",
      ),
      "weak-hash-sha1-signature",
    ),
    "SignData(HashAlgorithmName.SHA1) flagged",
  );
  assert.ok(
    rule(run("Sign.cs", 'var sig = rsacsp.SignData(data, "MD5");'), "weak-hash-md5-signature"),
    'SignData(..., "MD5") flagged',
  );
});

// --- Negatives ---------------------------------------------------------------

test("a bare sha1sum checksum with NO signature marker is NOT flagged", () => {
  assert.deepEqual(run("build.sh", "sha1sum release.tar.gz > SHA1SUMS"), []);
});

test("a bare SHA1(data) hash call with NO signature marker is NOT flagged", () => {
  assert.deepEqual(run("hash.c", "unsigned char *d = SHA1(data, len, out);"), []);
});

test("a SHA-256 signature algorithm (SHA256withRSA) is NOT flagged", () => {
  assert.deepEqual(run("Sign.java", 'Signature s = Signature.getInstance("SHA256withRSA");'), []);
});

test("an openssl checksum (dgst -sha1, no -sign) is NOT flagged", () => {
  // Passes the file-level fast-reject (dgst marker) but must not produce a
  // finding: `dgst -sha1` with no `-sign` is a digest, not a signature.
  assert.deepEqual(run("hash.sh", "openssl dgst -sha1 release.tar.gz"), []);
});

test("the same tokens in prose docs (.md) are NOT flagged", () => {
  assert.deepEqual(
    run("guide.md", "Legacy certs used SHA1withRSA (sha1WithRSAEncryption) before 2016."),
    [],
  );
});

test("a commented-out SHA1withRSA line is NOT flagged", () => {
  assert.deepEqual(run("Sign.java", '// Signature s = Signature.getInstance("SHA1withRSA");'), []);
});

test("audit H3: .NET SignData with a nested-call first argument is still flagged", () => {
  const src =
    "var sig = rsa.SignData(Encoding.UTF8.GetBytes(msg), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);";
  assert.ok(rule(run("Signer.cs", src), "weak-hash-sha1-signature"), "nested-arg SignData(SHA1)");
  const md5 =
    "var h = rsa.SignHash(Hash.Compute(x), HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1);";
  assert.ok(rule(run("Signer.cs", md5), "weak-hash-md5-signature"), "nested-arg SignHash(MD5)");
});

test("audit M1: openssl x509 read-only thumbprint ops are NOT flagged (only signing is)", () => {
  // Display/identifier operations — NOT signature generation.
  assert.deepEqual(
    run("ops.sh", "openssl x509 -in cert.pem -noout -fingerprint -sha1").filter((f) =>
      f.ruleId.startsWith("weak-hash-"),
    ),
    [],
  );
  assert.deepEqual(
    run("ops.sh", "openssl x509 -in cert.pem -subject_hash -sha1").filter((f) =>
      f.ruleId.startsWith("weak-hash-"),
    ),
    [],
  );
  // Actual signing operations still fire.
  assert.ok(
    rule(
      run("ca.sh", "openssl req -new -x509 -sha1 -key k.pem -out c.pem"),
      "weak-hash-sha1-signature",
    ),
    "self-signed cert gen",
  );
  assert.ok(
    rule(
      run("ca.sh", "openssl x509 -req -signkey ca.key -sha1 -in csr.pem"),
      "weak-hash-sha1-signature",
    ),
    "sign a CSR",
  );
});
