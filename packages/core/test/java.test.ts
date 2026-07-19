/**
 * Tests for the Java/Kotlin JCA detector. The JCA keys everything off an
 * algorithm STRING passed to `getInstance`, so these pin the classifier: the
 * right (factory, alg) pair must map to the right rule, and symmetric/hash
 * algorithms must map to nothing.
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

test("the JVM pack also covers Scala (.scala) and Scala scripts (.sc)", () => {
  // Scala compiles against the same JCA, so the Java rules apply to .scala/.sc.
  const rsa = byRule(
    run("Keys.scala", 'val kpg = KeyPairGenerator.getInstance("RSA")'),
    "java-rsa",
  );
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);
  const ec = byRule(
    run("build.sc", 'val ec = KeyPairGenerator.getInstance("EC")'),
    "java-ec-keygen",
  );
  assert.equal(ec?.algorithm, "ECDH");
});

test("KeyPairGenerator RSA/EC/DSA/DH classify correctly", () => {
  const rsa = byRule(run("A.java", 'KeyPairGenerator.getInstance("RSA")'), "java-rsa");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, true);

  const ec = byRule(run("A.java", 'KeyPairGenerator.getInstance("EC")'), "java-ec-keygen");
  assert.equal(ec?.algorithm, "ECDH");
  assert.equal(ec?.hndl, true, "EC keygen is conservatively HNDL-exposed");

  assert.equal(
    byRule(run("A.java", 'KeyPairGenerator.getInstance("DSA")'), "java-dsa")?.algorithm,
    "DSA",
  );
  const dh = byRule(run("A.java", 'KeyPairGenerator.getInstance("DiffieHellman")'), "java-dh");
  assert.equal(dh?.algorithm, "DH");
  assert.equal(dh?.hndl, true);
});

test("Signature strings classify by suffix (…withRSA vs …withECDSA)", () => {
  const rsa = byRule(run("A.java", 'Signature.getInstance("SHA256withRSA")'), "java-rsa-sign");
  assert.equal(rsa?.algorithm, "RSA");
  assert.equal(rsa?.hndl, false);
  const ec = byRule(run("A.java", 'Signature.getInstance("SHA256withECDSA")'), "java-ecdsa-sign");
  assert.equal(ec?.algorithm, "ECDSA");
  assert.equal(ec?.hndl, false);
});

test("Cipher RSA is KEM/HNDL; KeyAgreement ECDH is key-exchange/HNDL", () => {
  const cipher = byRule(
    run("A.java", 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")'),
    "java-rsa",
  );
  assert.equal(cipher?.category, "kem");
  assert.equal(cipher?.hndl, true);
  const ka = byRule(run("A.java", 'KeyAgreement.getInstance("ECDH")'), "java-ecdh");
  assert.equal(ka?.algorithm, "ECDH");
  assert.equal(ka?.hndl, true);
});

test("modern-but-classical: X25519 and Ed25519", () => {
  assert.equal(
    byRule(run("A.java", 'KeyPairGenerator.getInstance("X25519")'), "java-xdh")?.algorithm,
    "X25519",
  );
  const ed = byRule(run("A.java", 'KeyPairGenerator.getInstance("Ed25519")'), "java-eddsa");
  assert.equal(ed?.algorithm, "EdDSA");
  assert.equal(ed?.hndl, false);
});

test("BouncyCastle lightweight-API classes are detected", () => {
  assert.equal(
    byRule(run("A.java", "s = new ECDSASigner();"), "java-ecdsa-sign")?.algorithm,
    "ECDSA",
  );
  assert.equal(
    byRule(run("A.java", "a = new X25519Agreement();"), "java-xdh")?.algorithm,
    "X25519",
  );
  assert.equal(
    byRule(run("A.java", "g = new RSAKeyPairGenerator();"), "java-rsa")?.algorithm,
    "RSA",
  );
});

test("Kotlin (.kt) uses the same JCA detector", () => {
  const f = byRule(
    run("Keys.kt", 'val s = Signature.getInstance("SHA256withRSA")'),
    "java-rsa-sign",
  );
  assert.equal(f?.algorithm, "RSA");
});

test("symmetric / hashing getInstance calls produce no findings", () => {
  // Cipher is in the factory list, but AES classifies to nothing.
  assert.deepEqual(run("A.java", 'Cipher.getInstance("AES/GCM/NoPadding")'), []);
  // MessageDigest / Mac / KeyGenerator are not asymmetric factories at all.
  assert.deepEqual(run("A.java", 'MessageDigest.getInstance("SHA-256")'), []);
  assert.deepEqual(run("A.java", 'Mac.getInstance("HmacSHA256")'), []);
  assert.deepEqual(run("A.java", 'KeyGenerator.getInstance("AES")'), []);
});

test("clean Java source produces no findings", () => {
  const src = [
    "import java.security.MessageDigest;",
    "public class Clean {",
    "  // once used KeyPairGenerator.getInstance for RSA, now removed",
    '  String alg = "RSA";',
    "  void run() throws Exception {",
    '    var md = MessageDigest.getInstance("SHA-256");',
    "  }",
    "}",
  ].join("\n");
  const findings = run("Clean.java", src);
  assert.deepEqual(findings, [], `expected none, got ${findings.map((f) => f.ruleId).join(", ")}`);
});

test("Java detector does not run on non-Java files", () => {
  assert.equal(byRule(run("a.py", 'KeyPairGenerator.getInstance("RSA")'), "java-rsa"), undefined);
});

test("an import of NoopHostnameVerifier is NOT flagged (only real usage is)", () => {
  // A bare import line is not disabled verification — firing high severity on it is
  // a false positive.
  assert.equal(
    byRule(
      run("A.java", "import org.apache.http.conn.ssl.NoopHostnameVerifier;\nclass A {}"),
      "java-tls-hostname-verification-disabled",
    ),
    undefined,
  );
});

test("real all-trusting hostname-verifier usage IS flagged (construction + member access)", () => {
  assert.ok(
    byRule(
      run("A.java", "var v = new NoopHostnameVerifier();"),
      "java-tls-hostname-verification-disabled",
    ),
    "new NoopHostnameVerifier() must fire",
  );
  assert.ok(
    byRule(
      run("A.java", "var a = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;"),
      "java-tls-hostname-verification-disabled",
    ),
    ".ALLOW_ALL_HOSTNAME_VERIFIER must fire",
  );
});

test("Kotlin bare-form BouncyCastle constructors (no `new`) are flagged", () => {
  // Kotlin instantiates without `new`; the RSA/EC/DSA/DH lightweight-API classes were
  // only matched in their `new …()` (Java/Scala) form before.
  assert.equal(
    byRule(run("Keys.kt", "val g = ECKeyPairGenerator()"), "java-ec-keygen")?.algorithm,
    "ECDH",
  );
  assert.ok(byRule(run("Keys.kt", "val r = RSAKeyPairGenerator()"), "java-rsa"));
  // The Java/Scala `new` form is still matched exactly once (no double-count).
  const news = run("Keys.java", "var g = new ECKeyPairGenerator();").filter(
    (f) => f.ruleId === "java-ec-keygen",
  );
  assert.equal(news.length, 1);
});
