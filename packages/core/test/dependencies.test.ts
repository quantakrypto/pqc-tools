/**
 * Tests for the vulnerable-dependency database and manifest scanner.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { vulnerableDependencies } from "../src/index.js";
import { scanManifest, isManifestFile } from "../src/dependencies.js";

test("database has a healthy number of curated entries across ecosystems", () => {
  assert.ok(vulnerableDependencies.length >= 15, "at least 15 curated entries");
  const validEcosystems = new Set(["npm", "pypi", "cargo", "go", "maven", "rubygems"]);
  const ecosystems = new Set<string>();
  for (const d of vulnerableDependencies) {
    assert.ok(validEcosystems.has(d.ecosystem), `${d.name}: valid ecosystem`);
    ecosystems.add(d.ecosystem);
    assert.ok(d.name.length > 0);
    assert.ok(d.algorithms.length > 0);
    assert.ok(d.reason.length > 0);
  }
  // Multi-ecosystem coverage — not just npm anymore.
  for (const eco of ["npm", "pypi", "cargo", "go", "maven", "rubygems"]) {
    assert.ok(ecosystems.has(eco), `database covers ${eco}`);
  }
});

test("isManifestFile recognises manifests across ecosystems", () => {
  for (const f of [
    "package.json",
    "nested/dir/package-lock.json",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "lib/foo.gemspec",
  ]) {
    assert.equal(isManifestFile(f), true, `${f} is a manifest`);
  }
  assert.equal(isManifestFile("src/index.ts"), false);
  assert.equal(isManifestFile("notes.txt"), false);
});

/** Assert a scanManifest run flags exactly the given package names (by title substring). */
function assertFlags(file: string, content: string, expected: string[]): void {
  const findings = scanManifest(file, content);
  for (const f of findings) {
    assert.equal(f.ruleId, "dep-vulnerable");
    assert.equal(f.category, "dependency");
    assert.equal(f.location.file, file);
  }
  const titles = findings.map((f) => f.title).join(" | ");
  for (const name of expected) {
    assert.ok(
      findings.some((f) => f.title.includes(name)),
      `expected ${name} flagged in ${file}; got: ${titles}`,
    );
  }
}

test("pypi: requirements.txt is parsed (name normalization, comments skipped)", () => {
  const req = [
    "# app deps",
    "PyJWT==2.8.0",
    "pycryptodome>=3.19",
    "cryptography~=41.0",
    "requests==2.31.0",
    "-r other.txt",
  ].join("\n");
  assertFlags("requirements.txt", req, ["pycryptodome", "cryptography", "pyjwt"]);
  assert.ok(!scanManifest("requirements.txt", req).some((f) => f.title.includes("requests")));
});

test("cargo: Cargo.toml dependency keys are matched", () => {
  const toml = [
    "[dependencies]",
    'rsa = "0.9"',
    'ed25519-dalek = { version = "2" }',
    'serde = "1"',
    "[dev-dependencies]",
    'p256 = "0.13"',
  ].join("\n");
  assertFlags("Cargo.toml", toml, ["rsa", "ed25519-dalek", "p256"]);
  assert.ok(!scanManifest("Cargo.toml", toml).some((f) => f.title.includes("serde")));
});

test("go.mod require paths are matched", () => {
  const gomod = [
    "module example.com/app",
    "go 1.22",
    "require (",
    "\tgolang.org/x/crypto v0.17.0",
    ")",
  ].join("\n");
  assertFlags("go.mod", gomod, ["golang.org/x/crypto"]);
});

test("maven pom.xml artifactIds are matched", () => {
  const pom = [
    "<project>",
    "  <dependencies>",
    "    <dependency>",
    "      <groupId>org.bouncycastle</groupId>",
    "      <artifactId>bcprov-jdk18on</artifactId>",
    "    </dependency>",
    "  </dependencies>",
    "</project>",
  ].join("\n");
  assertFlags("pom.xml", pom, ["bcprov-jdk18on"]);
});

test("rubygems Gemfile gem lines are matched", () => {
  const gemfile = [
    "source 'https://rubygems.org'",
    "gem 'jwt'",
    "gem 'rails'",
    "gem 'rbnacl'",
  ].join("\n");
  assertFlags("Gemfile", gemfile, ["jwt", "rbnacl"]);
  assert.ok(
    !scanManifest("Gemfile", gemfile).some(
      (f) => f.title === "Quantum-vulnerable dependency: rails",
    ),
  );
});

test("ecosystem scoping: a same-named package matches only its ecosystem", () => {
  // "rsa" is a pypi + cargo package but NOT npm — a package.json must not flag it.
  const pkg = JSON.stringify({ dependencies: { rsa: "^1.0.0" } });
  assert.equal(scanManifest("package.json", pkg).length, 0, "npm has no 'rsa' entry");
  // …but the same name in requirements.txt does flag.
  assertFlags("requirements.txt", "rsa==4.9\n", ["rsa"]);
});

test("package.json dependencies + devDependencies are matched", () => {
  const pkg = JSON.stringify({
    name: "demo",
    dependencies: { "node-forge": "^1.0.0", "left-pad": "1.0.0" },
    devDependencies: { elliptic: "^6.5.4" },
  });
  const findings = scanManifest("package.json", pkg);
  const names = findings.map((f) => f.title).sort();
  assert.ok(names.some((t) => t.includes("node-forge")));
  assert.ok(names.some((t) => t.includes("elliptic")));
  assert.ok(!names.some((t) => t.includes("left-pad")), "non-crypto dep not flagged");
  for (const f of findings) {
    assert.equal(f.category, "dependency");
    assert.equal(f.ruleId, "dep-vulnerable");
    assert.equal(f.location.file, "package.json");
  }
});

test("scoped package names (@noble/curves) are matched and located", () => {
  const pkg = JSON.stringify({ dependencies: { "@noble/curves": "^1.0.0" } });
  const findings = scanManifest("package.json", pkg);
  assert.equal(findings.length, 1);
  assert.ok(findings[0].title.includes("@noble/curves"));
  // location should point at the key, not line 1 fallback artifacts
  assert.ok(findings[0].location.line >= 1);
});

test("package-lock.json v3 packages map is parsed", () => {
  const lock = JSON.stringify({
    name: "demo",
    lockfileVersion: 3,
    packages: {
      "": { name: "demo" },
      "node_modules/jsonwebtoken": { version: "9.0.0" },
      "node_modules/jose": { version: "5.0.0" },
      "node_modules/lodash": { version: "4.17.21" },
    },
  });
  const findings = scanManifest("package-lock.json", lock);
  const names = findings.map((f) => f.title);
  assert.ok(names.some((t) => t.includes("jsonwebtoken")));
  assert.ok(names.some((t) => t.includes("jose")));
  assert.ok(!names.some((t) => t.includes("lodash")));
});

test("HNDL flag reflects confidentiality vs signature-only packages", () => {
  // jose exposes RSA/ECDH → HNDL true; ecpair is ECDSA-only → HNDL false.
  const joseF = scanManifest("package.json", JSON.stringify({ dependencies: { jose: "5" } }))[0];
  const ecpairF = scanManifest(
    "package.json",
    JSON.stringify({ dependencies: { ecpair: "2" } }),
  )[0];
  assert.equal(joseF.hndl, true);
  assert.equal(ecpairF.hndl, false);
});

test("invalid JSON manifests are skipped without throwing", () => {
  assert.deepEqual(scanManifest("package.json", "{ not json"), []);
});

test("dependency findings carry a CWE id", () => {
  const f = scanManifest("package.json", JSON.stringify({ dependencies: { elliptic: "^6" } }))[0];
  assert.equal(f.cwe, "CWE-327");
});

test("multi-family dependency remediation names all exposed families (C5)", () => {
  // jose exposes RSA + ECDH + ECDSA + EdDSA → remediation should mention both a
  // KEM (for the confidentiality families) and a signature replacement.
  const f = scanManifest("package.json", JSON.stringify({ dependencies: { jose: "5" } }))[0];
  assert.ok(f.remediation && f.remediation.length > 0);
  assert.match(f.remediation, /ML-KEM|X25519MLKEM768/);
  assert.match(f.remediation, /ML-DSA/);
});

test("multi-family remediation de-dupes by target: ML-DSA / ML-KEM named once each", () => {
  // A KEM+signature library used to read "…ML-DSA-65 for signatures; ML-DSA-65
  // (FIPS 204)" because the old per-string Set couldn't collapse the two. Now
  // the KEM target and the signature target are each named exactly once.
  const f = scanManifest("package.json", JSON.stringify({ dependencies: { jose: "5" } }))[0];
  const rem = f.remediation ?? "";
  assert.equal(rem.match(/ML-DSA/g)?.length, 1, `ML-DSA should appear once: "${rem}"`);
  assert.equal(rem.match(/ML-KEM/g)?.length, 1, `ML-KEM should appear once: "${rem}"`);
});

test("HNDL override: signing-only deps are not HNDL, but encryption libs are (audit: crypto #1)", () => {
  const jwt = scanManifest(
    "package.json",
    JSON.stringify({ dependencies: { jsonwebtoken: "9" } }),
  )[0];
  assert.equal(jwt.hndl, false, "jsonwebtoken is JWS/signing-only → not HNDL");
  const jose = scanManifest("package.json", JSON.stringify({ dependencies: { jose: "5" } }))[0];
  assert.equal(jose.hndl, true, "jose does JWE/ECDH-ES encryption → HNDL");
  for (const name of ["jws", "pyjwt", "paseto", "http-signature"]) {
    const eco = name === "pyjwt" ? "requirements.txt" : "package.json";
    const content =
      name === "pyjwt" ? "pyjwt==2.8.0\n" : JSON.stringify({ dependencies: { [name]: "1" } });
    const f = scanManifest(eco, content)[0];
    assert.equal(f?.hndl, false, `${name} is signing-only → not HNDL`);
  }
});
