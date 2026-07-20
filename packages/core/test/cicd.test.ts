/**
 * Tests for CI/CD signing detection — classical artifact/code signatures in
 * pipeline definitions, forgeable once a CRQC exists.
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

test("cosign signing in a GitHub Actions workflow is flagged as ECDSA (signature, not HNDL)", () => {
  const f = rule(
    run(".github/workflows/release.yml", "      - run: cosign sign --key cosign.key $IMAGE\n"),
    "ci-cosign-ecdsa",
  );
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("cosign sign-blob subcommand is covered", () => {
  const f = rule(
    run(".github/workflows/release.yml", "      - run: cosign sign-blob --key k artifact.tar\n"),
    "ci-cosign-ecdsa",
  );
  assert.ok(f, "sign-blob is flagged as classical signing");
});

test("gpg --detach-sign is flagged as RSA signing", () => {
  const f = rule(
    run(".gitlab-ci.yml", "  script:\n    - gpg --detach-sign --armor dist/app.tar.gz\n"),
    "ci-gpg-sign",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, false);
});

test("gpg short sign flags (-s / -b) are flagged", () => {
  assert.ok(rule(run(".github/workflows/r.yml", "run: gpg -s dist/app.tar\n"), "ci-gpg-sign"));
  assert.ok(rule(run(".github/workflows/r.yml", "run: gpg -b dist/app.tar\n"), "ci-gpg-sign"));
});

test("jarsigner, codesign and minisign are detected", () => {
  assert.ok(
    rule(run("Jenkinsfile", "sh 'jarsigner -keystore ks.jks app.jar alias'"), "ci-jarsigner"),
  );
  assert.ok(
    rule(
      run(".github/workflows/mac.yml", "run: codesign --sign 'Dev ID' MyApp.app"),
      "ci-codesign",
    ),
  );
  assert.ok(rule(run(".github/workflows/rel.yml", "run: minisign -Sm dist/app"), "ci-minisign"));
});

test("CI signing detector is gated to pipeline files (not arbitrary scripts/docs)", () => {
  // Same command in a shell script or README must not fire this detector.
  assert.deepEqual(
    run("scripts/build.sh", "cosign sign --key k image").filter((f) => f.ruleId.startsWith("ci-")),
    [],
  );
  assert.deepEqual(
    run("README.md", "We sign releases with gpg --detach-sign.").filter((f) =>
      f.ruleId.startsWith("ci-"),
    ),
    [],
  );
});

test("a clean workflow with no signing produces no ci- findings", () => {
  const clean = "jobs:\n  build:\n    steps:\n      - run: npm ci && npm test\n";
  assert.deepEqual(
    run(".github/workflows/ci.yml", clean).filter((f) => f.ruleId.startsWith("ci-")),
    [],
  );
});

test("a COMMENTED-OUT signing step is NOT flagged", () => {
  assert.deepEqual(
    run(".github/workflows/rel.yml", "      # - run: cosign sign --key k $IMAGE\n").filter((f) =>
      f.ruleId.startsWith("ci-"),
    ),
    [],
  );
  // An active step with a trailing comment still fires.
  assert.ok(
    rule(
      run(".github/workflows/rel.yml", "      - run: cosign sign # release\n"),
      "ci-cosign-ecdsa",
    ),
  );
});

test("codesign with flags between the command and --sign is flagged", () => {
  assert.ok(
    rule(
      run(
        ".github/workflows/mac.yml",
        'run: codesign --force --options runtime --sign "Dev ID" App.app',
      ),
      "ci-codesign",
    ),
    "codesign --force … --sign must fire",
  );
});

test("gpg that only decrypts and a later tool's --sign-artifacts does NOT fire ci-gpg-sign", () => {
  assert.equal(
    rule(
      run(".gitlab-ci.yml", "  script:\n    - gpg --decrypt s.gpg && deploy --sign-artifacts\n"),
      "ci-gpg-sign",
    ),
    undefined,
  );
});
