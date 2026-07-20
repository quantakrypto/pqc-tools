/**
 * Tests for the Pulumi tls-provider IaC detector.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectFile, detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function scan1(file: string, content: string): Finding[] {
  return detectFile(file, content, detectors, { source: true, config: true, deps: true });
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("Pulumi TS tls.PrivateKey RSA is flagged (kem, HNDL)", () => {
  const src = [
    'import * as tls from "@pulumi/tls";',
    'const key = new tls.PrivateKey("k", { algorithm: "RSA", rsaBits: 2048 });',
  ].join("\n");
  const f = rule(run("index.ts", src), "pulumi-tls-rsa");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, true);
});

test("Pulumi Python tls.PrivateKey ECDSA is flagged (signature)", () => {
  const src = ["import pulumi_tls as tls", 'k = tls.PrivateKey("k", algorithm="ECDSA")'].join("\n");
  const f = rule(run("__main__.py", src), "pulumi-tls-ecdsa");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.hndl, false);
});

test("Pulumi Go tls.NewPrivateKey ED25519 is flagged (EdDSA)", () => {
  const src = [
    'import "github.com/pulumi/pulumi-tls/sdk/v4/go/tls"',
    'tls.NewPrivateKey(ctx, "k", &tls.PrivateKeyArgs{ Algorithm: pulumi.String("ED25519") })',
  ].join("\n");
  const f = rule(run("main.go", src), "pulumi-tls-ed25519");
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.hndl, false);
});

test("an `algorithm` field in a non-pulumi-tls file does not fire", () => {
  // No pulumi-tls marker → the generic algorithm value must not fire.
  assert.deepEqual(
    run("config.ts", 'const jwtOpts = { algorithm: "RSA" };').filter((f) =>
      f.ruleId.startsWith("pulumi-"),
    ),
    [],
  );
});

test("commented-out Pulumi tls.PrivateKey is suppressed", () => {
  const src = [
    'import * as tls from "@pulumi/tls";',
    '// const key = new tls.PrivateKey("k", { algorithm: "RSA" });',
  ].join("\n");
  assert.equal(rule(scan1("index.ts", src), "pulumi-tls-rsa"), undefined);
});
