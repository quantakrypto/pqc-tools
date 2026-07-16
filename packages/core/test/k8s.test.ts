/**
 * Tests for Kubernetes crypto detection — cert-manager key algorithms and Istio
 * mesh TLS floors, gated so generic YAML `algorithm:` keys don't fire.
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

const CERT = `apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  privateKey:
    algorithm: ECDSA
    size: 256
`;

test("cert-manager ECDSA privateKey algorithm is flagged", () => {
  const f = rule(run("cert.yaml", CERT), "k8s-certmanager-ecdsa");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "certificate");
  assert.equal(f?.hndl, false);
});

test("cert-manager RSA key is flagged as HNDL", () => {
  const y = "kind: Issuer\napiVersion: cert-manager.io/v1\nspec:\n  privateKey:\n    algorithm: RSA\n";
  const f = rule(run("issuer.yaml", y), "k8s-certmanager-rsa");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, true);
});

test("Istio legacy TLS floor is flagged", () => {
  const y = "kind: DestinationRule\nspec:\n  trafficPolicy:\n    tls:\n      minProtocolVersion: TLSV1_0\n";
  assert.ok(rule(run("dr.yaml", y), "k8s-istio-legacy-tls"));
});

test("generic YAML with algorithm: RSA but no cert-manager/Istio marker does NOT fire", () => {
  // A random config that happens to say `algorithm: RSA` must not be flagged.
  const y = "myapp:\n  algorithm: RSA\n  note: not kubernetes crypto\n";
  assert.deepEqual(
    run("app-config.yaml", y).filter((f) => f.ruleId.startsWith("k8s-")),
    [],
  );
});
