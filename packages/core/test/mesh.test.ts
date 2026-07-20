/**
 * Tests for service-mesh crypto detection — Linkerd's default ECDSA identity
 * issuer, Consul Connect's mesh CA private key type, and classical ECDHE
 * cipher suites in Istio DestinationRule/Gateway TLS policy. A surface neither
 * the language packs, the Terraform detector, nor `k8s.ts` (cert-manager /
 * Istio TLS floor) see.
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

test("Linkerd default identity issuer scheme (linkerd.io/tls) classifies as ECDSA", () => {
  const values = [
    "identity:",
    "  issuer:",
    "    scheme: linkerd.io/tls",
    "    tls:",
    "      crtPEM: |",
    "        -----BEGIN CERTIFICATE-----",
  ].join("\n");
  const found = rule(run("linkerd-values.yaml", values), "mesh-linkerd-identity-ecdsa");
  assert.equal(found?.algorithm, "ECDSA");
  assert.equal(found?.hndl, false);
});

test("Linkerd identityTrustAnchorsPEM Helm key is caught", () => {
  const values = [
    "# linkerd control-plane trust anchors",
    "identityTrustAnchorsPEM: |",
    "  -----BEGIN CERTIFICATE-----",
  ].join("\n");
  assert.ok(rule(run("values.yaml", values), "mesh-linkerd-identity-ecdsa"));
});

test("Consul Connect ca_config private_key_type ec/rsa classify correctly", () => {
  const ec = [
    "connect {",
    "  enabled = true",
    '  ca_provider = "consul"',
    "  ca_config {",
    '    private_key_type = "ec"',
    "    private_key_bits = 256",
    '    leaf_cert_ttl = "72h"',
    "  }",
    "}",
  ].join("\n");
  const foundEc = rule(run("consul-connect.hcl", ec), "mesh-consul-connect-ec");
  assert.equal(foundEc?.algorithm, "ECDSA");
  assert.equal(foundEc?.hndl, false);

  const rsa = [
    "connect {",
    "  enabled = true",
    '  ca_provider = "consul"',
    "  ca_config {",
    '    private_key_type = "rsa"',
    "    private_key_bits = 2048",
    "  }",
    "}",
  ].join("\n");
  const foundRsa = rule(run("consul-connect.hcl", rsa), "mesh-consul-connect-rsa");
  assert.equal(foundRsa?.algorithm, "RSA");
  assert.equal(foundRsa?.hndl, true);
});

test("Istio DestinationRule cipherSuites (ECDHE-RSA/ECDHE-ECDSA) are flagged by source's tls-classical-kex, not duplicated by mesh", () => {
  const manifest = [
    "apiVersion: networking.istio.io/v1beta1",
    "kind: DestinationRule",
    "metadata:",
    "  name: legacy-tls",
    "spec:",
    "  trafficPolicy:",
    "    tls:",
    "      mode: SIMPLE",
    "      cipherSuites:",
    "      - ECDHE-RSA-AES256-GCM-SHA384",
    "      - ECDHE-ECDSA-AES128-GCM-SHA256",
  ].join("\n");
  // mesh no longer emits a cipher rule (source.ts's tls-classical-kex owns the token).
  assert.deepEqual(
    run("dr.yaml", manifest).filter((f) => f.ruleId === "mesh-istio-classical-cipher"),
    [],
  );
  const kex = run("dr.yaml", manifest).filter((f) => f.ruleId === "tls-classical-kex");
  assert.equal(kex.length, 2, "both ECDHE suites flagged once each");
  assert.equal(kex[0]?.hndl, true);
});

test("gating: mesh markers require the mesh detector's fast-reject tokens, not just any keyword", () => {
  // A cipher-suite-looking token in prose, without "cipherSuites" or
  // "DestinationRule" in the document, must not fire the Istio rule.
  const prose = [
    "notes: |",
    "  Our recommended cipher list includes ECDHE-RSA-AES256-GCM-SHA384 for legacy clients.",
  ].join("\n");
  assert.deepEqual(
    run("notes.yaml", prose).filter((f) => f.ruleId.startsWith("mesh-")),
    [],
  );

  // A bare private_key_type without "consul" AND "connect" in the document
  // must not fire the Consul rule either.
  const bare = 'private_key_type = "ec"';
  assert.deepEqual(
    run("bare.hcl", bare).filter((f) => f.ruleId.startsWith("mesh-")),
    [],
  );
});

test("mesh detector is gated to config extensions (not arbitrary files)", () => {
  const values = "identityTrustAnchorsPEM: |\n  -----BEGIN CERTIFICATE-----";
  assert.deepEqual(
    run("notes.txt", values).filter((f) => f.ruleId.startsWith("mesh-")),
    [],
  );
});

test("Consul agent config in JSON is scanned (private_key_type)", () => {
  // Consul agent config is commonly JSON; the `.json` extension is a mesh surface.
  const cfg =
    '{"data_dir":"/opt/consul","connect":{"ca_config":{"private_key_type":"rsa"}},"datacenter":"dc1"}';
  const f = run("consul.json", cfg).find((x) => x.ruleId === "mesh-consul-connect-rsa");
  assert.ok(f, "Consul Connect RSA CA in JSON is detected");
});

test("clean mesh config (TLS 1.3-only cipher suite, no classical CA settings) produces no findings", () => {
  const manifest = [
    "apiVersion: networking.istio.io/v1beta1",
    "kind: DestinationRule",
    "spec:",
    "  trafficPolicy:",
    "    tls:",
    "      cipherSuites:",
    "      - TLS_AES_256_GCM_SHA384",
  ].join("\n");
  assert.deepEqual(
    run("dr-clean.yaml", manifest).filter((f) => f.ruleId.startsWith("mesh-")),
    [],
  );
});
