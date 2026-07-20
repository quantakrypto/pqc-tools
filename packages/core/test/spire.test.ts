/**
 * Tests for SPIRE / SPIFFE classical SVID key-type detection — the key types
 * configured for X.509-SVID certificates in SPIRE server/agent config (HCL and
 * its YAML/JSON templated forms), a surface none of the IaC or language-pack
 * detectors see. The detector is imported directly so the test is independent
 * of registry wiring.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { spireDetector } from "../src/detectors/spire.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  return spireDetector.appliesTo(file) ? spireDetector.detect({ file, content }) : [];
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("SPIRE server ca_key_type = rsa-2048 classifies as RSA, certificate, hndl:false", () => {
  const content = [
    "server {",
    '    trust_domain = "example.org"',
    '    ca_key_type = "rsa-2048"',
    "}",
  ].join("\n");
  const f = rule(run("server.conf", content), "spire-rsa-key");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "certificate");
  assert.equal(f?.severity, "medium");
  assert.equal(f?.confidence, "high");
  assert.equal(f?.hndl, false);
});

test("SPIRE server ca_key_type = ec-p384 classifies as ECDSA, certificate, hndl:false", () => {
  const content = [
    "server {",
    '    trust_domain = "example.org"',
    '    ca_key_type = "ec-p384"',
    "}",
  ].join("\n");
  const f = rule(run("server.conf", content), "spire-ec-key");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "certificate");
  assert.equal(f?.hndl, false);
});

test("per-plugin key_type = ec-p256 (with a spire marker) classifies as ECDSA", () => {
  // The bare per-plugin `key_type` is generic; the `spire`/`spiffe` marker in
  // the surrounding UpstreamAuthority config is what makes it fire here.
  const content = [
    'UpstreamAuthority "disk" {',
    "    plugin_data {",
    '        key_type = "ec-p256"',
    '        cert_file_path = "/opt/spire/conf/upstream_ca.crt"',
    "    }",
    "}",
  ].join("\n");
  const f = rule(run("upstream.conf", content), "spire-ec-key");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.hndl, false);
});

test("agent svid_key_type = rsa-2048 (YAML `:` form) classifies as RSA", () => {
  const content = ["spiffe:", "  agent:", '    svid_key_type: "rsa-2048"'].join("\n");
  const f = rule(run("values.yaml", content), "spire-rsa-key");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, false);
});

test("bare key_type = rsa-2048 with NO spiffe/spire marker does NOT fire", () => {
  // Same attribute, unrelated file (no spiffe/spire/svid/ca_key_type anywhere):
  // the generic `key_type` must not be enough to trigger the SPIRE detector.
  const content = ["backend {", '    key_type = "rsa-2048"', "}"].join("\n");
  assert.deepEqual(run("backend.conf", content), []);
});

test("prose .md describing SPIRE ca_key_type is documentation, not config", () => {
  const prose = [
    "## Configuring the SPIRE CA",
    "",
    'Set `ca_key_type = "rsa-4096"` in the server block for a stronger CA key.',
  ].join("\n");
  assert.deepEqual(run("docs/spire-setup.md", prose), []);
});

test("a COMMENTED-OUT ca_key_type line does NOT fire (comment masking)", () => {
  const content = [
    "server {",
    '    trust_domain = "example.org"',
    '    # ca_key_type = "rsa-2048"',
    '    ca_key_type = "ec-p256"',
    "}",
  ].join("\n");
  const findings = run("server.conf", content);
  // The commented RSA line is masked; only the live ECDSA line fires.
  assert.equal(rule(findings, "spire-rsa-key"), undefined);
  assert.equal(rule(findings, "spire-ec-key")?.algorithm, "ECDSA");
});
