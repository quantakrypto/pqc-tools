/**
 * Tests for SSH certificate-authority (SSH-CA) detection — the OpenSSH
 * certificate mechanism where a CA key signs host/user certificates
 * (`*-cert-v01@openssh.com`). Distinct from SSH key-exchange (`ssh-kex-classical`)
 * and from bare-public-key detection (`ssh-public-key`): this is the certificate
 * SIGNATURE / trust-root surface, `category: "signature"`, `hndl: false`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { sshCaDetector } from "../src/detectors/ssh-ca.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  return sshCaDetector.appliesTo(file) ? sshCaDetector.detect({ file, content }) : [];
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("@cert-authority known_hosts line with ssh-rsa-cert-v01 classifies as RSA, signature, hndl:false", () => {
  const content =
    "@cert-authority *.example.com ssh-rsa-cert-v01@openssh.com AAAAB3NzaC1yc2EAAAADAQABAAABgQC";
  const f = rule(run("known_hosts", content), "ssh-ca-rsa-cert");
  assert.ok(f, "expected an ssh-ca-rsa-cert finding");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  assert.equal(f?.severity, "medium");
  assert.equal(f?.confidence, "high");
});

test("rsa-sha2-256 certificate type classifies as RSA", () => {
  const content =
    "@cert-authority host.example.com rsa-sha2-256-cert-v01@openssh.com AAAAB3NzaC1yc2E";
  const f = rule(run("known_hosts", content), "ssh-ca-rsa-cert");
  assert.equal(f?.algorithm, "RSA");
});

test("ecdsa-sha2-nistp256-cert-v01 classifies as ECDSA, signature, hndl:false", () => {
  const content = [
    "HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub",
    "# host cert type: ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAE2VjZHNh",
    "@cert-authority *.corp.example ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAE2VjZHNh",
  ].join("\n");
  const f = rule(run("ssh_known_hosts", content), "ssh-ca-ecdsa-cert");
  assert.ok(f, "expected an ssh-ca-ecdsa-cert finding");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("ssh-ed25519-cert-v01 classifies as EdDSA, signature, hndl:false", () => {
  const content =
    "@cert-authority *.example.net ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5";
  const f = rule(run("known_hosts", content), "ssh-ca-ed25519-cert");
  assert.ok(f, "expected an ssh-ca-ed25519-cert finding");
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("plain ssh-ed25519 public key WITHOUT -cert-v01 does NOT fire the CA rule", () => {
  // A normal authorized_keys / known_hosts public key — no certificate involved.
  // (There's no SSH-CA marker either, so the fast-reject also bails.)
  const content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0 user@host";
  assert.equal(run("authorized_keys", content).length, 0);
});

test("a plain public key ALONGSIDE a CA marker still does not fire a CA rule", () => {
  // Marker present (so detect() runs), but the ed25519 line itself is not a cert.
  const content = [
    "TrustedUserCAKeys /etc/ssh/ca.pub",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0 user@host",
  ].join("\n");
  assert.equal(run("sshd_config", content).length, 0);
});

test("prose .md file never fires, even with a cert token", () => {
  const content =
    "Configure the CA with `ssh-ed25519-cert-v01@openssh.com` and `@cert-authority` lines.";
  assert.equal(run("README.md", content).length, 0);
});

test("commented-out (#) cert line does not fire", () => {
  const content = "#@cert-authority *.example.com ssh-rsa-cert-v01@openssh.com AAAAB3NzaC1yc2E";
  assert.equal(run("known_hosts", content).length, 0);
});

test("file with no SSH-CA marker yields no findings", () => {
  const content = ["Host example.com", "  User deploy", "  Port 22"].join("\n");
  assert.equal(run("config", content).length, 0);
});

test("marked sensitive so reporters drop the key-bearing snippet", () => {
  const content =
    "@cert-authority *.example.com ssh-rsa-cert-v01@openssh.com AAAAB3NzaC1yc2EAAAADAQAB";
  const f = rule(run("known_hosts", content), "ssh-ca-rsa-cert");
  assert.equal(f?.sensitive, true);
});
