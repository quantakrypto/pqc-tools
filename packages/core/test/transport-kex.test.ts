/**
 * Tests for the language-agnostic transport key-exchange token rules
 * (ssh-kex-classical / tls-classical-kex) in source.ts, focused on the
 * documentation-field guard: an algorithm name LISTED in a `description` / `help`
 * field is prose, not an active setting, and must not fire.
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
const has = (findings: Finding[], ruleId: string): boolean =>
  findings.some((f) => f.ruleId === ruleId);

test("real KexAlgorithms config still fires ssh-kex-classical", () => {
  assert.equal(
    has(
      run("sshd_config", "KexAlgorithms ecdh-sha2-nistp256,diffie-hellman-group14-sha1\n"),
      "ssh-kex-classical",
    ),
    true,
  );
});

test("classical KEX names inside a Terraform/Packer description string do NOT fire", () => {
  // Regression (real-world FP: terraform-aws-eks packer HCL). A variable description
  // listing the acceptable algorithm values is documentation, not configuration.
  const hcl = [
    'variable "ssh_key_exchange_algorithms" {',
    '  description = "Acceptable values include: curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, diffie-hellman-group14-sha1, and diffie-hellman-group1-sha1"',
    "  type = list(string)",
    "}",
  ].join("\n");
  assert.equal(has(run("variables.pkr.hcl", hcl), "ssh-kex-classical"), false);
});

test("real ECDHE cipher list still fires tls-classical-kex", () => {
  assert.equal(
    has(run("nginx.conf", "ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"), "tls-classical-kex"),
    true,
  );
});

test("ECDHE suite names inside a description field do NOT fire tls-classical-kex", () => {
  const hcl =
    '  description = "Cipher suites, e.g. ECDHE-RSA-AES128-GCM-SHA256 or TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"';
  assert.equal(has(run("vars.tf", hcl), "tls-classical-kex"), false);
});
