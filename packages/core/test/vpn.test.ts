/**
 * Tests for network transport / VPN key-exchange detection (WireGuard, IPsec, sshd).
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

const WG_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

test("WireGuard Curve25519 key is flagged (no PQC option), snippet redacted", () => {
  const conf = `[Interface]\nPrivateKey = ${WG_KEY}\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = ${WG_KEY}\n`;
  const f = rule(run("wg0.conf", conf), "net-wireguard-x25519");
  assert.equal(f?.algorithm, "X25519");
  assert.equal(f?.hndl, true);
  // Marked sensitive so the reporters drop the private-key snippet.
  assert.equal(f?.sensitive, true);
});

test("IPsec classical DH groups (modp / ecp) are flagged", () => {
  const conf =
    "conn tunnel\n  keyexchange=ikev2\n  ike=aes256-sha256-modp2048\n  esp=aes256-sha256-ecp256\n";
  const fs = run("ipsec.conf", conf);
  assert.equal(rule(fs, "net-ipsec-modp-dh")?.algorithm, "DH");
  assert.equal(rule(fs, "net-ipsec-ecp-ecdh")?.algorithm, "ECDH");
});

test("sshd_config with only classical KexAlgorithms is flagged", () => {
  assert.ok(
    rule(
      run("sshd_config", "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n"),
      "net-sshd-classical-kex",
    ),
  );
});

test("sshd_config that DOES offer a PQC hybrid KEX stays silent", () => {
  const conf = "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256\n";
  assert.deepEqual(
    run("sshd_config", conf).filter((f) => f.ruleId.startsWith("net-")),
    [],
  );
});

test("gating: modp in a non-IPsec .conf, and WireGuard keys with no section, do not fire", () => {
  // A .conf that mentions modp2048 but has no ike=/esp= proposal marker.
  assert.deepEqual(
    run("app.conf", "cache_size = 2048\nnote = modp2048 is a group\n").filter((f) =>
      f.ruleId.startsWith("net-"),
    ),
    [],
  );
  // WireGuard-looking key but no [Interface]/[Peer] section.
  assert.deepEqual(
    run("random.conf", `token = ${WG_KEY}\n`).filter((f) => f.ruleId.startsWith("net-")),
    [],
  );
  // A non-config extension isn't scanned by this detector at all.
  assert.deepEqual(
    run("notes.txt", `[Interface]\nPrivateKey = ${WG_KEY}\n`).filter((f) =>
      f.ruleId.startsWith("net-"),
    ),
    [],
  );
});
