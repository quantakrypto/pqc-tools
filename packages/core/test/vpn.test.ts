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

test("sshd_config KexAlgorithms is NOT handled by vpn (source.ts's ssh-kex-classical owns it)", () => {
  // The vpn detector intentionally emits no `net-` finding for sshd_config; the
  // language-agnostic ssh-kex token detector in source.ts covers it (avoids a
  // double-count).
  assert.deepEqual(
    run("sshd_config", "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n").filter((f) =>
      f.ruleId.startsWith("net-"),
    ),
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

test("a COMMENTED-OUT ipsec proposal / disabled-group note is NOT flagged", () => {
  const conf =
    "conn tunnel\n  keyexchange=ikev2\n  ike=aes256-sha256-ecp384\n  # esp=aes256-modp1024 (disabled)\n";
  const fs = run("ipsec.conf", conf);
  // The active ecp384 line still fires; the commented modp1024 must not.
  assert.ok(rule(fs, "net-ipsec-ecp-ecdh"), "active ecp384 fires");
  assert.equal(rule(fs, "net-ipsec-modp-dh"), undefined, "commented modp1024 does not fire");
});
