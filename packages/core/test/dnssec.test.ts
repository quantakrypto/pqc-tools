/**
 * Tests for DNSSEC classical signing-algorithm detection — zone files and
 * signer/resolver config (BIND, Knot DNS, `ldns-signzone`), a surface none of
 * the IaC or language-pack detectors see.
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

test("Knot DNS policy algorithm RSASHA256 classifies as RSA, signature, hndl:false", () => {
  const content = [
    "zone:",
    "  - domain: example.com",
    "    dnssec-signing: on",
    "    dnssec-policy: default",
    "",
    "policy:",
    "  - id: default",
    "    algorithm: RSASHA256",
    "    ksk-size: 2048",
  ].join("\n");
  const f = rule(run("knot.conf", content), "dnssec-rsa-sig");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("BIND dnssec-policy algorithm ECDSAP256SHA256 classifies as ECDSA", () => {
  const content = [
    'dnssec-policy "mypolicy" {',
    "  keys {",
    "    csk lifetime unlimited algorithm ECDSAP256SHA256;",
    "  };",
    "};",
  ].join("\n");
  const f = rule(run("named.conf", content), "dnssec-ecdsa-sig");
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.hndl, false);
});

test("ldns-signzone -a ED25519 in ops config classifies as EdDSA", () => {
  const content = [
    "# Re-sign the zone after every edit:",
    "# ldns-signzone -a ED25519 -k Kexample.com.+015+12345 example.com.zone",
  ].join("\n");
  const f = rule(run("signer.conf", content), "dnssec-eddsa-sig");
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.hndl, false);
});

test("bare `algorithm DSA;` (Knot legacy policy) classifies as DSA (deprecated)", () => {
  const content = [
    "policy:",
    "  - id: legacy",
    "    algorithm DSA;",
    "    dnssec-signing: on",
  ].join("\n");
  const f = rule(run("legacy.conf", content), "dnssec-dsa-sig");
  assert.equal(f?.algorithm, "DSA");
  assert.equal(f?.hndl, false);
});

test("structural DNSKEY RDATA (flags 3 <alg>) is caught without any named token present", () => {
  // Algorithm number 13 = ECDSAP256SHA256, but the mnemonic never appears —
  // only the raw presentation-format RDATA, as a zone-file dump would show.
  const content =
    "example.com.\t3600\tIN\tDNSKEY\t257 3 13 AwEAAdRe7Q0M8OJZzEyf4WhBhkfyaGKzbe/juzYAoEPnRZbj\n";
  const f = rule(run("example.com.zone", content), "dnssec-ecdsa-sig");
  assert.equal(f?.algorithm, "ECDSA");
});

test("DNSSEC detector is gated to .zone/.db/.conf (a .md mentioning the algorithm name is prose, not config)", () => {
  const prose =
    "## Choosing a DNSSEC algorithm\n\nWe recommend ECDSAP256SHA256 over RSASHA256 for smaller signatures.";
  assert.deepEqual(
    run("docs/dnssec-guide.md", prose).filter((f) => f.ruleId.startsWith("dnssec-")),
    [],
  );
});

test("clean zone file with no DNSSEC records produces no findings", () => {
  const clean = [
    "$TTL 3600",
    "example.com.  IN  SOA  ns1.example.com. hostmaster.example.com. 2026071601 3600 900 604800 3600",
    "example.com.  IN  NS   ns1.example.com.",
    "example.com.  IN  A    203.0.113.10",
    "www           IN  A    203.0.113.11",
  ].join("\n");
  assert.deepEqual(
    run("example.com.zone", clean).filter((f) => f.ruleId.startsWith("dnssec-")),
    [],
  );
});

test("ED25519/DSA mentioned outside any DNSSEC context (no marker) does not fire", () => {
  // An SSH-adjacent .conf that happens to name ED25519 and DSA for unrelated
  // reasons, with no DNSKEY/RRSIG/dnssec/ldns-signzone marker anywhere.
  const content = [
    "# host key preferences (unrelated to DNS)",
    "HostKeyAlgorithms ssh-ed25519,ED25519",
    "PubkeyAcceptedKeyTypes ssh-dsa,DSA",
  ].join("\n");
  assert.deepEqual(
    run("host.conf", content).filter((f) => f.ruleId.startsWith("dnssec-")),
    [],
  );
});
