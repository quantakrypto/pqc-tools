/**
 * Config detector: classical DNSSEC signing algorithms in zone files and
 * signer/resolver config (BIND, Knot DNS, PowerDNS, `ldns-signzone` /
 * `dnssec-signzone` invocations recorded in ops config).
 *
 * DNSSEC is "communication between things" infrastructure: resolvers verify
 * DNSKEY/RRSIG chains to authenticate zone data. Unlike a KEM or key-exchange
 * finding, a DNSSEC signing key is not harvest-now-decrypt-later exposed —
 * there is no confidentiality to harvest — but every classical signature it
 * produces becomes FORGEABLE the moment a cryptographically-relevant quantum
 * computer (CRQC) exists. A forged DNSKEY/RRSIG chain lets an attacker spoof
 * DNSSEC-validated records (cache poisoning that a validating resolver would
 * otherwise reject). So these findings are `category: "signature"`,
 * `hndl: false`.
 *
 * RFC 8624 / IANA "DNSSEC Algorithm Numbers" families covered, mapped to
 * {@link AlgorithmFamily}:
 *  - RSASHA1 (5), RSASHA1-NSEC3-SHA1 (7), RSASHA256 (8), RSASHA512 (10) → RSA
 *  - ECDSAP256SHA256 (13), ECDSAP384SHA384 (14)                        → ECDSA
 *  - ED25519 (15), ED448 (16)                                          → EdDSA
 *  - DSA (3), DSA-NSEC3-SHA1 (6)                                      → DSA
 *
 * Two independent match shapes per family, both gated to `.zone` / `.db` /
 * `.conf` files AND to a file-level DNSSEC marker (see `hasDnssecMarker`
 * below) so the algorithm tokens can't fire on unrelated config:
 *
 *  1. NAMED form — the algorithm's mnemonic name, as written in signer/policy
 *     config (Knot `algorithm RSASHA256;`, a `dnssec-policy` block, BIND
 *     `algorithm: ecdsap256sha256;`) or on an `ldns-signzone -a ECDSAP256SHA256`
 *     / `dnssec-signzone -a ECDSAP256SHA256` command line. These mnemonics
 *     (`RSASHA256`, `ECDSAP384SHA384`, `ED25519`, …) are distinctive enough to
 *     match bare, EXCEPT plain `DSA`, which is too generic a token on its own
 *     (used well outside DNSSEC); that one is only matched immediately after
 *     an `algorithm` keyword.
 *  2. STRUCTURAL form — the DNSKEY presentation-format RDATA, e.g.
 *     `example.com. IN DNSKEY 257 3 8 AwEAAd...`, where the fields after the
 *     `DNSKEY` keyword are `flags protocol algorithm public-key` (RFC 4034
 *     §2). Anchoring on the literal `DNSKEY` keyword AND the literal
 *     protocol value `3` (always 3 for DNSSEC) before a restricted algorithm
 *     number keeps this precise despite being numeric. Bare algorithm
 *     numbers with no such anchor are deliberately NOT matched anywhere —
 *     `algorithm 8;` alone is far too ambiguous to key off of.
 *
 * Fast reject: `detect()` bails unless the file contains `DNSKEY`, `RRSIG`,
 * a case-insensitive `dnssec` substring (present in `dnssec-policy`,
 * `dnssec-signing: on`, etc. in any real signer config), or an
 * `ldns-signzone` / `dnssec-signzone` invocation. This stops the DSA/EdDSA
 * named-form tokens — which are individually generic outside DNSSEC — from
 * firing on, say, an unrelated SSH or TLS `.conf` file that happens to
 * mention `ED25519` or `DSA` for its own reasons.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const DNSSEC_EXTENSIONS: readonly string[] = [".zone", ".db", ".conf"];

// IANA DNSSEC algorithm numbers, grouped by family.
const NUM_RSA = "5|7|8|10"; // RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512
const NUM_ECDSA = "13|14"; // ECDSAP256SHA256, ECDSAP384SHA384
const NUM_EDDSA = "15|16"; // ED25519, ED448
const NUM_DSA = "3|6"; // DSA, DSA-NSEC3-SHA1

// --- NAMED form: mnemonic algorithm names in signer/policy config or CLI args. ---
const RE_NAMED_RSA = /\bRSASHA(?:256|512|1(?:-NSEC3-SHA1)?)\b/g;
const RE_NAMED_ECDSA = /\bECDSAP(?:256SHA256|384SHA384)\b/g;
const RE_NAMED_EDDSA = /\bED(?:25519|448)\b/g;
// Bare "DSA" is too generic to key off alone; require it right after an
// `algorithm` keyword (Knot/BIND config / dnssec-policy style), optionally
// quoted or separated by `:`/`=`.
const RE_NAMED_DSA = /\balgorithm\s*[:=]?\s*"?DSA(?:-NSEC3-SHA1)?"?\b/gi;

// --- STRUCTURAL form: `DNSKEY <flags> 3 <algorithm>` presentation RDATA (RFC 4034 §2). ---
const RE_DNSKEY_RSA = new RegExp(`\\bDNSKEY\\s+\\d+\\s+3\\s+(?:${NUM_RSA})\\b`, "g");
const RE_DNSKEY_ECDSA = new RegExp(`\\bDNSKEY\\s+\\d+\\s+3\\s+(?:${NUM_ECDSA})\\b`, "g");
const RE_DNSKEY_EDDSA = new RegExp(`\\bDNSKEY\\s+\\d+\\s+3\\s+(?:${NUM_EDDSA})\\b`, "g");
const RE_DNSKEY_DSA = new RegExp(`\\bDNSKEY\\s+\\d+\\s+3\\s+(?:${NUM_DSA})\\b`, "g");

const RULE_DNSSEC_RSA: RuleMeta = {
  id: "dnssec-rsa-sig",
  title: "DNSSEC RSA signing algorithm",
  description: "DNSSEC zone signed with a classical RSA algorithm (RSASHA1/256/512)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "DNSSEC zone is signed with a classical RSA algorithm (RSASHA1/RSASHA1-NSEC3-SHA1/RSASHA256/RSASHA512); DNSKEY/RRSIG signatures become forgeable once a CRQC exists.",
  remediation:
    "Track IETF dnsop post-quantum DNSSEC signing work (ML-DSA); plan re-signing with a PQC algorithm once assigned an IANA DNSSEC algorithm number.",
};
const RULE_DNSSEC_ECDSA: RuleMeta = {
  id: "dnssec-ecdsa-sig",
  title: "DNSSEC ECDSA signing algorithm",
  description: "DNSSEC zone signed with a classical ECDSA algorithm (ECDSAP256SHA256/384SHA384)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "DNSSEC zone is signed with a classical ECDSA algorithm (ECDSAP256SHA256/ECDSAP384SHA384); DNSKEY/RRSIG signatures become forgeable once a CRQC exists.",
  remediation:
    "Track IETF dnsop post-quantum DNSSEC signing work (ML-DSA); plan re-signing with a PQC algorithm once assigned an IANA DNSSEC algorithm number.",
};
const RULE_DNSSEC_EDDSA: RuleMeta = {
  id: "dnssec-eddsa-sig",
  title: "DNSSEC EdDSA signing algorithm",
  description: "DNSSEC zone signed with a classical EdDSA algorithm (ED25519/ED448)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "DNSSEC zone is signed with a classical EdDSA algorithm (ED25519/ED448); modern but still classical — DNSKEY/RRSIG signatures become forgeable once a CRQC exists.",
  remediation:
    "Track IETF dnsop post-quantum DNSSEC signing work (ML-DSA); plan re-signing with a PQC algorithm once assigned an IANA DNSSEC algorithm number.",
};
const RULE_DNSSEC_DSA: RuleMeta = {
  id: "dnssec-dsa-sig",
  title: "DNSSEC DSA signing algorithm (deprecated)",
  description:
    "DNSSEC zone signed with the deprecated classical DSA algorithm (DSA/DSA-NSEC3-SHA1)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "DNSSEC zone is signed with DSA/DSA-NSEC3-SHA1 — deprecated by RFC 8624 (MUST NOT sign) and, independent of that, forgeable once a CRQC exists.",
  remediation:
    "Re-sign with a non-deprecated algorithm today (RFC 8624); track IETF dnsop post-quantum DNSSEC signing work (ML-DSA) for the eventual PQC migration.",
};

/** True when `content` carries some DNSSEC-specific marker (not just a bare algorithm token). */
function hasDnssecMarker(content: string): boolean {
  return (
    content.includes("DNSKEY") ||
    content.includes("RRSIG") ||
    /dnssec/i.test(content) ||
    /ldns-signzone|dnssec-signzone/.test(content)
  );
}

interface DnssecRule {
  meta: RuleMeta;
  res: readonly RegExp[];
}

const DNSSEC_RULES: readonly DnssecRule[] = [
  { meta: RULE_DNSSEC_RSA, res: [RE_NAMED_RSA, RE_DNSKEY_RSA] },
  { meta: RULE_DNSSEC_ECDSA, res: [RE_NAMED_ECDSA, RE_DNSKEY_ECDSA] },
  { meta: RULE_DNSSEC_EDDSA, res: [RE_NAMED_EDDSA, RE_DNSKEY_EDDSA] },
  { meta: RULE_DNSSEC_DSA, res: [RE_NAMED_DSA, RE_DNSKEY_DSA] },
];

/** Detects classical DNSSEC signing algorithms in zone files and signer config. */
export const dnssecDetector: Detector = {
  id: "dnssec-crypto",
  description: "Classical DNSSEC signing algorithms in zone files / signer config",
  scope: "config",
  language: "any",
  rules: DNSSEC_RULES.map((r) => r.meta),
  appliesTo: (f) => hasExtension(f, DNSSEC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    if (!hasDnssecMarker(content)) return [];

    const findings: Finding[] = [];
    for (const { meta, res } of DNSSEC_RULES) {
      for (const re of res) {
        eachMatch(re, content, (m) =>
          findings.push(
            findingFromRule(meta, { file, content, index: m.index, matchLength: m[0].length }),
          ),
        );
      }
    }
    return findings;
  },
};
