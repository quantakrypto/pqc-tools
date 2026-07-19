/**
 * Config detector: classical key exchange in network transport / VPN config —
 * WireGuard and IPsec (strongSwan). These are the tunnels carrying "communication
 * between things"; their key exchange is classical and so harvest-now-decrypt-later
 * exposed (a recorded tunnel is decryptable once a CRQC exists).
 *
 * Covered (each gated so it only fires inside the relevant config):
 *  - **WireGuard** — `[Interface]`/`[Peer]` sections with `PrivateKey`/`PublicKey`.
 *    WireGuard's Noise handshake is Curve25519 with NO standard PQC option, so this
 *    is an especially sharp finding: it cannot be made quantum-safe without a
 *    tunnel-wrapping layer. The private key is treated as sensitive key material.
 *  - **IPsec / strongSwan** — IKE/ESP proposals naming classical DH groups
 *    (`modp*` = finite-field DH, `ecp*` = ECDH).
 *
 * `sshd_config` / `ssh_config` KexAlgorithms are intentionally NOT handled here —
 * the language-agnostic SSH token detector in `source.ts` (`ssh-kex-classical`)
 * already covers them; a rule here would double-count.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension, maskCommentLines } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const CONF_EXTENSIONS: readonly string[] = [".conf"];

const RE_WG_KEY = /\b(?:PrivateKey|PublicKey)\s*=\s*[A-Za-z0-9+/]{42,}=/g;
const RE_IPSEC_MODP = /\bmodp\d+\b/gi;
const RE_IPSEC_ECP = /\becp\d+(?:bp)?\b/gi;

const RULE_WG: RuleMeta = {
  id: "net-wireguard-x25519",
  title: "WireGuard Curve25519 key",
  description: "WireGuard [Interface]/[Peer] key — Curve25519 Noise handshake (no PQC option)",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  sensitive: true,
  message:
    "WireGuard tunnel keyed by classical Curve25519 (Noise); WireGuard has no standard post-quantum KEM, so the tunnel is harvest-now-decrypt-later exposed until wrapped by a PQC layer.",
  remediation:
    "Wrap the tunnel in a PQC-hybrid transport (e.g. a TLS 1.3 X25519MLKEM768 layer) or track WireGuard PQC proposals; rotate keys when available.",
};
const RULE_IPSEC_DH: RuleMeta = {
  id: "net-ipsec-modp-dh",
  title: "IPsec classical DH group (modp)",
  description: "IPsec/strongSwan IKE/ESP proposal names a finite-field DH group (modp*)",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "IPsec proposal uses a classical finite-field Diffie-Hellman group (modp*); the tunnel key exchange is harvest-now-decrypt-later exposed.",
  remediation: "Add a PQC/hybrid IKE proposal (ML-KEM) as your IPsec stack supports it.",
};
const RULE_IPSEC_EC: RuleMeta = {
  id: "net-ipsec-ecp-ecdh",
  title: "IPsec classical ECDH group (ecp)",
  description: "IPsec/strongSwan IKE/ESP proposal names an elliptic-curve DH group (ecp*)",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "IPsec proposal uses a classical elliptic-curve Diffie-Hellman group (ecp*); the tunnel key exchange is harvest-now-decrypt-later exposed.",
  remediation:
    "Add a PQC/hybrid IKE proposal (X25519MLKEM768 / ML-KEM) as your IPsec stack supports it.",
};

/** Detects classical key exchange in WireGuard / IPsec network config. */
export const vpnDetector: Detector = {
  id: "network-transport-crypto",
  description: "Classical key exchange in network transport / VPN config (WireGuard, IPsec)",
  scope: "config",
  language: "any",
  rules: [RULE_WG, RULE_IPSEC_DH, RULE_IPSEC_EC],
  appliesTo: (f) => hasExtension(f, CONF_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const push = (rule: RuleMeta, index: number, length: number) =>
      findings.push(findingFromRule(rule, { file, content, index, matchLength: length }));
    // ipsec.conf / wg configs use `#` line comments. Match over comment-masked
    // content (offsets preserved); gates stay on the original.
    const scan = maskCommentLines(content, ["#"]);

    // WireGuard: gated to a WireGuard config section.
    if (content.includes("[Interface]") || content.includes("[Peer]")) {
      eachMatch(RE_WG_KEY, scan, (m) => push(RULE_WG, m.index, m[0].length));
    }

    // IPsec / strongSwan: gated to a proposal assignment.
    if (/\b(?:ike|esp|proposals?|keyexchange)\s*=/i.test(content)) {
      eachMatch(RE_IPSEC_MODP, scan, (m) => push(RULE_IPSEC_DH, m.index, m[0].length));
      eachMatch(RE_IPSEC_ECP, scan, (m) => push(RULE_IPSEC_EC, m.index, m[0].length));
    }
    return findings;
  },
};
