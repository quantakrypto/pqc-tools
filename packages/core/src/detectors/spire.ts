/**
 * Config detector: classical key types configured for SPIFFE X.509 SVIDs in
 * SPIRE server/agent configuration (HCL, and the `.conf`/YAML/JSON variants
 * SPIRE deployments ship).
 *
 * SPIRE is the reference SPIFFE implementation: it issues each workload a
 * short-lived X.509-SVID certificate, signed by the SPIRE server's CA (itself
 * often chained to an UpstreamAuthority). The SVID leaf key and the CA signing
 * key are configured by explicit key-type strings:
 *  - server `ca_key_type = "rsa-2048" | "rsa-4096" | "ec-p256" | "ec-p384"` —
 *    the CA that signs every workload SVID in the trust domain (the identity
 *    ROOT: forge this and you forge the whole trust domain).
 *  - agent/server `svid_key_type = "rsa-2048" | "ec-p256"` — the per-workload
 *    leaf key type.
 *  - per-plugin `key_type = "rsa-2048" | "ec-p256"` on UpstreamAuthority /
 *    KeyManager plugins.
 *
 * These are SIGNING / identity keys, not confidentiality keys: an SVID X.509
 * signature is verified, never used to wrap harvestable ciphertext. So there is
 * nothing to "harvest now, decrypt later" — `hndl: false` — but every SVID
 * signature (and the CA signature over it) becomes FORGEABLE the moment a
 * cryptographically-relevant quantum computer (CRQC) exists, letting an attacker
 * mint certificates for any SPIFFE ID in the trust domain. Findings are
 * therefore `category: "certificate"` (X.509 / PKI material), `severity:
 * "medium"`, `confidence: "high"`.
 *
 * Algorithm mapping (SPIRE key-type value → {@link AlgorithmFamily}):
 *  - `rsa-2048` / `rsa-4096` / any `rsa-*`  → RSA
 *  - `ec-p256` / `ec-p384` / `ecdsa`        → ECDSA
 *
 * Match shape: the key-type attribute name (`ca_key_type`, `svid_key_type`, or
 * the bare per-plugin `key_type`) followed by `=`/`:` and a quoted value, in
 * both HCL (`=`) and YAML/JSON (`:`) forms. The `\b(?:ca_|svid_)?key_type\b`
 * anchor covers all three names in one pattern — the leading `\b` won't fire
 * inside `ca_key_type`/`svid_key_type` for the bare `key_type` alternative
 * because `_` is a word character, so those longer names are matched whole.
 *
 * Fast reject: `detect()` bails unless the file carries a SPIFFE/SPIRE-specific
 * marker (`spiffe`, `spire`, the distinctive `ca_key_type`, or `svid`). A bare
 * `key_type = "rsa-2048"` is deliberately NOT a sufficient marker — `key_type`
 * is a generic attribute (Vault PKI roles, cloud IaC, …), so without a
 * spiffe/spire/svid/ca_key_type anchor an unrelated config must not fire. This
 * keeps the generic per-plugin `key_type` rule precise while still catching a
 * real SPIRE config, which always names its trust domain / server / SVIDs.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  findingFromRule,
  hasExtension,
  maskCommentLines,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// SPIRE config is HCL/conf, but deployments also template it as YAML (Helm
// values / ConfigMaps) or JSON. Prose (`.md`, …) is excluded in `appliesTo`.
const SPIRE_EXTENSIONS: readonly string[] = [".conf", ".hcl", ".yaml", ".yml", ".json"];

// The three SPIRE key-type attribute names in one anchor: `ca_key_type`,
// `svid_key_type`, and the bare per-plugin `key_type`.
const KEY_ATTR = "(?:ca_|svid_)?key_type";
// HCL `=` and YAML/JSON `:` assignment forms; value quoted. Case-insensitive so
// an upper/mixed-case value can't slip past, though SPIRE writes them lowercase.
const RE_SPIRE_RSA = new RegExp(`\\b${KEY_ATTR}\\s*[:=]\\s*"rsa-\\d+"`, "gi");
const RE_SPIRE_ECDSA = new RegExp(`\\b${KEY_ATTR}\\s*[:=]\\s*"(?:ec-p\\d+|ecdsa)"`, "gi");

const RULE_SPIRE_RSA: RuleMeta = {
  id: "spire-rsa-key",
  title: "SPIRE/SPIFFE RSA SVID key type",
  description: 'SPIRE ca_key_type/svid_key_type/key_type = "rsa-*" (classical X.509-SVID key)',
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "SPIRE issues SPIFFE X.509-SVIDs with a classical RSA key; the SVID (and CA) signatures become forgeable once a CRQC exists, letting an attacker mint identities for the trust domain.",
  remediation:
    "SPIFFE/SPIRE has no PQC SVID key type yet — track the SPIFFE roadmap for PQC signature support. Prioritise the SPIRE server ca_key_type: the classical CA is the identity root, so its forgeability compromises every workload SVID.",
};
const RULE_SPIRE_ECDSA: RuleMeta = {
  id: "spire-ec-key",
  title: "SPIRE/SPIFFE ECDSA SVID key type",
  description:
    'SPIRE ca_key_type/svid_key_type/key_type = "ec-p256|ec-p384|ecdsa" (classical X.509-SVID key)',
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "SPIRE issues SPIFFE X.509-SVIDs with a classical ECDSA (P-256/P-384) key; the SVID (and CA) signatures become forgeable once a CRQC exists, letting an attacker mint identities for the trust domain.",
  remediation:
    "SPIFFE/SPIRE has no PQC SVID key type yet — track the SPIFFE roadmap for PQC signature support. Prioritise the SPIRE server ca_key_type: the classical CA is the identity root, so its forgeability compromises every workload SVID.",
};

/**
 * True when `content` carries a SPIFFE/SPIRE-specific marker. A bare generic
 * `key_type` is intentionally NOT enough — only `spiffe`/`spire` context, the
 * distinctive `ca_key_type`, or an `svid` token qualifies — so an unrelated
 * config that merely sets `key_type = "rsa-2048"` cannot fire.
 */
function hasSpireMarker(content: string): boolean {
  return /spiffe|spire|ca_key_type|svid/i.test(content);
}

/** Detects classical key types configured for SPIFFE X.509 SVIDs in SPIRE config. */
export const spireDetector: Detector = {
  id: "spire-crypto",
  description: "Classical key types for SPIFFE X.509 SVIDs in SPIRE server/agent config",
  scope: "config",
  language: "any",
  rules: [RULE_SPIRE_RSA, RULE_SPIRE_ECDSA],
  // Gate to SPIRE's config extensions, and never run on prose (a README that
  // describes `ca_key_type = "rsa-2048"` is documentation, not live config).
  appliesTo: (f) => hasExtension(f, SPIRE_EXTENSIONS) && !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    if (!hasSpireMarker(content)) return [];

    // Mask whole comment lines (HCL/YAML `#`, HCL/JSON5 `//`) so a commented-out
    // key-type directive can't fire. Offsets are preserved, so finding
    // line/column/snippet for the remaining live config stay exact.
    const scan = maskCommentLines(content, ["#", "//"]);
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_SPIRE_RSA, RULE_SPIRE_RSA);
    add(RE_SPIRE_ECDSA, RULE_SPIRE_ECDSA);
    return findings;
  },
};
