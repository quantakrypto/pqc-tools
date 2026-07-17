/**
 * Config detector: classical crypto in SERVICE MESH configuration — the
 * control-plane identity/CA systems and mesh-internal TLS settings of
 * Linkerd, HashiCorp Consul Connect, and Istio. These mint the mTLS identity
 * certificates that secure sidecar-to-sidecar traffic and are configured in
 * their own Helm values / HCL / CRD surfaces, distinct from what `k8s.ts`
 * already covers (cert-manager `Certificate`/`Issuer` keys and Istio's
 * `minProtocolVersion` TLS floor — NOT duplicated here).
 *
 * Covered (gated by a mesh marker in the document to keep generic keys like
 * `scheme:` / `private_key_type` from firing on unrelated YAML/HCL):
 *  - Linkerd control-plane identity issuer: Helm values `identityTrustAnchorsPEM`
 *    and `identity.issuer.scheme` / nested `issuer.scheme: linkerd.io/tls` — the
 *    default self-managed Linkerd identity scheme, which mints workload
 *    certificates from an ECDSA P-256 trust anchor. Flagged as a classical mesh
 *    CA (certificate, ECDSA, hndl:false) since Linkerd's identity issuer signs
 *    forgeable-by-quantum leaf certs, not a confidentiality key.
 *  - HashiCorp Consul Connect: the `connect { ca_config { private_key_type =
 *    "ec" | "rsa" } } }` mesh CA provider setting (also `ca_provider`). Flagged
 *    as a classical mesh CA (certificate; ECDSA for "ec", RSA for "rsa").
 *  - Istio `DestinationRule` / `Gateway` `tls.cipherSuites:` listing a classical
 *    `ECDHE-RSA-*` / `ECDHE-ECDSA-*` suite — the (EC)DHE key exchange in these
 *    suites is classical and harvest-now-decrypt-later exposed (tls, ECDH,
 *    hndl:true). This complements, and does not duplicate, `k8s.ts`'s
 *    `minProtocolVersion` legacy-TLS-floor rule.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_RISKY_PRIMITIVE } from "../cwe.js";

const MESH_EXTENSIONS: readonly string[] = [".yaml", ".yml", ".hcl"];

// Linkerd's default self-managed identity scheme (`linkerd.io/tls`, as opposed
// to a `kubernetes.io/tls` bring-your-own-cert secret) mints its trust anchor
// and issuer credentials as ECDSA P-256 by default. Matched in both nested
// YAML form (`scheme: linkerd.io/tls`) and the flattened Helm `--set`/values
// key form (`identity.issuer.scheme: linkerd.io/tls`), plus the distinctive
// `identityTrustAnchorsPEM` values key which only exists in Linkerd charts.
const RE_MESH_LINKERD_ECDSA =
  /identityTrustAnchorsPEM\b|(?:identity\.issuer\.scheme|scheme)\s*[:=]\s*["']?linkerd\.io\/tls\b/g;

// Consul Connect's CA provider config: `private_key_type = "ec" | "rsa"`
// inside a `ca_config` block. Matched in both HCL (`=`) and JSON (`:`) forms,
// mirroring the terraform.ts attribute-matching convention.
const RE_MESH_CONSUL_RSA = /(?<![\w"-])"?private_key_type"?\s*[:=]\s*"rsa"/gi;
const RE_MESH_CONSUL_EC = /(?<![\w"-])"?private_key_type"?\s*[:=]\s*"ec"/gi;

// Istio mesh TLS cipher suites: OpenSSL-style suite names naming classical
// ECDHE key exchange combined with an RSA or ECDSA certificate. These are
// distinctive tokens (no generic-config collision risk).
const RE_MESH_ISTIO_CLASSICAL_CIPHER = /\bECDHE-(?:RSA|ECDSA)-[A-Z0-9_-]+\b/g;

const RULE_MESH_LINKERD_ECDSA: RuleMeta = {
  id: "mesh-linkerd-identity-ecdsa",
  title: "Linkerd ECDSA identity issuer",
  description: "Linkerd control-plane identity issuer (default ECDSA P-256 mesh CA)",
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Linkerd's control-plane identity issuer mints workload certificates from a classical ECDSA P-256 trust anchor by default, forgeable by a quantum attacker.",
  remediation:
    "Plan migration to ML-DSA-65 (FIPS 204) once Linkerd's identity issuer supports PQC signing.",
};
const RULE_MESH_CONSUL_RSA: RuleMeta = {
  id: "mesh-consul-connect-rsa",
  title: "Consul Connect RSA mesh CA",
  description: 'Consul Connect ca_config private_key_type = "rsa"',
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Consul Connect's mesh CA issues leaf certificates from a classical RSA private key, which is not quantum-safe.",
  remediation:
    "Plan migration to PQC certificate keys (ML-DSA-65) as the Connect CA provider adds support.",
};
const RULE_MESH_CONSUL_EC: RuleMeta = {
  id: "mesh-consul-connect-ec",
  title: "Consul Connect EC mesh CA",
  description: 'Consul Connect ca_config private_key_type = "ec"',
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Consul Connect's mesh CA issues leaf certificates from a classical EC private key, forgeable by a quantum attacker.",
  remediation: "Plan migration to ML-DSA-65 (FIPS 204) as the Connect CA provider adds support.",
};
const RULE_MESH_ISTIO_CLASSICAL_CIPHER: RuleMeta = {
  id: "mesh-istio-classical-cipher",
  title: "Istio classical ECDHE cipher suite",
  description:
    "Istio DestinationRule/Gateway tls.cipherSuites lists a classical ECDHE-RSA/ECDHE-ECDSA suite",
  category: "tls",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_RISKY_PRIMITIVE,
  message:
    "Istio mesh TLS cipher suite allows classical ECDHE key exchange, which is harvest-now-decrypt-later exposed.",
  remediation:
    "Prefer TLS 1.3 AEAD suites and track PQC-hybrid mesh key exchange (X25519MLKEM768) as Envoy/BoringSSL adds support.",
};

/**
 * Detects classical asymmetric crypto in service-mesh configuration: Linkerd's
 * default ECDSA identity issuer, Consul Connect's mesh CA private key type,
 * and classical ECDHE cipher suites in Istio DestinationRule/Gateway TLS
 * policy.
 */
export const meshDetector: Detector = {
  id: "service-mesh-crypto",
  description:
    "Classical crypto in service-mesh config (Linkerd identity, Consul Connect CA, Istio cipher suites)",
  scope: "config",
  language: "any",
  rules: [
    RULE_MESH_LINKERD_ECDSA,
    RULE_MESH_CONSUL_RSA,
    RULE_MESH_CONSUL_EC,
    RULE_MESH_ISTIO_CLASSICAL_CIPHER,
  ],
  appliesTo: (f) => hasExtension(f, MESH_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const isLinkerd = content.includes("linkerd") || content.includes("identityTrustAnchors");
    const isConsulConnect = content.includes("consul") && content.includes("connect");
    const isIstioCipher = content.includes("DestinationRule") || content.includes("cipherSuites");
    if (!isLinkerd && !isConsulConnect && !isIstioCipher) return [];

    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    if (isLinkerd) add(RE_MESH_LINKERD_ECDSA, RULE_MESH_LINKERD_ECDSA);
    if (isConsulConnect) {
      add(RE_MESH_CONSUL_RSA, RULE_MESH_CONSUL_RSA);
      add(RE_MESH_CONSUL_EC, RULE_MESH_CONSUL_EC);
    }
    if (isIstioCipher) add(RE_MESH_ISTIO_CLASSICAL_CIPHER, RULE_MESH_ISTIO_CLASSICAL_CIPHER);
    return findings;
  },
};
