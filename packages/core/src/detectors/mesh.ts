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
 * Istio `tls.cipherSuites:` `ECDHE-RSA-*` / `ECDHE-ECDSA-*` suites are NOT handled
 * here — the language-agnostic `tls-classical-kex` token rule in `source.ts`
 * already flags those cipher strings in any config file, so a rule here would
 * double-count.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

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
/**
 * Detects classical asymmetric crypto in service-mesh configuration: Linkerd's
 * default ECDSA identity issuer and Consul Connect's mesh CA private key type.
 * (Istio ECDHE cipher-suite strings are covered by `source.ts`'s
 * `tls-classical-kex` token rule, so they are not duplicated here.)
 */
export const meshDetector: Detector = {
  id: "service-mesh-crypto",
  description: "Classical crypto in service-mesh config (Linkerd identity, Consul Connect CA)",
  scope: "config",
  language: "any",
  rules: [RULE_MESH_LINKERD_ECDSA, RULE_MESH_CONSUL_RSA, RULE_MESH_CONSUL_EC],
  appliesTo: (f) => hasExtension(f, MESH_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const isLinkerd = content.includes("linkerd") || content.includes("identityTrustAnchors");
    const isConsulConnect = content.includes("consul") && content.includes("connect");
    if (!isLinkerd && !isConsulConnect) return [];

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
    return findings;
  },
};
