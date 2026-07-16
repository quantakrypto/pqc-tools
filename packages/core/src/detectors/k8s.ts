/**
 * Config detector: classical crypto in Kubernetes manifests — cert-manager key
 * algorithms and service-mesh (Istio) TLS floors. These mint the certificates
 * and secure the pod-to-pod traffic of a cluster, a surface neither the language
 * packs nor the Terraform detector see.
 *
 * Covered (gated by a cert-manager / Istio marker in the document to keep the
 * generic `algorithm:` / `minProtocolVersion:` keys from firing on unrelated YAML):
 *  - cert-manager `Certificate`/`Issuer` `privateKey.algorithm` (or legacy
 *    `keyAlgorithm`): `RSA` | `ECDSA` | `Ed25519`.
 *  - Istio `minProtocolVersion: TLSV1_0 | TLSV1_1` — a legacy TLS floor on mesh
 *    traffic, whose (EC)DHE key exchange is classical and harvestable.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_RISKY_PRIMITIVE } from "../cwe.js";

const K8S_EXTENSIONS: readonly string[] = [".yaml", ".yml", ".json"];

const RE_CM_RSA = /(?:algorithm|keyAlgorithm):\s*["']?RSA\b/g;
const RE_CM_ECDSA = /(?:algorithm|keyAlgorithm):\s*["']?ECDSA\b/g;
const RE_CM_ED25519 = /(?:algorithm|keyAlgorithm):\s*["']?Ed25519\b/g;
const RE_ISTIO_LEGACY_TLS = /minProtocolVersion:\s*["']?TLSV1_[01]\b/g;

const RULE_CM_RSA: RuleMeta = {
  id: "k8s-certmanager-rsa",
  title: "cert-manager RSA key",
  description: "cert-manager Certificate/Issuer privateKey.algorithm = RSA",
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "cert-manager mints certificates with a classical RSA key, which is not quantum-safe.",
  remediation:
    "Plan migration to PQC certificate keys (ML-DSA-65) as the CA/issuer chain adds support.",
};
const RULE_CM_ECDSA: RuleMeta = {
  id: "k8s-certmanager-ecdsa",
  title: "cert-manager ECDSA key",
  description: "cert-manager Certificate/Issuer privateKey.algorithm = ECDSA",
  category: "certificate",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "cert-manager mints certificates with a classical ECDSA key, forgeable by a quantum attacker.",
  remediation: "Plan migration to ML-DSA-65 (FIPS 204) certificate keys.",
};
const RULE_CM_ED25519: RuleMeta = {
  id: "k8s-certmanager-ed25519",
  title: "cert-manager Ed25519 key",
  description: "cert-manager Certificate/Issuer privateKey.algorithm = Ed25519",
  category: "certificate",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "cert-manager mints certificates with a classical Ed25519 key, forgeable by a quantum attacker.",
  remediation: "Plan migration to ML-DSA-65 (FIPS 204) certificate keys.",
};
const RULE_ISTIO_LEGACY_TLS: RuleMeta = {
  id: "k8s-istio-legacy-tls",
  title: "Istio legacy TLS floor",
  description: "Istio minProtocolVersion allows TLS 1.0 / 1.1 on mesh traffic",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_RISKY_PRIMITIVE,
  message:
    "Istio mesh TLS floor allows TLS 1.0/1.1; its classical (EC)DHE key exchange is weak and harvestable.",
  remediation:
    "Raise minProtocolVersion to TLSV1_3 and track PQC-hybrid mesh KEX (X25519MLKEM768).",
};

/** Detects classical cert-manager keys and legacy Istio TLS floors in K8s YAML. */
export const k8sDetector: Detector = {
  id: "k8s-crypto",
  description: "Classical crypto in Kubernetes manifests (cert-manager keys, Istio TLS floors)",
  scope: "config",
  language: "any",
  rules: [RULE_CM_RSA, RULE_CM_ECDSA, RULE_CM_ED25519, RULE_ISTIO_LEGACY_TLS],
  appliesTo: (f) => hasExtension(f, K8S_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const isCertManager =
      content.includes("cert-manager.io") ||
      /kind:\s*["']?(?:Certificate|Issuer|ClusterIssuer)\b/.test(content);
    const isIstio = content.includes("minProtocolVersion");
    if (!isCertManager && !isIstio) return [];

    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    if (isCertManager) {
      add(RE_CM_RSA, RULE_CM_RSA);
      add(RE_CM_ECDSA, RULE_CM_ECDSA);
      add(RE_CM_ED25519, RULE_CM_ED25519);
    }
    if (isIstio) add(RE_ISTIO_LEGACY_TLS, RULE_ISTIO_LEGACY_TLS);
    return findings;
  },
};
