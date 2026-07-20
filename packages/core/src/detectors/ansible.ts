/**
 * Config detector: classical asymmetric keys provisioned by Ansible's
 * `community.crypto` collection. Playbooks that mint TLS/SSH key material with
 * `openssl_privatekey` / `openssl_csr` / `x509_certificate` provision real
 * classical keys the language packs never see — the IaC surface, in YAML.
 *
 * Gated to a `community.crypto` / `openssl_privatekey` marker so a bare
 * `type: RSA` in unrelated YAML does not fire.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension, maskCommentLines } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const YAML_EXTENSIONS: readonly string[] = [".yml", ".yaml"];

const RE_ANSIBLE_RSA = /\btype:\s*["']?RSA\b/g;
const RE_ANSIBLE_ECC = /\btype:\s*["']?ECC\b/g;
// community.crypto also supports these `type:` values, all classical.
const RE_ANSIBLE_EDDSA = /\btype:\s*["']?Ed(?:25519|448)\b/g;
const RE_ANSIBLE_XDH = /\btype:\s*["']?X(?:25519|448)\b/g;
const RE_ANSIBLE_DSA = /\btype:\s*["']?DSA\b/g;

const RULE_ANSIBLE_RSA: RuleMeta = {
  id: "ansible-openssl-rsa",
  title: "Ansible community.crypto RSA key",
  description: "Ansible community.crypto openssl_privatekey/csr with type: RSA",
  category: "kem",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ansible provisions a classical RSA key (community.crypto), which is not quantum-safe.",
  remediation:
    "Plan migration to PQC keys (ML-KEM-768 / ML-DSA-65) as the collection adds support.",
};
const RULE_ANSIBLE_ECC: RuleMeta = {
  id: "ansible-openssl-ecc",
  title: "Ansible community.crypto EC key",
  description: "Ansible community.crypto openssl_privatekey/csr with type: ECC",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Ansible provisions a classical EC key (community.crypto); EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};

const RULE_ANSIBLE_EDDSA: RuleMeta = {
  id: "ansible-openssl-eddsa",
  title: "Ansible community.crypto Ed25519/Ed448 key",
  description: "Ansible community.crypto openssl_privatekey with type: Ed25519/Ed448",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Ansible provisions a classical Ed25519/Ed448 key (community.crypto), forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_ANSIBLE_XDH: RuleMeta = {
  id: "ansible-openssl-xdh",
  title: "Ansible community.crypto X25519/X448 key",
  description: "Ansible community.crypto openssl_privatekey with type: X25519/X448",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Ansible provisions a classical X25519/X448 key-agreement key (community.crypto), which is harvest-now-decrypt-later exposed.",
  remediation: "Migrate key agreement to hybrid X25519MLKEM768 (ML-KEM-768).",
};
const RULE_ANSIBLE_DSA: RuleMeta = {
  id: "ansible-openssl-dsa",
  title: "Ansible community.crypto DSA key (deprecated)",
  description: "Ansible community.crypto openssl_privatekey with type: DSA",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Ansible provisions a classical DSA key (community.crypto); deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA today; migrate to ML-DSA-65 (FIPS 204).",
};

/** Detects classical asymmetric keys provisioned by Ansible community.crypto. */
export const ansibleDetector: Detector = {
  id: "ansible-crypto",
  description: "Classical asymmetric keys provisioned by Ansible community.crypto",
  scope: "config",
  language: "any",
  rules: [
    RULE_ANSIBLE_RSA,
    RULE_ANSIBLE_ECC,
    RULE_ANSIBLE_EDDSA,
    RULE_ANSIBLE_XDH,
    RULE_ANSIBLE_DSA,
  ],
  appliesTo: (f) => hasExtension(f, YAML_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Gate: only inside a community.crypto / openssl_privatekey context.
    if (!content.includes("community.crypto") && !content.includes("openssl_privatekey")) return [];
    // YAML `#` comments are not active settings; match over comment-masked content
    // (offsets preserved) so a `# type: RSA` note does not fire.
    const scan = maskCommentLines(content, ["#"]);
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_ANSIBLE_RSA, RULE_ANSIBLE_RSA);
    add(RE_ANSIBLE_ECC, RULE_ANSIBLE_ECC);
    add(RE_ANSIBLE_EDDSA, RULE_ANSIBLE_EDDSA);
    add(RE_ANSIBLE_XDH, RULE_ANSIBLE_XDH);
    add(RE_ANSIBLE_DSA, RULE_ANSIBLE_DSA);
    return findings;
  },
};
