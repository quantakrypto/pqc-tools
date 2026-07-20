/**
 * IaC detector: classical asymmetric cryptography provisioned by Terraform /
 * OpenTofu (`.tf`, `.tf.json`). Infrastructure-as-code mints real keys and CMKs
 * that never appear in application source, so this is a distinct surface from the
 * language packs.
 *
 * Covered:
 *  - hashicorp/tls `tls_private_key`:      `algorithm = "RSA" | "ECDSA"`
 *  - Google Cloud KMS `version_template`:  `algorithm = "RSA_SIGN_…" | "EC_SIGN_…"`
 *  - AWS KMS `aws_kms_key`:                `customer_master_key_spec = "RSA_…" | "ECC_…"`
 *  - Azure `azurerm_key_vault_key`:        `key_type = "RSA" | "EC"` (+ HSM variants)
 *
 * The HCL assignment forms (`algorithm = "…"`, `customer_master_key_spec = "…"`,
 * `key_type = "…"`) are specific enough inside `.tf` files that the false-positive
 * risk is low. EC keys are classified conservatively as key-agreement-capable
 * (hndl:true) since a provisioned EC key can feed ECDH.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const TF_EXTENSIONS: readonly string[] = [".tf", ".tf.json"];

// Each attribute is matched in BOTH HCL (`algorithm = "RSA"`) and the `.tf.json`
// variant (`"algorithm": "RSA"`): an optional quote around the key, and `:` or
// `=` as the separator. The `(?<![\w"-])` lookbehind stops a longer attribute
// name (`my_algorithm`) from matching on its suffix.
// RSA: tls_private_key `"RSA"` plus the Google KMS `RSA_SIGN_…` / `RSA_DECRYPT_…`.
const RE_TF_RSA = /(?<![\w"-])"?algorithm"?\s*[:=]\s*"RSA(?:_[A-Z0-9_]+)?"/g;
// ECDSA / EC signing: tls_private_key `"ECDSA"` and Google KMS `"EC_SIGN_…"`.
const RE_TF_ECDSA = /(?<![\w"-])"?algorithm"?\s*[:=]\s*"(?:ECDSA|EC_SIGN_[A-Z0-9_]+)"/g;
// EdDSA signing: hashicorp/tls `tls_private_key` `algorithm = "ED25519"` (a supported,
// classical algorithm the RSA/ECDSA rules miss).
const RE_TF_ED25519 = /(?<![\w"-])"?algorithm"?\s*[:=]\s*"ED25519"/g;
// AWS KMS key specs: the legacy `customer_master_key_spec` and the modern `key_spec`
// alias (aws provider v4+). The `(?<![\w"-])` lookbehind rejects the `key_spec` suffix
// inside `customer_master_key_spec` (preceded by `_`), so no double-count.
const RE_TF_KMS_RSA = /(?<![\w"-])"?(?:customer_master_key_spec|key_spec)"?\s*[:=]\s*"RSA_\d+"/g;
const RE_TF_KMS_EC =
  /(?<![\w"-])"?(?:customer_master_key_spec|key_spec)"?\s*[:=]\s*"ECC_[A-Z0-9_]+"/g;
// `key_type` key material: Azure Key Vault (`"RSA"` / `"EC"`, incl. `-HSM`) and
// HashiCorp Vault PKI, which uses the lowercase `"rsa"` / `"ec"` tokens — so the value
// is matched case-insensitively. The `"…"` bound keeps `"ec"` from matching `"ecc"`,
// and `customer_master_key_spec` (AWS) is a different attribute handled above.
const RE_TF_AZ_RSA = /(?<![\w"-])"?key_type"?\s*[:=]\s*"RSA(?:-HSM)?"/gi;
const RE_TF_AZ_EC = /(?<![\w"-])"?key_type"?\s*[:=]\s*"EC(?:-HSM)?"/gi;

const RULE_TF_RSA: RuleMeta = {
  id: "tf-rsa-key",
  title: "Terraform RSA key",
  description: "Terraform tls_private_key / KMS RSA key material",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Terraform provisions a classical RSA key, which is not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 for encryption, ML-DSA-65 for signatures).",
};
const RULE_TF_ECDSA: RuleMeta = {
  id: "tf-ecdsa-key",
  title: "Terraform ECDSA key",
  description: "Terraform tls_private_key / KMS EC signing key",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Terraform provisions a classical ECDSA key, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_TF_ED25519: RuleMeta = {
  id: "tf-ed25519-key",
  title: "Terraform Ed25519 key",
  description: 'Terraform tls_private_key algorithm = "ED25519"',
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Terraform provisions a classical Ed25519 key, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_TF_KMS_RSA: RuleMeta = {
  id: "tf-kms-rsa",
  title: "Terraform AWS KMS RSA CMK",
  description: 'Terraform aws_kms_key customer_master_key_spec = "RSA_*"',
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Terraform provisions a classical RSA KMS customer master key (harvest-now-decrypt-later exposed for encryption CMKs).",
  remediation: "Plan migration to PQC as cloud KMS adds ML-KEM / ML-DSA key specs.",
};
const RULE_TF_KMS_EC: RuleMeta = {
  id: "tf-kms-ec",
  title: "Terraform AWS KMS EC CMK",
  description: 'Terraform aws_kms_key customer_master_key_spec = "ECC_*"',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Terraform provisions a classical EC KMS customer master key; EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_TF_AZ_RSA: RuleMeta = {
  id: "tf-keyvault-rsa",
  title: "Terraform Azure Key Vault RSA key",
  description: 'Terraform azurerm_key_vault_key key_type = "RSA"',
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Terraform provisions a classical RSA Azure Key Vault key, which is not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 / ML-DSA-65).",
};
const RULE_TF_AZ_EC: RuleMeta = {
  id: "tf-keyvault-ec",
  title: "Terraform Azure Key Vault EC key",
  description: 'Terraform azurerm_key_vault_key key_type = "EC"',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Terraform provisions a classical EC Azure Key Vault key; EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};

/** Detects classical asymmetric crypto provisioned in Terraform / OpenTofu. */
export const terraformDetector: Detector = {
  id: "terraform-crypto",
  description: "Classical asymmetric crypto provisioned by Terraform / OpenTofu (IaC)",
  scope: "config",
  language: "any",
  rules: [
    RULE_TF_RSA,
    RULE_TF_ECDSA,
    RULE_TF_ED25519,
    RULE_TF_KMS_RSA,
    RULE_TF_KMS_EC,
    RULE_TF_AZ_RSA,
    RULE_TF_AZ_EC,
  ],
  appliesTo: (f) => hasExtension(f, TF_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    // A commented HCL argument (`# algorithm = "RSA"`, `//` lines, and `/* … */` block
    // comments) is not an active resource argument. Mask block comments then line
    // comments; offsets preserved.
    const scan = maskCommentLines(maskBlockComments(content), ["#", "//"]);
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_TF_RSA, RULE_TF_RSA);
    add(RE_TF_ECDSA, RULE_TF_ECDSA);
    add(RE_TF_ED25519, RULE_TF_ED25519);
    add(RE_TF_KMS_RSA, RULE_TF_KMS_RSA);
    add(RE_TF_KMS_EC, RULE_TF_KMS_EC);
    add(RE_TF_AZ_RSA, RULE_TF_AZ_RSA);
    add(RE_TF_AZ_EC, RULE_TF_AZ_EC);
    return findings;
  },
};
