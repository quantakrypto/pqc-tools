/**
 * Cloud-KMS SDK detector: classical asymmetric keys minted at RUNTIME through a
 * cloud KMS SDK call — the application-code counterpart to the Terraform detector
 * (which covers the infrastructure-as-code path). AWS KMS `CreateKey` /
 * `GenerateDataKeyPair` select the key type with a `KeySpec` / `KeyPairSpec`
 * (legacy `CustomerMasterKeySpec`) field whose value is `RSA_*` or `ECC_*`.
 *
 * These PascalCase field names + `RSA_2048` / `ECC_NIST_P256` values are specific
 * to the AWS KMS API across every SDK language (JS/TS, Python/boto3, Java, Go,
 * the CLI, JSON policies), so a single lexical rule catches them all with a very
 * low false-positive rate. Terraform uses the snake_case `customer_master_key_spec`
 * instead, so this never double-counts with the IaC detector.
 *
 * HNDL: an RSA KMS key (encryption/KEM) and an EC KMS key (which AWS KMS can use
 * for ECDH key agreement as well as ECDSA signing) are both harvest-now-decrypt-
 * later exposed → hndl:true.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// The AWS KMS key-spec fields (CreateKey / GenerateDataKeyPair / legacy CMK). The
// optional `"?` after the field name accepts both the JS/HCL form (`KeySpec:`) and
// the JSON form where the key is quoted (`"KeySpec":`).
const SPEC_KEYS = "KeySpec|KeyPairSpec|CustomerMasterKeySpec";
const RE_KMS_RSA = new RegExp(`\\b(?:${SPEC_KEYS})"?\\s*[:=]\\s*['"]RSA_\\d+['"]`, "g");
const RE_KMS_EC = new RegExp(`\\b(?:${SPEC_KEYS})"?\\s*[:=]\\s*['"]ECC_[A-Z0-9_]+['"]`, "g");

const RULE_KMS_RSA: RuleMeta = {
  id: "cloud-kms-rsa",
  title: "AWS KMS RSA key",
  description: "AWS KMS CreateKey / GenerateDataKeyPair with an RSA_* key spec",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Mints a classical RSA key via the AWS KMS SDK (harvest-now-decrypt-later exposed for encryption).",
  remediation: "Plan migration to PQC as cloud KMS adds ML-KEM / ML-DSA key specs.",
};
const RULE_KMS_EC: RuleMeta = {
  id: "cloud-kms-ec",
  title: "AWS KMS EC key",
  description: "AWS KMS CreateKey / GenerateDataKeyPair with an ECC_* key spec",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Mints a classical EC key via the AWS KMS SDK; EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};

/** Detects classical asymmetric keys provisioned via a cloud KMS SDK call. */
export const cloudKmsDetector: Detector = {
  id: "cloud-kms",
  description: "Classical asymmetric keys minted via a cloud KMS SDK (AWS KMS)",
  scope: "config",
  language: "any",
  rules: [RULE_KMS_RSA, RULE_KMS_EC],
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    // Fast reject: only proceed if a KMS key-spec field name is present.
    if (
      !content.includes("KeySpec") &&
      !content.includes("KeyPairSpec") &&
      !content.includes("CustomerMasterKeySpec")
    ) {
      return [];
    }
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta): void =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_KMS_RSA, RULE_KMS_RSA);
    add(RE_KMS_EC, RULE_KMS_EC);
    return findings;
  },
};
