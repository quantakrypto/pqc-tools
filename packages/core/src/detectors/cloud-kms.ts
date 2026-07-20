/**
 * Cloud-KMS SDK detector: classical asymmetric keys minted at RUNTIME through a
 * cloud KMS SDK call — the application-code counterpart to the Terraform detector
 * (which covers the infrastructure-as-code path). AWS KMS `CreateKey` /
 * `GenerateDataKeyPair` select the key type with a `KeySpec` / `KeyPairSpec`
 * (legacy `CustomerMasterKeySpec`) field whose value is `RSA_*` or `ECC_*`.
 *
 * These field names + `RSA_2048` / `ECC_NIST_P256` values are specific to the AWS
 * KMS/ACM API across every SDK language (JS/TS, Python/boto3, Java, Go, the CLI, JSON
 * policies), so a single lexical rule catches them at very low false-positive rate.
 * Covered forms: the quoted-value SDK/JSON form (`KeySpec: "RSA_2048"`), the camelCase
 * CDK/Pulumi prop form (`customerMasterKeySpec: "RSA_2048"`), and the AWS CDK ENUM
 * form (`kms.KeySpec.RSA_2048`, `KeyAlgorithm.EC_prime256v1`). Terraform uses the
 * snake_case `customer_master_key_spec`, so this never double-counts with the IaC
 * detector.
 *
 * HNDL: an RSA KMS key (encryption/KEM) and an EC KMS key (which AWS KMS can use
 * for ECDH key agreement as well as ECDSA signing) are both harvest-now-decrypt-
 * later exposed → hndl:true.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { DOC_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { isCloudTemplateFile } from "./cloudformation.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// The AWS KMS / ACM key-spec field names. Both PascalCase (SDK / boto3 / JSON) and
// camelCase (AWS CDK / Pulumi props) leading letters are accepted. `KeyAlgorithm` is
// the ACM certificate key spec.
const SPEC_KEYS = "[Kk]eySpec|[Kk]eyPairSpec|[Cc]ustomerMasterKeySpec|[Kk]eyAlgorithm";
// (a) The QUOTED-VALUE form: `KeySpec: "RSA_2048"` / `"KeySpec": "RSA_2048"` /
//     `customerMasterKeySpec: "RSA_2048"` (SDK, boto3, JSON, Pulumi props).
const RE_KMS_RSA = new RegExp(`\\b(?:${SPEC_KEYS})"?\\s*[:=]\\s*['"](?:RSA_\\d+)['"]`, "g");
const RE_KMS_EC = new RegExp(
  `\\b(?:${SPEC_KEYS})"?\\s*[:=]\\s*['"](?:ECC_[A-Z0-9_]+|EC_[A-Za-z0-9]+)['"]`,
  "g",
);
// (b) The ENUM-MEMBER form used by AWS CDK: `kms.KeySpec.RSA_2048`,
//     `KeySpec.ECC_NIST_P256`, `KeyAlgorithm.RSA_2048`, `KeyAlgorithm.EC_prime256v1`
//     — an enum reference, no quoted value, so (a) never matches it.
const RE_KMS_RSA_ENUM = /\b(?:KeySpec|KeyAlgorithm)\.RSA_\d+\b/g;
const RE_KMS_EC_ENUM = /\b(?:KeySpec|KeyAlgorithm)\.(?:ECC_[A-Z0-9_]+|EC_[A-Za-z0-9]+)\b/g;

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
  description: "Classical asymmetric keys minted via a cloud KMS/ACM SDK, AWS CDK, or Pulumi",
  scope: "config",
  language: "any",
  rules: [RULE_KMS_RSA, RULE_KMS_EC],
  // Skip prose/docs: a README or tutorial showing `KeySpec: "RSA_2048"` to describe
  // the KMS API is not a live key-minting call.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Fast reject: only proceed if a KMS/ACM key-spec field name is present (any case).
    const lc = content.toLowerCase();
    if (!lc.includes("keyspec") && !lc.includes("keypairspec") && !lc.includes("keyalgorithm")) {
      return [];
    }
    // Inside a CloudFormation / ARM template FILE, the cloudformation detector owns
    // the KMS key specs — defer so a KeySpec line is not counted twice. Gated to the
    // template extensions it scans, so an SDK call in a `.ts` stays covered here.
    if (isCloudTemplateFile(file, content)) return [];
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta): void =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_KMS_RSA, RULE_KMS_RSA);
    add(RE_KMS_EC, RULE_KMS_EC);
    add(RE_KMS_RSA_ENUM, RULE_KMS_RSA);
    add(RE_KMS_EC_ENUM, RULE_KMS_EC);
    return findings;
  },
};
