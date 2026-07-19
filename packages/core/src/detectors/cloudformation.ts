/**
 * IaC detector: classical asymmetric cryptography (and legacy TLS config)
 * declared in AWS CloudFormation / Azure ARM (incl. Bicep-compiled JSON)
 * templates — plus CDK `cdk synth` output, which is plain CloudFormation
 * JSON. This is a distinct surface from `terraform.ts`: CloudFormation/ARM
 * use PascalCase JSON/YAML property names, never Terraform's snake_case HCL
 * attributes, so the two detectors never collide on the same file.
 *
 * Covered:
 *  - AWS::KMS::Key `KeySpec`:                    `"RSA_…"` (kem) / `"ECC_…"` (key-exchange)
 *  - AWS::CertificateManager::Certificate
 *    `KeyAlgorithm`:                             `"RSA_…"` / `"EC_…"` (certificate)
 *  - CloudFront distribution `MinimumProtocolVersion`: legacy `TLSv1` / `TLSv1.1` (tls)
 *  - ELB/ALB listener `SslPolicy`:                legacy `ELBSecurityPolicy-2016-08` /
 *                                                 `-TLS-1-0-…` / `-TLS-1-1-…` (tls)
 *  - Azure ARM `Microsoft.KeyVault` key `kty`:    `"RSA"` (kem) / `"EC"` (key-exchange)
 *
 * `KeySpec` is PascalCase and case-sensitive, so it never matches Terraform's
 * snake_case `customer_master_key_spec` (same underlying AWS API, different
 * authoring surface). A fast-reject on a CFN/ARM marker keeps this detector
 * from ever firing on arbitrary JSON/YAML that happens to contain one of
 * these property names in an unrelated context.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_WEAK_STRENGTH } from "../cwe.js";

const CFN_EXTENSIONS: readonly string[] = [".json", ".yaml", ".yml"];

// Fast-reject markers: at least one must appear before any rule regex runs, so
// this detector never scans arbitrary JSON/YAML that merely happens to share
// an attribute name (`KeySpec`, `kty`, …) with an unrelated schema.
const CFN_MARKERS: readonly string[] = [
  "AWS::KMS",
  "AWS::CertificateManager",
  "AWSTemplateFormatVersion",
  "MinimumProtocolVersion",
  "Microsoft.KeyVault",
  "SslPolicy", // unquoted so a YAML `SslPolicy:` key also gates the file in, not just JSON
];

// Each attribute is matched with an optional quote around the key and `:` as
// the separator (both plain-JSON and YAML-block-scalar forms use `:`). The
// `(?<![\w"-])` lookbehind stops a longer/prefixed attribute name from
// matching on its suffix.
const RE_CFN_KMS_RSA = /(?<![\w"-])"?KeySpec"?\s*:\s*"?RSA_\d+"?/g;
const RE_CFN_KMS_EC = /(?<![\w"-])"?KeySpec"?\s*:\s*"?ECC_[A-Z0-9_]+"?/g;
const RE_CFN_ACM_RSA = /(?<![\w"-])"?KeyAlgorithm"?\s*:\s*"?RSA_\d+"?/g;
const RE_CFN_ACM_EC = /(?<![\w"-])"?KeyAlgorithm"?\s*:\s*"?EC_[A-Za-z0-9]+"?/g;
// CloudFront: only the pre-2018 "TLSv1" / "TLSv1_2016" / "TLSv1.1_2016"
// values are legacy; the lookahead delimiter stops this from matching a
// "TLSv1.2_2018"-style value that merely starts with the same prefix.
const RE_CFN_CLOUDFRONT_TLS =
  /(?<![\w"-])"?MinimumProtocolVersion"?\s*:\s*"?(?:TLSv1(?:\.1)?_2016|TLSv1)(?=["'\s,}]|$)/gm;
// ELB/ALB legacy SSL negotiation policies (named, dated policy strings). The value
// quote is optional (`"?`) so YAML block scalars (`SslPolicy: ELBSecurityPolicy-...`)
// match too, with a delimiter lookahead so a longer/newer policy name that merely
// shares the prefix is not matched.
const RE_CFN_ELB_TLS =
  /(?<![\w"-])"?SslPolicy"?\s*:\s*"?ELBSecurityPolicy-(?:2016-08|TLS-1-0-\d{4}-\d{2}|TLS-1-1-\d{4}-\d{2})(?=["'\s,}]|$)/g;
// Azure ARM Microsoft.KeyVault key resource `properties.kty`.
const RE_CFN_ARM_KV_RSA = /(?<![\w"-])"?kty"?\s*:\s*"?RSA"?(?!\w)/g;
const RE_CFN_ARM_KV_EC = /(?<![\w"-])"?kty"?\s*:\s*"?EC"?(?!\w)/g;

const RULE_CFN_KMS_RSA: RuleMeta = {
  id: "cfn-kms-rsa",
  title: "CloudFormation KMS RSA key",
  description: 'AWS::KMS::Key KeySpec = "RSA_*"',
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "CloudFormation provisions a classical RSA KMS key (harvest-now-decrypt-later exposed for encryption CMKs).",
  remediation: "Plan migration to PQC as cloud KMS adds ML-KEM / ML-DSA key specs.",
};
const RULE_CFN_KMS_EC: RuleMeta = {
  id: "cfn-kms-ec",
  title: "CloudFormation KMS EC key",
  description: 'AWS::KMS::Key KeySpec = "ECC_*"',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "CloudFormation provisions a classical EC KMS key; EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_CFN_ACM_RSA: RuleMeta = {
  id: "cfn-acm-rsa",
  title: "CloudFormation ACM RSA certificate",
  description: 'AWS::CertificateManager::Certificate KeyAlgorithm = "RSA_*"',
  category: "certificate",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "CloudFormation provisions an ACM certificate with a classical RSA key, which is not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 for encryption, ML-DSA-65 for signatures).",
};
const RULE_CFN_ACM_EC: RuleMeta = {
  id: "cfn-acm-ec",
  title: "CloudFormation ACM EC certificate",
  description: 'AWS::CertificateManager::Certificate KeyAlgorithm = "EC_*"',
  category: "certificate",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "CloudFormation provisions an ACM certificate with a classical EC key, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_CFN_CLOUDFRONT_TLS: RuleMeta = {
  id: "cfn-cloudfront-legacy-tls",
  title: "CloudFormation CloudFront legacy TLS",
  description: 'CloudFront Distribution MinimumProtocolVersion = "TLSv1" / "TLSv1.1"',
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "CloudFront distribution permits TLS 1.0/1.1, which are deprecated and insecure.",
  remediation:
    "Set MinimumProtocolVersion to TLSv1.2_2021 (or later) and prefer PQC-hybrid key exchange.",
};
const RULE_CFN_ELB_TLS: RuleMeta = {
  id: "cfn-elb-legacy-tls",
  title: "CloudFormation ELB/ALB legacy TLS policy",
  description: "Elastic Load Balancer SslPolicy naming a pre-2017 legacy policy",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "Load balancer listener uses a legacy SSL negotiation policy permitting TLS 1.0/1.1.",
  remediation: "Use ELBSecurityPolicy-TLS13-1-2-2021-06 (or the latest FS+TLS1.2/1.3 policy).",
};
const RULE_CFN_ARM_KV_RSA: RuleMeta = {
  id: "cfn-arm-keyvault-rsa",
  title: "ARM template Key Vault RSA key",
  description: 'Microsoft.KeyVault key resource kty = "RSA"',
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "ARM template provisions a classical RSA Azure Key Vault key, which is not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 / ML-DSA-65).",
};
const RULE_CFN_ARM_KV_EC: RuleMeta = {
  id: "cfn-arm-keyvault-ec",
  title: "ARM template Key Vault EC key",
  description: 'Microsoft.KeyVault key resource kty = "EC"',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "ARM template provisions a classical EC Azure Key Vault key; EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};

/**
 * Detects classical asymmetric crypto and legacy TLS config declared in
 * AWS CloudFormation / Azure ARM (incl. Bicep-compiled JSON) templates.
 */
export const cloudformationDetector: Detector = {
  id: "cloudformation-crypto",
  description:
    "Classical asymmetric crypto and legacy TLS config declared in CloudFormation / ARM templates (IaC)",
  scope: "config",
  language: "any",
  rules: [
    RULE_CFN_KMS_RSA,
    RULE_CFN_KMS_EC,
    RULE_CFN_ACM_RSA,
    RULE_CFN_ACM_EC,
    RULE_CFN_CLOUDFRONT_TLS,
    RULE_CFN_ELB_TLS,
    RULE_CFN_ARM_KV_RSA,
    RULE_CFN_ARM_KV_EC,
  ],
  appliesTo: (f) => hasExtension(f, CFN_EXTENSIONS),
  detect({ file, content }): Finding[] {
    if (!CFN_MARKERS.some((marker) => content.includes(marker))) return [];

    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_CFN_KMS_RSA, RULE_CFN_KMS_RSA);
    add(RE_CFN_KMS_EC, RULE_CFN_KMS_EC);
    add(RE_CFN_ACM_RSA, RULE_CFN_ACM_RSA);
    add(RE_CFN_ACM_EC, RULE_CFN_ACM_EC);
    add(RE_CFN_CLOUDFRONT_TLS, RULE_CFN_CLOUDFRONT_TLS);
    add(RE_CFN_ELB_TLS, RULE_CFN_ELB_TLS);
    add(RE_CFN_ARM_KV_RSA, RULE_CFN_ARM_KV_RSA);
    add(RE_CFN_ARM_KV_EC, RULE_CFN_ARM_KV_EC);
    return findings;
  },
};
