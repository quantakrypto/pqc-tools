/**
 * Source detector for classical asymmetric cryptography in Swift (Apple platforms) —
 * Apple CryptoKit and the older Security framework (`SecKey*`). Lexical, same strategy
 * as the other language packs; the API names are distinctive enough to keep the
 * false-positive risk low. Comment/string suppression is handled centrally
 * (`.swift` is a C-style comment language).
 *
 * CryptoKit:
 *  - `P256|P384|P521.Signing.PrivateKey`            → ECDSA signature (hndl:false)
 *  - `P256|P384|P521.KeyAgreement.PrivateKey`       → ECDH key agreement (hndl:true)
 *  - `Curve25519.Signing.PrivateKey`                → Ed25519 signature (hndl:false)
 *  - `Curve25519.KeyAgreement.PrivateKey`           → X25519 key agreement (hndl:true)
 * (`SecureEnclave.P256.…` forms are covered by the same P-curve regexes.)
 *
 * Security framework:
 *  - `SecKeyCreateRandomKey` with `kSecAttrKeyTypeRSA`                 → RSA
 *  - … with `kSecAttrKeyTypeEC` / `kSecAttrKeyTypeECSECPrimeRandom`    → EC
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const SWIFT_EXTENSIONS: readonly string[] = [".swift"];

// CryptoKit P-curve keys, split by usage (Signing vs KeyAgreement). `SecureEnclave.`
// may prefix the P-curve type, so it is allowed optionally.
const RE_SWIFT_P_SIGN = /\b(?:SecureEnclave\.)?P(?:256|384|521)\.Signing\.PrivateKey\b/g;
const RE_SWIFT_P_KEX = /\b(?:SecureEnclave\.)?P(?:256|384|521)\.KeyAgreement\.PrivateKey\b/g;
// CryptoKit Curve25519: Signing = Ed25519 (EdDSA); KeyAgreement = X25519.
const RE_SWIFT_ED25519 = /\bCurve25519\.Signing\.PrivateKey\b/g;
const RE_SWIFT_X25519 = /\bCurve25519\.KeyAgreement\.PrivateKey\b/g;
// Security framework key-type attributes (used with SecKeyCreateRandomKey).
const RE_SWIFT_SEC_RSA = /\bkSecAttrKeyTypeRSA\b/g;
const RE_SWIFT_SEC_EC = /\bkSecAttrKeyType(?:EC|ECSECPrimeRandom)\b/g;

const RULE_SWIFT_ECDSA: RuleMeta = {
  id: "swift-ecdsa",
  title: "Swift CryptoKit ECDSA signing key",
  description: "CryptoKit P256/P384/P521 Signing.PrivateKey",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "CryptoKit P-curve ECDSA signing (Swift) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_SWIFT_ECDH: RuleMeta = {
  id: "swift-ecdh",
  title: "Swift CryptoKit ECDH key agreement",
  description: "CryptoKit P256/P384/P521 KeyAgreement.PrivateKey",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "CryptoKit P-curve ECDH key agreement (Swift) is harvest-now-decrypt-later exposed.",
  remediation: "Migrate key agreement to hybrid X25519MLKEM768 (ML-KEM-768).",
};
const RULE_SWIFT_ED25519: RuleMeta = {
  id: "swift-ed25519",
  title: "Swift CryptoKit Ed25519 signing key",
  description: "CryptoKit Curve25519.Signing.PrivateKey (Ed25519)",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "CryptoKit Ed25519 signing (Swift) is classical and forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
};
const RULE_SWIFT_X25519: RuleMeta = {
  id: "swift-x25519",
  title: "Swift CryptoKit X25519 key agreement",
  description: "CryptoKit Curve25519.KeyAgreement.PrivateKey (X25519)",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "CryptoKit X25519 key agreement (Swift) is classical and harvest-now-decrypt-later exposed.",
  remediation: "Migrate key agreement to hybrid X25519MLKEM768 (ML-KEM-768).",
};
const RULE_SWIFT_RSA: RuleMeta = {
  id: "swift-rsa",
  title: "Swift Security-framework RSA key",
  description: "SecKeyCreateRandomKey with kSecAttrKeyTypeRSA",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Security-framework RSA key (Swift) is classical and not quantum-safe.",
  remediation: "Plan migration to PQC (ML-KEM-768 for encryption, ML-DSA-65 for signatures).",
};
const RULE_SWIFT_SEC_EC: RuleMeta = {
  id: "swift-sec-ec",
  title: "Swift Security-framework EC key",
  description: "SecKeyCreateRandomKey with kSecAttrKeyTypeEC",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Security-framework EC key (Swift); EC keys feed ECDSA signatures and ECDH key agreement (the ECDH path is harvest-now-decrypt-later exposed).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};

/** Detects classical asymmetric crypto in Swift (CryptoKit + Security framework). */
export const swiftDetector: Detector = {
  id: "swift-crypto",
  description: "Classical asymmetric crypto in Swift (CryptoKit, Security framework)",
  scope: "source",
  language: "swift",
  rules: [
    RULE_SWIFT_ECDSA,
    RULE_SWIFT_ECDH,
    RULE_SWIFT_ED25519,
    RULE_SWIFT_X25519,
    RULE_SWIFT_RSA,
    RULE_SWIFT_SEC_EC,
  ],
  appliesTo: (f) => hasExtension(f, SWIFT_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_SWIFT_P_SIGN, RULE_SWIFT_ECDSA);
    add(RE_SWIFT_P_KEX, RULE_SWIFT_ECDH);
    add(RE_SWIFT_ED25519, RULE_SWIFT_ED25519);
    add(RE_SWIFT_X25519, RULE_SWIFT_X25519);
    add(RE_SWIFT_SEC_RSA, RULE_SWIFT_RSA);
    add(RE_SWIFT_SEC_EC, RULE_SWIFT_SEC_EC);
    return findings;
  },
};
