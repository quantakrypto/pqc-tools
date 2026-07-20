/**
 * Source detector for classical asymmetric cryptography in Objective-C on Apple
 * platforms (iOS / macOS / tvOS / watchOS), via the Security framework's
 * `SecKey*` API (and, underneath it, CommonCrypto). This is the Objective-C
 * sibling of the Swift pack: the same Security-framework surface, reached from
 * `.m` / `.mm` translation units instead of `.swift`. Lexical, same strategy as
 * the other language packs — the Security-framework identifiers
 * (`kSecAttrKeyType*`, `kSecKeyAlgorithm*`) are distinctive enough to keep the
 * false-positive risk low.
 *
 * WHY a dedicated Objective-C pack (and not the C/C++ pack):
 *  - The C/C++ pack (`c.ts`) matches OpenSSL / libsodium / Mbed TLS / wolfSSL
 *    symbols and is gated to `.c/.h/.cc/.cpp/...` (which INCLUDES `.h`). Apple's
 *    Security framework is a different API surface entirely, so a separate pack
 *    is the clean home for it.
 *  - Objective-C headers are `.h` — shared with C/C++. To avoid double-scanning
 *    a header the C pack already owns, this detector is gated to `.m` and `.mm`
 *    ONLY (implementation files). Declarations of `SecKey*` usage live in the
 *    implementation, not the interface, so no real coverage is lost.
 *
 * Security-framework surface mapped here:
 *  - Key generation attributes (`SecKeyCreateRandomKey` / `SecKeyGeneratePair`):
 *      `kSecAttrKeyTypeRSA`                         → RSA keygen (kem, hndl:true)
 *      `kSecAttrKeyTypeEC` / `…ECSECPrimeRandom`    → EC keygen (ECDSA, signature,
 *                                                     hndl:false — EC keys default
 *                                                     to signing; conservative)
 *  - Signing / verifying (`SecKeyCreateSignature` / `SecKeyVerifySignature`):
 *      `kSecKeyAlgorithmRSASignature*`              → RSA signature (hndl:false)
 *      `kSecKeyAlgorithmECDSASignature*`            → ECDSA signature (hndl:false)
 *  - Encryption / key agreement (`SecKeyCreateEncryptedData` / `SecKeyCopyKeyExchangeResult`):
 *      `kSecKeyAlgorithmRSAEncryption*`             → RSA encryption (kem, hndl:true)
 *      `kSecKeyAlgorithmECDHKeyExchange*`           → ECDH key agreement (hndl:true)
 *
 * Comment suppression is handled inline here (Objective-C is a C-style comment
 * language): C-style block comments and `//` line comments are masked before the
 * regexes run, so commented-out crypto never fires.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
  OBJC_EXTENSIONS,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// Security-framework key-type attributes (used with SecKeyCreateRandomKey /
// SecKeyGeneratePair). RSA vs EC. The EC form covers both the modern
// `kSecAttrKeyTypeECSECPrimeRandom` and the legacy `kSecAttrKeyTypeEC` alias.
const RE_OBJC_SEC_RSA = /\bkSecAttrKeyTypeRSA\b/g;
const RE_OBJC_SEC_EC = /\bkSecAttrKeyType(?:ECSECPrimeRandom|EC)\b/g;
// SecKey algorithm constants for signing / encryption / key agreement. The `\w*`
// tail captures the full family suffix (…PKCS1v15SHA256, …OAEPSHA256, …Standard,
// …CofactorX963SHA256, …) without needing to enumerate every variant.
const RE_OBJC_RSA_SIGN = /\bkSecKeyAlgorithmRSASignature\w*/g;
const RE_OBJC_RSA_ENCRYPT = /\bkSecKeyAlgorithmRSAEncryption\w*/g;
const RE_OBJC_ECDSA_SIGN = /\bkSecKeyAlgorithmECDSASignature\w*/g;
const RE_OBJC_ECDH = /\bkSecKeyAlgorithmECDHKeyExchange\w*/g;

const RULE_OBJC_SEC_RSA: RuleMeta = {
  id: "objc-seckey-rsa",
  title: "Objective-C Security-framework RSA key",
  description: "SecKeyCreateRandomKey / SecKeyGeneratePair with kSecAttrKeyTypeRSA",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Security-framework RSA key (Objective-C) is classical and not quantum-safe.",
  remediation:
    "Migrate to PQC as Apple's CryptoKit / Security add support: ML-KEM for encryption/key-agreement, ML-DSA for signatures.",
};
const RULE_OBJC_SEC_EC: RuleMeta = {
  id: "objc-seckey-ec",
  title: "Objective-C Security-framework EC key",
  description: "SecKeyCreateRandomKey / SecKeyGeneratePair with kSecAttrKeyTypeECSECPrimeRandom",
  category: "signature",
  severity: "high",
  confidence: "high",
  // EC keys feed BOTH ECDSA signatures and ECDH agreement; classified conservatively
  // as signing (the default use of an EC key), hence hndl:false.
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Security-framework EC key (Objective-C); EC keys feed ECDSA signatures (and ECDH key agreement) and are not quantum-safe.",
  remediation:
    "Migrate to PQC as Apple's CryptoKit / Security add support: ML-DSA for signatures, ML-KEM for the ECDH key-agreement path.",
};
const RULE_OBJC_RSA_SIGN: RuleMeta = {
  id: "objc-rsa-sign",
  title: "Objective-C RSA signature",
  description: "SecKeyCreateSignature / SecKeyVerifySignature with kSecKeyAlgorithmRSASignature*",
  category: "signature",
  // `medium` is acceptable for signatures — they are forgeable but not HNDL-exposed.
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical RSA signing (Objective-C, Security framework) is forgeable by a quantum attacker.",
  remediation: "Migrate to ML-DSA (FIPS 204) as Apple's CryptoKit / Security add PQC support.",
};
const RULE_OBJC_RSA_ENCRYPT: RuleMeta = {
  id: "objc-rsa-encrypt",
  title: "Objective-C RSA encryption",
  description: "SecKeyCreateEncryptedData with kSecKeyAlgorithmRSAEncryption*",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical RSA encryption (Objective-C, Security framework) is harvest-now-decrypt-later exposed.",
  remediation: "Migrate to ML-KEM (FIPS 203) as Apple's CryptoKit / Security add PQC support.",
};
const RULE_OBJC_ECDSA_SIGN: RuleMeta = {
  id: "objc-ecdsa-sign",
  title: "Objective-C ECDSA signature",
  description: "SecKeyCreateSignature / SecKeyVerifySignature with kSecKeyAlgorithmECDSASignature*",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical ECDSA signing (Objective-C, Security framework) is forgeable by a quantum attacker.",
  remediation: "Migrate to ML-DSA (FIPS 204) as Apple's CryptoKit / Security add PQC support.",
};
const RULE_OBJC_ECDH: RuleMeta = {
  id: "objc-ecdh",
  title: "Objective-C ECDH key agreement",
  description: "SecKeyCopyKeyExchangeResult with kSecKeyAlgorithmECDHKeyExchange*",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (Objective-C, Security framework) is broken by Shor's algorithm (harvest-now-decrypt-later).",
  remediation:
    "Migrate key agreement to ML-KEM (FIPS 203) as Apple's CryptoKit / Security add PQC support.",
};

/** Detects classical asymmetric crypto in Objective-C (Apple Security framework). */
export const objcDetector: Detector = {
  id: "objc-crypto",
  description: "Classical asymmetric crypto in Objective-C (Apple Security framework / SecKey)",
  scope: "source",
  language: "objc",
  rules: [
    RULE_OBJC_SEC_RSA,
    RULE_OBJC_SEC_EC,
    RULE_OBJC_RSA_SIGN,
    RULE_OBJC_RSA_ENCRYPT,
    RULE_OBJC_ECDSA_SIGN,
    RULE_OBJC_ECDH,
  ],
  appliesTo: (f) => hasExtension(f, OBJC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Fast reject: none of the Security-framework surface can appear without one
    // of these substrings, so most Objective-C files bail before any regex runs.
    if (
      !content.includes("SecKey") &&
      !content.includes("kSecAttrKeyType") &&
      !content.includes("kSecKeyAlgorithm")
    ) {
      return [];
    }
    // Mask C-style block comments then `//` line comments so commented-out crypto
    // does not fire. Both maskers preserve byte offsets, so finding line/column
    // stay exact.
    const masked = maskCommentLines(maskBlockComments(content), ["//"]);

    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, masked, (m) =>
        findings.push(
          findingFromRule(rule, {
            file,
            content: masked,
            index: m.index,
            matchLength: m[0].length,
          }),
        ),
      );
    add(RE_OBJC_SEC_RSA, RULE_OBJC_SEC_RSA);
    add(RE_OBJC_SEC_EC, RULE_OBJC_SEC_EC);
    add(RE_OBJC_RSA_SIGN, RULE_OBJC_RSA_SIGN);
    add(RE_OBJC_RSA_ENCRYPT, RULE_OBJC_RSA_ENCRYPT);
    add(RE_OBJC_ECDSA_SIGN, RULE_OBJC_ECDSA_SIGN);
    add(RE_OBJC_ECDH, RULE_OBJC_ECDH);
    return findings;
  },
};
