/**
 * Source-code detector for classical, non-quantum-safe asymmetric cryptography
 * in Go. Same lexical (regex-over-source) strategy as the JS/TS and Python
 * detectors. Go's crypto lives almost entirely in the highly-standardized
 * `crypto/*` standard library, so package-qualified calls (`rsa.GenerateKey`,
 * `ecdsa.SignASN1`, `ecdh.X25519`, …) are precise, low-false-positive signals.
 *
 * Covered:
 *   - crypto/rsa   — GenerateKey, EncryptOAEP/PKCS1v15, SignPKCS1v15/PSS, DecryptOAEP, VerifyPKCS1v15/PSS
 *   - crypto/ecdsa — GenerateKey, Sign/SignASN1, Verify/VerifyASN1
 *   - crypto/ecdh  — P256/P384/P521/X25519 curve construction (key agreement)
 *   - crypto/elliptic — GenerateKey / ScalarMult (classic pre-1.20 ECDH)
 *   - crypto/ed25519 — GenerateKey, Sign, Verify
 *   - crypto/dsa   — GenerateKey, GenerateParameters (deprecated)
 *   - crypto/tls   — InsecureSkipVerify, legacy MinVersion (transport config hygiene)
 *
 * HNDL policy mirrors the other detectors: KEM / key agreement (RSA encryption,
 * ECDH) is harvest-now-decrypt-later exposed (hndl:true); signatures (RSA-sign,
 * ECDSA, Ed25519, DSA) are hndl:false but still forgeable by a quantum attacker.
 * Unlike Node's ambiguous `'ec'` keygen, Go's `ecdsa.GenerateKey` is
 * signature-specific and Go's key agreement lives in the separate `crypto/ecdh`
 * package, so the two are classified precisely rather than conservatively merged.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { GO_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION, CWE_WEAK_STRENGTH } from "../cwe.js";

/* -------------------------------------------------------------------------- */
/* Precompiled regexes (module scope)                                         */
/* -------------------------------------------------------------------------- */

const RE_GO_RSA_KEYGEN = /\brsa\.GenerateKey\s*\(|\brsa\.GenerateMultiPrimeKey\s*\(/g;
const RE_GO_RSA_ENCRYPT = /\brsa\.EncryptOAEP\s*\(|\brsa\.EncryptPKCS1v15\s*\(/g;
const RE_GO_RSA_SIGN = /\brsa\.SignPKCS1v15\s*\(|\brsa\.SignPSS\s*\(/g;
const RE_GO_ECDSA = /\becdsa\.GenerateKey\s*\(|\becdsa\.SignASN1\s*\(|\becdsa\.Sign\s*\(/g;
const RE_GO_ECDH = /\becdh\.(?:P256|P384|P521)\s*\(/g;
// X25519 gets its own family (algorithm "X25519", lower severity) to match how
// every other pack classifies it — Go was the lone site reporting it as ECDH/high
// (audit F9). Still key-exchange + hndl:true.
const RE_GO_X25519 = /\becdh\.X25519\s*\(/g;
const RE_GO_ED25519 = /\bed25519\.GenerateKey\s*\(|\bed25519\.Sign\s*\(/g;
const RE_GO_DSA = /\bdsa\.GenerateKey\s*\(|\bdsa\.GenerateParameters\s*\(/g;
// Verify / decrypt call sites — the inverse operations the Sign/Encrypt/
// GenerateKey rules above miss today (audit F4/F6). Deliberately disjoint from
// those rules to avoid double-counting: DecryptOAEP≠EncryptOAEP, Verify*≠Sign*.
const RE_GO_RSA_DECRYPT = /\brsa\.DecryptOAEP\s*\(/g;
const RE_GO_RSA_VERIFY = /\brsa\.VerifyPKCS1v15\s*\(|\brsa\.VerifyPSS\s*\(/g;
const RE_GO_ECDSA_VERIFY = /\becdsa\.Verify(?:ASN1)?\s*\(/g;
const RE_GO_ED25519_VERIFY = /\bed25519\.Verify\s*\(/g;
// Classic pre-1.20 elliptic-curve key agreement (crypto/elliptic), superseded by
// crypto/ecdh but still widespread. GenerateKey + ScalarMult are the low-level
// ECDH building blocks the crypto/ecdh rule does not see. `.ScalarMult(` is an
// unqualified method call, so this rule carries medium confidence.
const RE_GO_ECDH_CLASSIC = /\belliptic\.GenerateKey\s*\(|\.ScalarMult\s*\(/g;
// Go TLS misconfiguration (crypto/tls). Mirrors the JS tlsDetector: disabled
// certificate verification and a legacy TLS/SSL version floor.
const RE_GO_TLS_SKIP_VERIFY = /InsecureSkipVerify:\s*true/g;
const RE_GO_TLS_LEGACY_VERSION = /MinVersion:\s*tls\.Version(?:TLS1[01]|SSL30)/g;

/* -------------------------------------------------------------------------- */
/* Rule catalog                                                               */
/* -------------------------------------------------------------------------- */

const RULE_GO_RSA_KEYGEN: RuleMeta = {
  id: "go-rsa-keygen",
  title: "Go RSA key generation",
  description: "crypto/rsa GenerateKey / GenerateMultiPrimeKey",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical RSA key pair (Go), which is not quantum-safe.",
};
const RULE_GO_RSA_ENCRYPT: RuleMeta = {
  id: "go-rsa-encrypt",
  title: "Go RSA public-key encryption",
  description: "crypto/rsa EncryptOAEP / EncryptPKCS1v15",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key encryption (Go) is broken by Shor's algorithm and exposed to harvest-now-decrypt-later.",
};
const RULE_GO_RSA_SIGN: RuleMeta = {
  id: "go-rsa-sign",
  title: "Go RSA signature",
  description: "crypto/rsa SignPKCS1v15 / SignPSS",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA signing (Go) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_GO_ECDSA: RuleMeta = {
  id: "go-ecdsa",
  title: "Go ECDSA key/signature",
  description: "crypto/ecdsa GenerateKey / Sign / SignASN1",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA (Go) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_GO_ECDH: RuleMeta = {
  id: "go-ecdh",
  title: "Go ECDH key exchange",
  description: "crypto/ecdh P256/P384/P521 key agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (Go crypto/ecdh) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_GO_X25519: RuleMeta = {
  id: "go-x25519",
  title: "Go X25519 key exchange",
  description: "crypto/ecdh X25519 key agreement",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519 (Go crypto/ecdh) is modern but still classical key agreement — harvest-now-decrypt-later.",
};
const RULE_GO_ED25519: RuleMeta = {
  id: "go-ed25519",
  title: "Go Ed25519 signature",
  description: "crypto/ed25519 GenerateKey / Sign",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519 (Go) is a modern but still classical signature scheme.",
};
const RULE_GO_DSA: RuleMeta = {
  id: "go-dsa",
  title: "Go DSA key/usage",
  description: "crypto/dsa GenerateKey / GenerateParameters",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Go) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_GO_RSA_DECRYPT: RuleMeta = {
  id: "go-rsa-decrypt",
  title: "Go RSA public-key decryption",
  description: "crypto/rsa DecryptOAEP",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key decryption (Go) recovers data protected by a classical KEM — harvest-now-decrypt-later exposed.",
};
const RULE_GO_RSA_VERIFY: RuleMeta = {
  id: "go-rsa-verify",
  title: "Go RSA signature verification",
  description: "crypto/rsa VerifyPKCS1v15 / VerifyPSS",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Verifies classical RSA signatures (Go), which are forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_GO_ECDSA_VERIFY: RuleMeta = {
  id: "go-ecdsa-verify",
  title: "Go ECDSA signature verification",
  description: "crypto/ecdsa Verify / VerifyASN1",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Verifies classical ECDSA signatures (Go), which are forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_GO_ED25519_VERIFY: RuleMeta = {
  id: "go-ed25519-verify",
  title: "Go Ed25519 signature verification",
  description: "crypto/ed25519 Verify",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Verifies Ed25519 signatures (Go) — modern but still classical and quantum-forgeable.",
};
const RULE_GO_ECDH_CLASSIC: RuleMeta = {
  id: "go-ecdh-classic",
  title: "Go classic EC key agreement (crypto/elliptic)",
  description: "crypto/elliptic GenerateKey / ScalarMult (pre-1.20 ECDH)",
  category: "key-exchange",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Low-level elliptic-curve key agreement (Go crypto/elliptic) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_GO_TLS_SKIP_VERIFY: RuleMeta = {
  id: "go-tls-insecure-skip-verify",
  title: "Go TLS certificate verification disabled",
  description: "crypto/tls Config InsecureSkipVerify: true",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message: "InsecureSkipVerify:true disables TLS certificate verification (Go) — MITM risk.",
  remediation: "Remove InsecureSkipVerify:true; verify certificates properly.",
};
const RULE_GO_TLS_LEGACY_VERSION: RuleMeta = {
  id: "go-tls-legacy-version",
  title: "Go legacy TLS version pinned",
  description: "crypto/tls MinVersion pinned to TLS 1.0/1.1 or SSL 3.0",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message:
    "MinVersion pins a deprecated TLS/SSL floor (TLS 1.0/1.1 or SSL 3.0) in Go; require TLS 1.3.",
  remediation: "Set MinVersion: tls.VersionTLS13 and prefer PQC-hybrid key exchange.",
};

/** Detects classical asymmetric crypto in Go source (crypto/* standard library). */
export const goDetector: Detector = {
  id: "go-crypto",
  description: "Classical asymmetric crypto in Go (crypto/rsa, ecdsa, ecdh, ed25519, dsa)",
  scope: "source",
  language: "go",
  rules: [
    RULE_GO_RSA_KEYGEN,
    RULE_GO_RSA_ENCRYPT,
    RULE_GO_RSA_SIGN,
    RULE_GO_ECDSA,
    RULE_GO_ECDH,
    RULE_GO_X25519,
    RULE_GO_ED25519,
    RULE_GO_DSA,
    RULE_GO_RSA_DECRYPT,
    RULE_GO_RSA_VERIFY,
    RULE_GO_ECDSA_VERIFY,
    RULE_GO_ED25519_VERIFY,
    RULE_GO_ECDH_CLASSIC,
    RULE_GO_TLS_SKIP_VERIFY,
    RULE_GO_TLS_LEGACY_VERSION,
  ],
  appliesTo: (f) => hasExtension(f, GO_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );

    add(RE_GO_RSA_KEYGEN, RULE_GO_RSA_KEYGEN);
    add(RE_GO_RSA_ENCRYPT, RULE_GO_RSA_ENCRYPT);
    add(RE_GO_RSA_SIGN, RULE_GO_RSA_SIGN);
    add(RE_GO_ECDSA, RULE_GO_ECDSA);
    add(RE_GO_ECDH, RULE_GO_ECDH);
    add(RE_GO_X25519, RULE_GO_X25519);
    add(RE_GO_ED25519, RULE_GO_ED25519);
    add(RE_GO_DSA, RULE_GO_DSA);
    add(RE_GO_RSA_DECRYPT, RULE_GO_RSA_DECRYPT);
    add(RE_GO_RSA_VERIFY, RULE_GO_RSA_VERIFY);
    add(RE_GO_ECDSA_VERIFY, RULE_GO_ECDSA_VERIFY);
    add(RE_GO_ED25519_VERIFY, RULE_GO_ED25519_VERIFY);
    add(RE_GO_ECDH_CLASSIC, RULE_GO_ECDH_CLASSIC);
    add(RE_GO_TLS_SKIP_VERIFY, RULE_GO_TLS_SKIP_VERIFY);
    add(RE_GO_TLS_LEGACY_VERSION, RULE_GO_TLS_LEGACY_VERSION);

    return findings;
  },
};
