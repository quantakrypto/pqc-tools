/**
 * Source-code detector for classical, non-quantum-safe asymmetric cryptography
 * in Go. Same lexical (regex-over-source) strategy as the JS/TS and Python
 * detectors. Go's crypto lives almost entirely in the highly-standardized
 * `crypto/*` standard library, so package-qualified calls (`rsa.GenerateKey`,
 * `ecdsa.SignASN1`, `ecdh.X25519`, …) are precise, low-false-positive signals.
 *
 * Covered:
 *   - crypto/rsa   — GenerateKey, EncryptOAEP/PKCS1v15, SignPKCS1v15/PSS
 *   - crypto/ecdsa — GenerateKey, Sign/SignASN1
 *   - crypto/ecdh  — P256/P384/P521/X25519 curve construction (key agreement)
 *   - crypto/ed25519 — GenerateKey, Sign
 *   - crypto/dsa   — GenerateKey, GenerateParameters (deprecated)
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
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

/* -------------------------------------------------------------------------- */
/* Precompiled regexes (module scope)                                         */
/* -------------------------------------------------------------------------- */

const RE_GO_RSA_KEYGEN = /\brsa\.GenerateKey\s*\(|\brsa\.GenerateMultiPrimeKey\s*\(/g;
const RE_GO_RSA_ENCRYPT = /\brsa\.EncryptOAEP\s*\(|\brsa\.EncryptPKCS1v15\s*\(/g;
const RE_GO_RSA_SIGN = /\brsa\.SignPKCS1v15\s*\(|\brsa\.SignPSS\s*\(/g;
const RE_GO_ECDSA = /\becdsa\.GenerateKey\s*\(|\becdsa\.SignASN1\s*\(|\becdsa\.Sign\s*\(/g;
const RE_GO_ECDH = /\becdh\.(?:P256|P384|P521|X25519)\s*\(/g;
const RE_GO_ED25519 = /\bed25519\.GenerateKey\s*\(|\bed25519\.Sign\s*\(/g;
const RE_GO_DSA = /\bdsa\.GenerateKey\s*\(|\bdsa\.GenerateParameters\s*\(/g;

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
  description: "crypto/ecdh P256/P384/P521/X25519 key agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (Go crypto/ecdh) is broken by Shor's algorithm (harvest-now-decrypt-later).",
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
    RULE_GO_ED25519,
    RULE_GO_DSA,
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
    add(RE_GO_ED25519, RULE_GO_ED25519);
    add(RE_GO_DSA, RULE_GO_DSA);

    return findings;
  },
};
