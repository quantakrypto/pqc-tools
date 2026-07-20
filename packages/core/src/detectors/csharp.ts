/**
 * Source-code detector for classical asymmetric cryptography in C# / .NET
 * (`System.Security.Cryptography`). Same lexical strategy as the other packs.
 * .NET exposes each algorithm through a factory (`RSA.Create()`,
 * `ECDsa.Create()`, `ECDiffieHellman.Create()`) or a concrete CSP/CNG class
 * (`RSACryptoServiceProvider`, `ECDsaCng`, …), all of which are precise signals.
 *
 * HNDL: RSA (keygen/encryption) and (EC)DH key agreement are harvest-now-
 * decrypt-later exposed (hndl:true); ECDSA/DSA signatures are hndl:false but
 * forgeable by a quantum attacker.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { CSHARP_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION, CWE_WEAK_STRENGTH } from "../cwe.js";

const RE_CS_RSA =
  /\bRSA\.Create\s*\(|\bnew\s+RSACryptoServiceProvider\s*\(|\bnew\s+RSACng\s*\(|\bnew\s+RSAOpenSsl\s*\(/g;
const RE_CS_ECDSA = /\bECDsa\.Create\s*\(|\bnew\s+ECDsaCng\s*\(|\bnew\s+ECDsaOpenSsl\s*\(/g;
const RE_CS_ECDH =
  /\bECDiffieHellman\.Create\s*\(|\bnew\s+ECDiffieHellmanCng\s*\(|\bnew\s+ECDiffieHellmanOpenSsl\s*\(/g;
const RE_CS_DSA = /\bDSA\.Create\s*\(|\bnew\s+DSACryptoServiceProvider\s*\(|\bnew\s+DSACng\s*\(/g;
// Insecure TLS configuration (.NET). Mirrors source.ts's tlsDetector split of a
// cert-verification-disabled rule (tls-reject-unauthorized) and a legacy-version
// rule (tls-legacy-version) for the equivalent C# idioms:
//   - DangerousAcceptAnyServerCertificateValidator / a custom
//     ServerCertificateCustomValidationCallback → accepts any cert (MITM).
//   - SslProtocols.Ssl3 / .Tls / .Tls11 → deprecated SSL 3.0 / TLS 1.0 / 1.1.
// `SslProtocols.Tls` (no suffix) is the legacy TLS 1.0 constant; `Tls12`/`Tls13`
// are excluded by the trailing \b (the following digit is a word char).
// Only the genuinely-permissive forms: the built-in accept-any validator, or a
// callback assigned an always-`true` lambda. A callback assigned a NAMED validator
// method is typically certificate PINNING (stricter than default) and must NOT fire.
const RE_CS_TLS_CERT_VALIDATION =
  /\bDangerousAcceptAnyServerCertificateValidator\b|ServerCertificateCustomValidationCallback\s*=\s*[^;\n]{0,80}=>\s*true\b/g;
const RE_CS_TLS_LEGACY_VERSION = /\bSslProtocols\.(?:Tls|Tls11|Ssl3)\b/g;
// Identifier-form JWT/JOSE signature algorithms (audit F7). The quoted-string
// alg token ("RS256") is caught by the language-agnostic jwt-jose detector, but
// Microsoft.IdentityModel passes the alg as an IDENTIFIER, not a string literal:
// SecurityAlgorithms.RsaSha256 / SecurityAlgorithms.EcdsaSha256.
const RE_CS_JWT_ALG = /\bSecurityAlgorithms\.(?:Rsa|Ecdsa)Sha(?:256|384|512)\b/g;
// BouncyCastle (Org.BouncyCastle) modern-curve and finite-field DH primitives,
// which System.Security.Cryptography does not expose directly. Each regex is
// anchored to the distinctive BouncyCastle class names for one family so it
// can't misfire on unrelated identifiers:
//   - Ed25519KeyPairGenerator / Ed25519Signer / Ed25519PrivateKeyParameters → EdDSA
//   - X25519KeyPairGenerator / X25519Agreement / X25519PrivateKeyParameters → X25519
//   - X448KeyPairGenerator / X448Agreement / X448PrivateKeyParameters → X448
//   - DHParametersGenerator / DHBasicAgreement / DH(Basic)KeyPairGenerator / DHParameters → DH
// The trailing \b keeps each token whole (e.g. Ed25519KeyGenerationParameters,
// X25519PublicKeyParameters and DHKeyGenerationParameters are NOT matched).
const RE_CS_BC_EDDSA = /\bEd25519(?:KeyPairGenerator|Signer|PrivateKeyParameters)\b/g;
const RE_CS_BC_X25519 = /\bX25519(?:KeyPairGenerator|Agreement|PrivateKeyParameters)\b/g;
const RE_CS_BC_X448 = /\bX448(?:KeyPairGenerator|Agreement|PrivateKeyParameters)\b/g;
const RE_CS_BC_DH =
  /\bDH(?:ParametersGenerator|BasicAgreement|BasicKeyPairGenerator|KeyPairGenerator|Parameters)\b/g;

const RULE_CS_RSA: RuleMeta = {
  id: "csharp-rsa",
  title: "C# RSA key/usage",
  description: "System.Security.Cryptography RSA.Create / RSACryptoServiceProvider / RSACng",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (.NET) is not quantum-safe and RSA encryption is HNDL-exposed.",
};
const RULE_CS_ECDSA: RuleMeta = {
  id: "csharp-ecdsa",
  title: "C# ECDSA signature",
  description: "System.Security.Cryptography ECDsa.Create / ECDsaCng",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (.NET) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_CS_ECDH: RuleMeta = {
  id: "csharp-ecdh",
  title: "C# ECDH key agreement",
  description: "System.Security.Cryptography ECDiffieHellman.Create / ECDiffieHellmanCng",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (.NET) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_CS_DSA: RuleMeta = {
  id: "csharp-dsa",
  title: "C# DSA key/signature",
  description: "System.Security.Cryptography DSA.Create / DSACryptoServiceProvider",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (.NET) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_CS_TLS_CERT: RuleMeta = {
  id: "csharp-tls-cert-validation",
  title: "C# TLS certificate verification disabled",
  description:
    "DangerousAcceptAnyServerCertificateValidator / ServerCertificateCustomValidationCallback override",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message: "Accepting any server certificate disables TLS certificate verification (MITM risk).",
  remediation:
    "Remove the custom validator and verify certificates properly; prefer PQC-hybrid key exchange.",
};
const RULE_CS_TLS_LEGACY: RuleMeta = {
  id: "csharp-tls-legacy-version",
  title: "C# legacy TLS/SSL version pinned",
  description: "SslProtocols pinned to Ssl3 / TLS 1.0 / TLS 1.1",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message:
    "SSL 3.0 / TLS 1.0 / TLS 1.1 are deprecated and insecure; require TLS 1.2+ (prefer 1.3).",
  remediation: "Use SslProtocols.Tls13 (or Tls12) and prefer PQC-hybrid key exchange.",
};
const RULE_CS_JWT_ALG: RuleMeta = {
  id: "csharp-jwt-alg",
  title: "C# identifier-form JWT/JOSE algorithm",
  description: "Microsoft.IdentityModel SecurityAlgorithms.RsaSha* / EcdsaSha*",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "A classical JWT/JOSE signature algorithm (.NET, identifier form) is used, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204); track IETF PQC JOSE/COSE algorithms",
};
const RULE_CS_BC_EDDSA: RuleMeta = {
  id: "csharp-bouncycastle-eddsa",
  title: "C# Ed25519 signature (BouncyCastle)",
  description:
    "Org.BouncyCastle Ed25519KeyPairGenerator / Ed25519Signer / Ed25519PrivateKeyParameters",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical Ed25519 signing (BouncyCastle) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_CS_BC_X25519: RuleMeta = {
  id: "csharp-bouncycastle-x25519",
  title: "C# X25519 key agreement (BouncyCastle)",
  description:
    "Org.BouncyCastle X25519KeyPairGenerator / X25519Agreement / X25519PrivateKeyParameters",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519 Diffie-Hellman key agreement (BouncyCastle) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_CS_BC_X448: RuleMeta = {
  id: "csharp-bouncycastle-x448",
  title: "C# X448 key agreement (BouncyCastle)",
  description: "Org.BouncyCastle X448KeyPairGenerator / X448Agreement / X448PrivateKeyParameters",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "X448",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X448 Diffie-Hellman key agreement (BouncyCastle) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_CS_BC_DH: RuleMeta = {
  id: "csharp-bouncycastle-dh",
  title: "C# finite-field Diffie-Hellman (BouncyCastle)",
  description:
    "Org.BouncyCastle DHParametersGenerator / DHBasicAgreement / DHKeyPairGenerator / DHParameters",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman (BouncyCastle) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};

/** Detects classical asymmetric crypto in C# (System.Security.Cryptography). */
export const csharpDetector: Detector = {
  id: "csharp-crypto",
  description:
    "Classical asymmetric crypto (System.Security.Cryptography) and insecure TLS config in C#/.NET",
  scope: "source",
  language: "csharp",
  rules: [
    RULE_CS_RSA,
    RULE_CS_ECDSA,
    RULE_CS_ECDH,
    RULE_CS_DSA,
    RULE_CS_TLS_CERT,
    RULE_CS_TLS_LEGACY,
    RULE_CS_JWT_ALG,
    RULE_CS_BC_EDDSA,
    RULE_CS_BC_X25519,
    RULE_CS_BC_X448,
    RULE_CS_BC_DH,
  ],
  appliesTo: (f) => hasExtension(f, CSHARP_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    // ECDSA / ECDH before RSA/DSA so the specific EC factories win.
    add(RE_CS_ECDSA, RULE_CS_ECDSA);
    add(RE_CS_ECDH, RULE_CS_ECDH);
    add(RE_CS_RSA, RULE_CS_RSA);
    add(RE_CS_DSA, RULE_CS_DSA);
    // Insecure TLS configuration (disjoint from the crypto factories above).
    add(RE_CS_TLS_CERT_VALIDATION, RULE_CS_TLS_CERT);
    add(RE_CS_TLS_LEGACY_VERSION, RULE_CS_TLS_LEGACY);
    // Identifier-form JWT/JOSE signature algorithms (Microsoft.IdentityModel).
    add(RE_CS_JWT_ALG, RULE_CS_JWT_ALG);
    // BouncyCastle (Org.BouncyCastle) curve / finite-field DH primitives that
    // System.Security.Cryptography does not expose directly.
    add(RE_CS_BC_EDDSA, RULE_CS_BC_EDDSA);
    add(RE_CS_BC_X25519, RULE_CS_BC_X25519);
    add(RE_CS_BC_X448, RULE_CS_BC_X448);
    add(RE_CS_BC_DH, RULE_CS_BC_DH);
    return findings;
  },
};
