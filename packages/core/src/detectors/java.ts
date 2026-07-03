/**
 * Source-code detector for classical, non-quantum-safe asymmetric cryptography
 * in Java / Kotlin (the JCA — Java Cryptography Architecture). Same lexical
 * strategy as the other language packs.
 *
 * The JCA funnels almost everything through a handful of factory methods keyed
 * by an ALGORITHM STRING: `KeyPairGenerator.getInstance("RSA")`,
 * `Signature.getInstance("SHA256withECDSA")`, `Cipher.getInstance("RSA/ECB/…")`,
 * `KeyAgreement.getInstance("ECDH")`. So detection here is two steps: match the
 * `<Factory>.getInstance("<alg>")` call, then classify the (factory, alg) pair
 * into a rule. Symmetric / hashing algorithms ("AES", "HmacSHA256", …) classify
 * to nothing and are ignored. A small set of BouncyCastle lightweight-API class
 * names (`new ECDSASigner()`, `new X25519Agreement()`, …) is matched directly.
 *
 * HNDL policy mirrors the other detectors: KEM / key agreement (RSA encryption,
 * (EC)DH, X25519/X448) is harvest-now-decrypt-later exposed (hndl:true);
 * signatures (RSA/ECDSA/DSA/EdDSA) are hndl:false but forgeable by a quantum
 * attacker. `KeyPairGenerator.getInstance("EC")` is ambiguous (an EC key feeds
 * both ECDSA and ECDH), so it is classified conservatively as
 * key-exchange-capable (hndl:true), exactly as the Node/Python EC keygen rules.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { JAVA_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

/* -------------------------------------------------------------------------- */
/* Regexes                                                                    */
/* -------------------------------------------------------------------------- */

// <Factory>.getInstance("<alg>") — the JCA entry points that carry asymmetric
// algorithms. KeyGenerator/MessageDigest/Mac are intentionally excluded (they
// are symmetric / hashing only).
const RE_JAVA_GETINSTANCE =
  /\b(KeyPairGenerator|Signature|Cipher|KeyAgreement|KeyFactory)\s*\.\s*getInstance\s*\(\s*"([^"]+)"/g;

// BouncyCastle lightweight-API class instantiations.
const RE_JAVA_BC =
  /\bnew\s+(RSAKeyPairGenerator|DSAKeyPairGenerator|ECKeyPairGenerator|ECDSASigner|Ed25519Signer|Ed448Signer|X25519Agreement|X448Agreement)\s*\(/g;

/* -------------------------------------------------------------------------- */
/* Rule catalog                                                               */
/* -------------------------------------------------------------------------- */

const RULE_JAVA_RSA: RuleMeta = {
  id: "java-rsa",
  title: "Java RSA key/encryption",
  description: "JCA RSA KeyPairGenerator / Cipher / KeyFactory",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (Java/JCA) is not quantum-safe and RSA encryption is HNDL-exposed.",
};
const RULE_JAVA_RSA_SIGN: RuleMeta = {
  id: "java-rsa-sign",
  title: "Java RSA signature",
  description: 'JCA Signature.getInstance("…withRSA")',
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA signing (Java/JCA) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_JAVA_EC_KEYGEN: RuleMeta = {
  id: "java-ec-keygen",
  title: "Java EC key generation",
  description: 'JCA KeyPairGenerator.getInstance("EC")',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates a classical EC key pair (Java/JCA). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_JAVA_ECDSA_SIGN: RuleMeta = {
  id: "java-ecdsa-sign",
  title: "Java ECDSA signature",
  description: 'JCA Signature.getInstance("…withECDSA")',
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (Java/JCA) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_JAVA_ECDH: RuleMeta = {
  id: "java-ecdh",
  title: "Java ECDH key agreement",
  description: 'JCA KeyAgreement.getInstance("ECDH")',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (Java/JCA) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_JAVA_DSA: RuleMeta = {
  id: "java-dsa",
  title: "Java DSA key/signature",
  description: "JCA DSA KeyPairGenerator / Signature",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Java/JCA) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_JAVA_DH: RuleMeta = {
  id: "java-dh",
  title: "Java Diffie-Hellman key exchange",
  description: "JCA DiffieHellman KeyPairGenerator / KeyAgreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman (Java/JCA) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_JAVA_XDH: RuleMeta = {
  id: "java-xdh",
  title: "Java X25519/X448 key agreement",
  description: "JCA XDH / X25519 / X448 (KeyPairGenerator / KeyAgreement)",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519/X448 (Java/JCA) is modern but still classical key agreement — harvest-now-decrypt-later.",
};
const RULE_JAVA_EDDSA: RuleMeta = {
  id: "java-eddsa",
  title: "Java Ed25519/Ed448 signature",
  description: "JCA EdDSA / Ed25519 / Ed448",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519/Ed448 (Java/JCA) is a modern but still classical signature scheme.",
};

/**
 * Classify a `<factory>.getInstance("<alg>")` pair into a rule, or null when the
 * algorithm is not classical asymmetric crypto (AES, HMAC, PBKDF2, hashes, …).
 * `alg` is normalised to upper-case with any Cipher transformation suffix
 * (`RSA/ECB/OAEPPadding` → `RSA`) stripped.
 */
function classifyGetInstance(factory: string, rawAlg: string): RuleMeta | null {
  const alg = rawAlg.split("/")[0].trim().toUpperCase();
  const isSignature = factory === "Signature";

  if (alg.includes("ECDSA")) return RULE_JAVA_ECDSA_SIGN;
  if (alg.includes("ECDH")) return RULE_JAVA_ECDH;
  if (alg === "EC") return isSignature ? RULE_JAVA_ECDSA_SIGN : RULE_JAVA_EC_KEYGEN;
  if (alg.includes("ED25519") || alg.includes("ED448") || alg.includes("EDDSA"))
    return RULE_JAVA_EDDSA;
  if (alg.includes("X25519") || alg.includes("X448") || alg === "XDH") return RULE_JAVA_XDH;
  if (alg.includes("RSA")) return isSignature ? RULE_JAVA_RSA_SIGN : RULE_JAVA_RSA;
  if (alg.includes("DSA")) return RULE_JAVA_DSA; // ECDSA already handled above
  if (alg.includes("DH") || alg.includes("DIFFIEHELLMAN")) return RULE_JAVA_DH;
  return null;
}

/** BouncyCastle lightweight-API class name → rule. */
const BC_CLASS_RULES: Record<string, RuleMeta> = {
  RSAKeyPairGenerator: RULE_JAVA_RSA,
  DSAKeyPairGenerator: RULE_JAVA_DSA,
  ECKeyPairGenerator: RULE_JAVA_EC_KEYGEN,
  ECDSASigner: RULE_JAVA_ECDSA_SIGN,
  Ed25519Signer: RULE_JAVA_EDDSA,
  Ed448Signer: RULE_JAVA_EDDSA,
  X25519Agreement: RULE_JAVA_XDH,
  X448Agreement: RULE_JAVA_XDH,
};

/** Detects classical asymmetric crypto in Java / Kotlin (JCA + BouncyCastle). */
export const javaDetector: Detector = {
  id: "java-crypto",
  description: "Classical asymmetric crypto in Java/Kotlin (JCA getInstance + BouncyCastle)",
  scope: "source",
  language: "java",
  rules: [
    RULE_JAVA_RSA,
    RULE_JAVA_RSA_SIGN,
    RULE_JAVA_EC_KEYGEN,
    RULE_JAVA_ECDSA_SIGN,
    RULE_JAVA_ECDH,
    RULE_JAVA_DSA,
    RULE_JAVA_DH,
    RULE_JAVA_XDH,
    RULE_JAVA_EDDSA,
  ],
  appliesTo: (f) => hasExtension(f, JAVA_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    eachMatch(RE_JAVA_GETINSTANCE, content, (m) => {
      const rule = classifyGetInstance(m[1], m[2]);
      if (!rule) return; // symmetric / hashing algorithm — not our concern.
      findings.push(
        findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
      );
    });

    eachMatch(RE_JAVA_BC, content, (m) => {
      const rule = BC_CLASS_RULES[m[1]];
      if (!rule) return;
      findings.push(
        findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
      );
    });

    return findings;
  },
};
