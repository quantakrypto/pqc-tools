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
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const RE_CS_RSA =
  /\bRSA\.Create\s*\(|\bnew\s+RSACryptoServiceProvider\s*\(|\bnew\s+RSACng\s*\(|\bnew\s+RSAOpenSsl\s*\(/g;
const RE_CS_ECDSA = /\bECDsa\.Create\s*\(|\bnew\s+ECDsaCng\s*\(|\bnew\s+ECDsaOpenSsl\s*\(/g;
const RE_CS_ECDH =
  /\bECDiffieHellman\.Create\s*\(|\bnew\s+ECDiffieHellmanCng\s*\(|\bnew\s+ECDiffieHellmanOpenSsl\s*\(/g;
const RE_CS_DSA = /\bDSA\.Create\s*\(|\bnew\s+DSACryptoServiceProvider\s*\(|\bnew\s+DSACng\s*\(/g;

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

/** Detects classical asymmetric crypto in C# (System.Security.Cryptography). */
export const csharpDetector: Detector = {
  id: "csharp-crypto",
  description: "Classical asymmetric crypto in C#/.NET (System.Security.Cryptography)",
  scope: "source",
  language: "csharp",
  rules: [RULE_CS_RSA, RULE_CS_ECDSA, RULE_CS_ECDH, RULE_CS_DSA],
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
    return findings;
  },
};
