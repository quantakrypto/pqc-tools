/**
 * Source-code detector for classical asymmetric cryptography in Ruby. Ruby's
 * asymmetric crypto is almost entirely `OpenSSL::PKey::{RSA,EC,DSA,DH}`, which
 * makes the signals precise. Lexical, same strategy as the other packs.
 *
 * HNDL: RSA (keygen/encryption) and (EC)DH key agreement are harvest-now-
 * decrypt-later exposed (hndl:true); DSA signatures are hndl:false but forgeable.
 * `OpenSSL::PKey::EC` is ambiguous (feeds ECDSA + ECDH), so it is classified
 * conservatively as key-exchange-capable (hndl:true), like the other EC keygen
 * rules.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { RUBY_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const RE_RB_RSA = /\bOpenSSL::PKey::RSA\.(?:new|generate)\s*\(/g;
const RE_RB_EC = /\bOpenSSL::PKey::EC\.(?:new|generate)\s*\(/g;
const RE_RB_DSA = /\bOpenSSL::PKey::DSA\.(?:new|generate)\s*\(/g;
const RE_RB_DH = /\bOpenSSL::PKey::DH\.new\s*\(/g;

const RULE_RB_RSA: RuleMeta = {
  id: "ruby-rsa",
  title: "Ruby RSA key/usage",
  description: "OpenSSL::PKey::RSA.new / .generate",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (Ruby/OpenSSL) is not quantum-safe and RSA encryption is HNDL-exposed.",
};
const RULE_RB_EC: RuleMeta = {
  id: "ruby-ec",
  title: "Ruby EC key generation",
  description: "OpenSSL::PKey::EC.new / .generate",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates a classical EC key pair (Ruby/OpenSSL). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_RB_DSA: RuleMeta = {
  id: "ruby-dsa",
  title: "Ruby DSA key/signature",
  description: "OpenSSL::PKey::DSA.new / .generate",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Ruby/OpenSSL) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_RB_DH: RuleMeta = {
  id: "ruby-dh",
  title: "Ruby Diffie-Hellman key exchange",
  description: "OpenSSL::PKey::DH.new",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman (Ruby/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};

/** Detects classical asymmetric crypto in Ruby (OpenSSL::PKey). */
export const rubyDetector: Detector = {
  id: "ruby-crypto",
  description: "Classical asymmetric crypto in Ruby (OpenSSL::PKey::{RSA,EC,DSA,DH})",
  scope: "source",
  language: "ruby",
  rules: [RULE_RB_RSA, RULE_RB_EC, RULE_RB_DSA, RULE_RB_DH],
  appliesTo: (f) => hasExtension(f, RUBY_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_RB_RSA, RULE_RB_RSA);
    add(RE_RB_EC, RULE_RB_EC);
    add(RE_RB_DSA, RULE_RB_DSA);
    add(RE_RB_DH, RULE_RB_DH);
    return findings;
  },
};
