/**
 * Source-code detector for classical asymmetric cryptography in Ruby. Ruby's
 * asymmetric crypto is almost entirely `OpenSSL::PKey::{RSA,EC,DSA,DH}`, which
 * makes the signals precise. Lexical, same strategy as the other packs. Beyond
 * keygen it also covers RSA public-key encryption on a loaded key, DH key
 * agreement, the type-agnostic `OpenSSL::PKey.read` loader, Ed25519 key
 * generation, and disabled TLS peer verification (`VERIFY_NONE`).
 *
 * HNDL: RSA (keygen/encryption) and (EC)DH key agreement are harvest-now-
 * decrypt-later exposed (hndl:true); DSA / Ed25519 signatures are hndl:false but
 * forgeable. `OpenSSL::PKey::EC` is ambiguous (feeds ECDSA + ECDH), so it is
 * classified conservatively as key-exchange-capable (hndl:true), like the other
 * EC keygen rules; `OpenSSL::PKey.read` loads a key of unknown type and is
 * likewise treated conservatively.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { RUBY_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION } from "../cwe.js";

const RE_RB_RSA = /\bOpenSSL::PKey::RSA\.(?:new|generate)\s*\(/g;
const RE_RB_EC = /\bOpenSSL::PKey::EC\.(?:new|generate)\s*\(/g;
const RE_RB_DSA = /\bOpenSSL::PKey::DSA\.(?:new|generate)\s*\(/g;
const RE_RB_DH = /\bOpenSSL::PKey::DH\.new\s*\(/g;
// RSA public-key encryption on an already-loaded key (audit F4-ruby / F9).
const RE_RB_RSA_CRYPT = /\.public_encrypt\b|\.private_decrypt\b/g;
// Finite-field DH shared-secret agreement.
const RE_RB_DH_AGREE = /\bdh_compute_key\s*\(/g;
// Type-agnostic key loader — could be RSA/EC/DSA/DH (conservative).
const RE_RB_PKEY_READ = /\bOpenSSL::PKey\.read\s*\(/g;
// Ed25519 signing key via the generic generate_key factory.
const RE_RB_ED25519 = /\bOpenSSL::PKey\.generate_key\s*\(\s*["']ED25519["']/g;
// TLS peer verification disabled (mirrors the JS tlsDetector rejectUnauthorized rule).
const RE_RB_TLS_VERIFY_NONE = /\bOpenSSL::SSL::VERIFY_NONE\b/g;

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
const RULE_RB_RSA_CRYPT: RuleMeta = {
  id: "ruby-rsa-crypt",
  title: "Ruby RSA public-key encryption",
  description: "OpenSSL::PKey::RSA#public_encrypt / #private_decrypt",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key encryption/decryption (Ruby/OpenSSL) is harvest-now-decrypt-later exposed.",
};
const RULE_RB_DH_AGREE: RuleMeta = {
  id: "ruby-dh-agree",
  title: "Ruby Diffie-Hellman key agreement",
  description: "OpenSSL DH compute_key shared-secret agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman key agreement (Ruby/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_RB_PKEY_READ: RuleMeta = {
  id: "ruby-pkey-read",
  title: "Ruby PKey loaded from serialized key",
  description: "OpenSSL::PKey.read (type-agnostic key loader)",
  category: "key-exchange",
  severity: "high",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Loads a classical asymmetric key of unknown type (RSA/EC/DSA/DH) via OpenSSL::PKey.read. Treated conservatively as key-exchange-capable (harvest-now-decrypt-later).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_RB_ED25519: RuleMeta = {
  id: "ruby-ed25519",
  title: "Ruby Ed25519 key generation",
  description: 'OpenSSL::PKey.generate_key("ED25519")',
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates an Ed25519 signing key (Ruby/OpenSSL) — modern but classical, and forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_RB_TLS_VERIFY_NONE: RuleMeta = {
  id: "ruby-tls-verify-none",
  title: "Ruby TLS certificate verification disabled",
  description: "OpenSSL::SSL::VERIFY_NONE",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message: "OpenSSL::SSL::VERIFY_NONE disables TLS peer certificate verification (MITM risk).",
  remediation: "Use OpenSSL::SSL::VERIFY_PEER and verify the certificate chain.",
};

/** Detects classical asymmetric crypto in Ruby (OpenSSL::PKey). */
export const rubyDetector: Detector = {
  id: "ruby-crypto",
  description: "Classical asymmetric crypto in Ruby (OpenSSL::PKey::{RSA,EC,DSA,DH})",
  scope: "source",
  language: "ruby",
  rules: [
    RULE_RB_RSA,
    RULE_RB_EC,
    RULE_RB_DSA,
    RULE_RB_DH,
    RULE_RB_RSA_CRYPT,
    RULE_RB_DH_AGREE,
    RULE_RB_PKEY_READ,
    RULE_RB_ED25519,
    RULE_RB_TLS_VERIFY_NONE,
  ],
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
    add(RE_RB_RSA_CRYPT, RULE_RB_RSA_CRYPT);
    add(RE_RB_DH_AGREE, RULE_RB_DH_AGREE);
    add(RE_RB_PKEY_READ, RULE_RB_PKEY_READ);
    add(RE_RB_ED25519, RULE_RB_ED25519);
    add(RE_RB_TLS_VERIFY_NONE, RULE_RB_TLS_VERIFY_NONE);
    return findings;
  },
};
