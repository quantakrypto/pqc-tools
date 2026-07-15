/**
 * Source-code detector for classical asymmetric cryptography in C / C++ using
 * OpenSSL (the dominant crypto library for the ecosystem). Lexical, same
 * strategy as the other packs; the OpenSSL function names are distinctive.
 *
 * NOTE: scanning OpenSSL's OWN source/headers will naturally light up (the
 * library declares these symbols) — that is inherent to lexical scanning of a
 * crypto library, not a false positive in application code. Matches the classic
 * `*_generate_key` / `ECDSA_sign` / `ECDH_compute_key` call forms plus the
 * `EVP_RSA_gen` helper.
 *
 * HNDL: RSA encryption and (EC)DH key agreement are harvest-now-decrypt-later
 * exposed (hndl:true); ECDSA / DSA signatures are hndl:false but forgeable.
 * `EC_KEY_generate_key` is ambiguous (feeds ECDSA + ECDH), classified
 * conservatively as key-exchange-capable (hndl:true).
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { C_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const RE_C_RSA = /\bRSA_generate_key(?:_ex)?\s*\(|\bEVP_RSA_gen\s*\(/g;
const RE_C_EC = /\bEC_KEY_generate_key\s*\(|\bEC_KEY_new_by_curve_name\s*\(/g;
const RE_C_ECDSA = /\bECDSA_do_sign\s*\(|\bECDSA_sign\s*\(/g;
const RE_C_ECDH = /\bECDH_compute_key\s*\(/g;
const RE_C_DSA = /\bDSA_generate_key\s*\(|\bDSA_generate_parameters(?:_ex)?\s*\(/g;
const RE_C_DH = /\bDH_generate_key\s*\(|\bDH_generate_parameters(?:_ex)?\s*\(/g;
// Modern OpenSSL 3.x EVP API (the legacy *_generate_key forms above are
// deprecated) + libsodium — the biggest C false-negative surface (audit F1).
const RE_C_EVP_KEYGEN = /\bEVP_PKEY_(?:Q_)?keygen\s*\(|\bEVP_PKEY_paramgen\s*\(/g;
const RE_C_EVP_DERIVE = /\bEVP_PKEY_derive\s*\(/g;
const RE_C_EVP_CRYPT = /\bEVP_PKEY_(?:encrypt|decrypt)\s*\(/g;
const RE_C_EVP_SIGN = /\bEVP_DigestSign(?:Init)?\s*\(|\bEVP_DigestVerify(?:Init)?\s*\(/g;
const RE_C_SODIUM_BOX = /\bcrypto_box_(?:seed_)?keypair\s*\(/g;
const RE_C_SODIUM_SIGN = /\bcrypto_sign_(?:seed_)?keypair\s*\(/g;

const RULE_C_RSA: RuleMeta = {
  id: "c-rsa-keygen",
  title: "C/OpenSSL RSA key generation",
  description: "OpenSSL RSA_generate_key(_ex) / EVP_RSA_gen",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical RSA key pair (C/OpenSSL), which is not quantum-safe.",
};
const RULE_C_EC: RuleMeta = {
  id: "c-ec-keygen",
  title: "C/OpenSSL EC key generation",
  description: "OpenSSL EC_KEY_generate_key / EC_KEY_new_by_curve_name",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates a classical EC key pair (C/OpenSSL). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_C_ECDSA: RuleMeta = {
  id: "c-ecdsa",
  title: "C/OpenSSL ECDSA signature",
  description: "OpenSSL ECDSA_sign / ECDSA_do_sign",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (C/OpenSSL) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_C_ECDH: RuleMeta = {
  id: "c-ecdh",
  title: "C/OpenSSL ECDH key agreement",
  description: "OpenSSL ECDH_compute_key",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (C/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_C_DSA: RuleMeta = {
  id: "c-dsa",
  title: "C/OpenSSL DSA key/usage",
  description: "OpenSSL DSA_generate_key / DSA_generate_parameters",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (C/OpenSSL) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_C_DH: RuleMeta = {
  id: "c-dh",
  title: "C/OpenSSL Diffie-Hellman key exchange",
  description: "OpenSSL DH_generate_key / DH_generate_parameters",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman (C/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_C_EVP_KEYGEN: RuleMeta = {
  id: "c-evp-keygen",
  title: "C/OpenSSL EVP key generation",
  description: "OpenSSL 3.x EVP_PKEY_keygen / EVP_PKEY_Q_keygen / paramgen",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates an asymmetric key via the OpenSSL 3.x EVP API (the key type — RSA/EC/DH/X25519 — is set on the CTX). Treated conservatively as key-exchange-capable (harvest-now-decrypt-later).",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_C_EVP_DERIVE: RuleMeta = {
  id: "c-evp-derive",
  title: "C/OpenSSL EVP key agreement",
  description: "OpenSSL 3.x EVP_PKEY_derive (ECDH / DH shared secret)",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Derives an (EC)DH shared secret via the OpenSSL EVP API — broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_C_EVP_CRYPT: RuleMeta = {
  id: "c-evp-pkey-crypt",
  title: "C/OpenSSL EVP public-key encryption",
  description: "OpenSSL 3.x EVP_PKEY_encrypt / EVP_PKEY_decrypt (RSA)",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key encryption/decryption via the OpenSSL EVP API is harvest-now-decrypt-later exposed.",
};
const RULE_C_EVP_SIGN: RuleMeta = {
  id: "c-evp-sign",
  title: "C/OpenSSL EVP signing",
  description: "OpenSSL 3.x EVP_DigestSign* / EVP_DigestVerify*",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical signature via the OpenSSL EVP API (RSA/ECDSA/EdDSA) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_C_SODIUM_BOX: RuleMeta = {
  id: "c-libsodium-box",
  title: "libsodium X25519 key pair",
  description: "libsodium crypto_box_keypair (X25519 key agreement)",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "libsodium crypto_box uses X25519 key agreement — modern but classical, and harvest-now-decrypt-later exposed.",
};
const RULE_C_SODIUM_SIGN: RuleMeta = {
  id: "c-libsodium-sign",
  title: "libsodium Ed25519 key pair",
  description: "libsodium crypto_sign_keypair (Ed25519 signatures)",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "libsodium crypto_sign uses Ed25519 signatures — classical and forgeable by a quantum attacker.",
};

/** Detects classical asymmetric crypto in C/C++ (OpenSSL). */
export const cDetector: Detector = {
  id: "c-crypto",
  description: "Classical asymmetric crypto in C/C++ (OpenSSL)",
  scope: "source",
  language: "c",
  rules: [
    RULE_C_RSA,
    RULE_C_EC,
    RULE_C_ECDSA,
    RULE_C_ECDH,
    RULE_C_DSA,
    RULE_C_DH,
    RULE_C_EVP_KEYGEN,
    RULE_C_EVP_DERIVE,
    RULE_C_EVP_CRYPT,
    RULE_C_EVP_SIGN,
    RULE_C_SODIUM_BOX,
    RULE_C_SODIUM_SIGN,
  ],
  appliesTo: (f) => hasExtension(f, C_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_C_RSA, RULE_C_RSA);
    add(RE_C_EC, RULE_C_EC);
    add(RE_C_ECDSA, RULE_C_ECDSA);
    add(RE_C_ECDH, RULE_C_ECDH);
    add(RE_C_DSA, RULE_C_DSA);
    add(RE_C_DH, RULE_C_DH);
    add(RE_C_EVP_KEYGEN, RULE_C_EVP_KEYGEN);
    add(RE_C_EVP_DERIVE, RULE_C_EVP_DERIVE);
    add(RE_C_EVP_CRYPT, RULE_C_EVP_CRYPT);
    add(RE_C_EVP_SIGN, RULE_C_EVP_SIGN);
    add(RE_C_SODIUM_BOX, RULE_C_SODIUM_BOX);
    add(RE_C_SODIUM_SIGN, RULE_C_SODIUM_SIGN);
    return findings;
  },
};
