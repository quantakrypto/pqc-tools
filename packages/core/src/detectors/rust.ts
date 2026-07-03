/**
 * Source-code detector for classical asymmetric cryptography in Rust. Covers the
 * common crypto crates: `rsa`, `ring`, the `*-dalek` family (ed25519/x25519),
 * and the RustCrypto elliptic-curve crates (`p256`/`p384`/`k256`). Lexical, same
 * strategy as the other packs; the `::` path syntax makes the signals precise.
 *
 * HNDL: RSA encryption and (EC/X)DH key agreement are harvest-now-decrypt-later
 * exposed (hndl:true); ECDSA / Ed25519 signatures are hndl:false but forgeable.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { RUST_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// `rsa` crate + ring RsaKeyPair. `::` after the type marks an associated-fn call.
const RE_RUST_RSA = /\b(?:RsaPrivateKey|RsaPublicKey|RsaKeyPair)::/g;
// ECDSA: RustCrypto `p256::ecdsa::SigningKey` (contains `ecdsa::SigningKey`),
// ring `EcdsaKeyPair::`, or a bare `ecdsa::SigningKey`.
const RE_RUST_ECDSA = /\becdsa::SigningKey\b|\bEcdsaKeyPair::/g;
// ECDH: RustCrypto `p256::ecdh::EphemeralSecret`, ring agreement / ECDH_P*.
const RE_RUST_ECDH = /\becdh::EphemeralSecret\b|\bagreement::ECDH_P(?:256|384)\b/g;
// Ed25519 signatures (dalek + ring).
const RE_RUST_ED25519 = /\bed25519_dalek::(?:SigningKey|Keypair|SecretKey)\b|\bEd25519KeyPair::/g;
// X25519 key agreement (dalek).
const RE_RUST_X25519 = /\bx25519_dalek::(?:EphemeralSecret|StaticSecret)\b/g;

const RULE_RUST_RSA: RuleMeta = {
  id: "rust-rsa",
  title: "Rust RSA key/usage",
  description: "the `rsa` crate / ring RsaKeyPair",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (Rust) is not quantum-safe and RSA encryption is HNDL-exposed.",
};
const RULE_RUST_ECDSA: RuleMeta = {
  id: "rust-ecdsa",
  title: "Rust ECDSA signature",
  description: "p256/p384/k256 ecdsa::SigningKey / ring EcdsaKeyPair",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (Rust) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_RUST_ECDH: RuleMeta = {
  id: "rust-ecdh",
  title: "Rust ECDH key agreement",
  description: "p256/p384 ecdh::EphemeralSecret / ring agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman (Rust) is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_RUST_ED25519: RuleMeta = {
  id: "rust-ed25519",
  title: "Rust Ed25519 signature",
  description: "ed25519-dalek SigningKey/Keypair / ring Ed25519KeyPair",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519 (Rust) is a modern but still classical signature scheme.",
};
const RULE_RUST_X25519: RuleMeta = {
  id: "rust-x25519",
  title: "Rust X25519 key agreement",
  description: "x25519-dalek EphemeralSecret/StaticSecret",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X25519 (Rust) is modern but still classical key agreement — harvest-now-decrypt-later.",
};

/** Detects classical asymmetric crypto in Rust (rsa, ring, dalek, p256/k256). */
export const rustDetector: Detector = {
  id: "rust-crypto",
  description: "Classical asymmetric crypto in Rust (rsa, ring, *-dalek, p256/k256)",
  scope: "source",
  language: "rust",
  rules: [RULE_RUST_RSA, RULE_RUST_ECDSA, RULE_RUST_ECDH, RULE_RUST_ED25519, RULE_RUST_X25519],
  appliesTo: (f) => hasExtension(f, RUST_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    add(RE_RUST_RSA, RULE_RUST_RSA);
    add(RE_RUST_ECDSA, RULE_RUST_ECDSA);
    add(RE_RUST_ECDH, RULE_RUST_ECDH);
    add(RE_RUST_ED25519, RULE_RUST_ED25519);
    add(RE_RUST_X25519, RULE_RUST_X25519);
    return findings;
  },
};
