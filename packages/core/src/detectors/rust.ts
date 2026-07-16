/**
 * Source-code detector for classical asymmetric cryptography in Rust. Covers the
 * common crypto crates: `rsa`, `ring`, the `*-dalek` family (ed25519/x25519),
 * the RustCrypto elliptic-curve crates (`p256`/`p384`/`k256`), and the `openssl`
 * crate bindings. Lexical, same strategy as the other packs; the `::` path
 * syntax makes the signals precise.
 *
 * HNDL: RSA encryption and (EC/X)DH key agreement are harvest-now-decrypt-later
 * exposed (hndl:true); ECDSA / DSA / Ed25519 signatures are hndl:false but
 * forgeable. `openssl::EcKey` keygen is ambiguous (feeds ECDSA + ECDH),
 * classified conservatively as key-exchange-capable (hndl:true). Also flags
 * Rust TLS certificate-validation bypasses (reqwest / rustls) — not quantum but
 * mirrors the JS tlsDetector's cert-validation category.
 */
import type { AlgorithmFamily, Detector, Finding, RuleMeta } from "../types.js";
import { RUST_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION } from "../cwe.js";

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
// openssl crate bindings — the `Type::generate(` / `Dh::` call forms, distinct
// from the ring / RustCrypto path syntax above (audit F5/F9 false-negatives).
const RE_RUST_OPENSSL_RSA = /\bRsa::generate\s*\(/g;
const RE_RUST_OPENSSL_EC = /\bEcKey::generate\s*\(/g;
const RE_RUST_OPENSSL_DSA = /\bDsa::generate\s*\(/g;
const RE_RUST_OPENSSL_DH = /\bDh::/g;
// ring X25519 agreement (the ECDH_P* forms are handled by RE_RUST_ECDH above).
const RE_RUST_RING_X25519 = /\bagreement::X25519\b/g;
// Bare (unqualified) constructors: a braced `use x25519_dalek::{EphemeralSecret}`
// / `use ed25519_dalek::{SigningKey}` strips the `::` path prefix, defeating the
// path-qualified rules above. The `(?<![:\w])` lookbehind keeps these from
// double-matching the qualified forms (e.g. `p256::ecdsa::SigningKey::random`).
const RE_RUST_BARE_X25519 = /(?<![:\w])EphemeralSecret::new\s*\(/g;
const RE_RUST_BARE_SIGNINGKEY = /(?<![:\w])SigningKey::(?:generate|random)\s*\(/g;
// jsonwebtoken crate `Algorithm` enum variants selecting a classical JWT signer:
// RSASSA-PKCS1 (RS*), RSASSA-PSS (PS*), ECDSA (ES*), and Ed25519 (EdDSA). The
// `\s*` between `Algorithm` and `::` catches the variant split across lines /
// routed through a helper (audit token_policy false-negative); the required
// suffix keeps it off unrelated `Algorithm::` uses (e.g. `HS256` HMAC, which is
// symmetric and not quantum-vulnerable, or `Algorithm::new`).
const RE_RUST_JWT_ALG = /\bAlgorithm\s*::(RS|PS|ES)(?:256|384|512)\b|\bAlgorithm\s*::EdDSA\b/g;
// Rust TLS certificate-validation bypass: reqwest `danger_accept_invalid_certs`
// and the rustls `.dangerous()` escape hatch. Mirrors the JS tlsDetector.
const RE_RUST_TLS_ACCEPT_INVALID = /\bdanger_accept_invalid_certs\s*\(\s*true/g;
const RE_RUST_TLS_DANGEROUS = /\.dangerous\s*\(\s*\)/g;

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
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X25519 (Rust) is modern but still classical key agreement — harvest-now-decrypt-later.",
};
const RULE_RUST_X448: RuleMeta = {
  id: "rust-x448",
  title: "Rust X448 key agreement",
  description: "the `x448` crate Secret key agreement",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X448",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X448 (Rust) is modern but still classical key agreement — harvest-now-decrypt-later.",
};
const RULE_RUST_OPENSSL_RSA: RuleMeta = {
  id: "rust-openssl-rsa",
  title: "Rust openssl RSA key generation",
  description: "openssl crate Rsa::generate",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates a classical RSA key pair via the Rust `openssl` crate — not quantum-safe and RSA encryption is HNDL-exposed.",
};
const RULE_RUST_OPENSSL_EC: RuleMeta = {
  id: "rust-openssl-ec",
  title: "Rust openssl EC key generation",
  description: "openssl crate EcKey::generate",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Generates a classical EC key pair via the Rust `openssl` crate. EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation:
    "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
};
const RULE_RUST_OPENSSL_DSA: RuleMeta = {
  id: "rust-openssl-dsa",
  title: "Rust openssl DSA key/usage",
  description: "openssl crate Dsa::generate",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical DSA via the Rust `openssl` crate is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204).",
};
const RULE_RUST_OPENSSL_DH: RuleMeta = {
  id: "rust-openssl-dh",
  title: "Rust openssl Diffie-Hellman key exchange",
  description: "openssl crate Dh params / key generation",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Finite-field Diffie-Hellman via the Rust `openssl` crate is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_RUST_RING_X25519: RuleMeta = {
  id: "rust-ring-x25519",
  title: "Rust ring X25519 key agreement",
  description: "ring agreement::X25519",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519 key agreement via ring (Rust) is modern but still classical — harvest-now-decrypt-later.",
};
const RULE_RUST_BARE_X25519: RuleMeta = {
  id: "rust-x25519-bare",
  title: "Rust X25519 key agreement (unqualified)",
  description: "bare EphemeralSecret::new (x25519-dalek imported via `use`)",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519 key agreement (x25519-dalek, imported unqualified) is modern but still classical — harvest-now-decrypt-later.",
};
const RULE_RUST_BARE_SIGNINGKEY: RuleMeta = {
  id: "rust-signingkey-bare",
  title: "Rust signature key (unqualified)",
  description: "bare SigningKey::generate/random (ed25519-dalek / k256 via `use`)",
  category: "signature",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical signature key from an unqualified `SigningKey` (ed25519-dalek Ed25519 / k256 ECDSA) — forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_RUST_JWT_ALGORITHM: RuleMeta = {
  id: "rust-jwt-algorithm",
  title: "Rust jsonwebtoken classical signature algorithm",
  description: "jsonwebtoken Algorithm::{RS,PS,ES}* / Algorithm::EdDSA enum variant",
  category: "signature",
  severity: "high",
  confidence: "high",
  // Representative family; refined per-finding (RS*/PS* → RSA, ES* → ECDSA, EdDSA).
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Selects a classical JWT signature algorithm (jsonwebtoken RS*/PS*/ES*/EdDSA), forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_RUST_TLS_ACCEPT_INVALID: RuleMeta = {
  id: "rust-tls-accept-invalid-certs",
  title: "Rust TLS certificate verification disabled",
  description: "reqwest danger_accept_invalid_certs(true)",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message:
    "danger_accept_invalid_certs(true) disables TLS certificate verification in reqwest (MITM risk).",
  remediation: "Remove danger_accept_invalid_certs(true); verify certificates properly.",
};
const RULE_RUST_TLS_DANGEROUS: RuleMeta = {
  id: "rust-tls-rustls-dangerous",
  title: "Rust rustls dangerous certificate config",
  description: "rustls ClientConfig .dangerous() escape hatch",
  category: "tls",
  severity: "high",
  confidence: "medium",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message: "rustls `.dangerous()` opts into disabling certificate verification (MITM risk).",
  remediation: "Avoid the dangerous() escape hatch; keep the default certificate verifier.",
};

/**
 * Aliasable Rust crypto types (`<crate>::<OrigType>` → rule). A renamed `use`
 * (`use x25519_dalek::{EphemeralSecret as MontgomerySecret}`) binds the alias to a
 * classical-key type; a later `MontgomerySecret::<ctor>(` is that key's
 * construction. The `::`-qualified and braced rules above miss this because the
 * call site uses the renamed identifier, not the original path.
 */
const RUST_ALIASABLE: Record<string, RuleMeta> = {
  "x25519_dalek::EphemeralSecret": RULE_RUST_X25519,
  "x25519_dalek::StaticSecret": RULE_RUST_X25519,
  "x448::Secret": RULE_RUST_X448,
  "ed25519_dalek::SigningKey": RULE_RUST_ED25519,
  "ed25519_dalek::Keypair": RULE_RUST_ED25519,
  "ed25519_dalek::SecretKey": RULE_RUST_ED25519,
};

/** Escape a string for interpolation into a dynamically-built RegExp. */
function escapeRustRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Collect `use <crate>::<OrigType> as <Alias>` bindings (braced or single) that
 * rename an aliasable crypto type, returning {alias, rule} pairs. An alias equal
 * to its own type name is skipped (the qualified/bare rules already catch it).
 */
function collectRustTypeAliases(content: string): Array<{ alias: string; rule: RuleMeta }> {
  const out: Array<{ alias: string; rule: RuleMeta }> = [];
  const push = (crate: string, orig: string, alias: string): void => {
    if (!alias || alias === orig) return;
    const rule = RUST_ALIASABLE[`${crate}::${orig}`];
    if (rule) out.push({ alias, rule });
  };
  // Braced: `use <crate>::{ Orig as Alias, ... }`.
  const braced = /\buse\s+([\w:]+)::\{([^}]*)\}/g;
  for (let m = braced.exec(content); m; m = braced.exec(content)) {
    const specRe = /([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)/g;
    for (let s = specRe.exec(m[2]); s; s = specRe.exec(m[2])) push(m[1], s[1], s[2]);
  }
  // Single: `use <crate>::Orig as Alias;`.
  const single = /\buse\s+([\w:]+)::([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)/g;
  for (let m = single.exec(content); m; m = single.exec(content)) push(m[1], m[2], m[3]);
  return out;
}

/** Detects classical asymmetric crypto in Rust (rsa, ring, dalek, p256/k256). */
export const rustDetector: Detector = {
  id: "rust-crypto",
  description: "Classical asymmetric crypto in Rust (rsa, ring, *-dalek, p256/k256)",
  scope: "source",
  language: "rust",
  rules: [
    RULE_RUST_RSA,
    RULE_RUST_ECDSA,
    RULE_RUST_ECDH,
    RULE_RUST_ED25519,
    RULE_RUST_X25519,
    RULE_RUST_X448,
    RULE_RUST_OPENSSL_RSA,
    RULE_RUST_OPENSSL_EC,
    RULE_RUST_OPENSSL_DSA,
    RULE_RUST_OPENSSL_DH,
    RULE_RUST_RING_X25519,
    RULE_RUST_BARE_X25519,
    RULE_RUST_BARE_SIGNINGKEY,
    RULE_RUST_JWT_ALGORITHM,
    RULE_RUST_TLS_ACCEPT_INVALID,
    RULE_RUST_TLS_DANGEROUS,
  ],
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
    add(RE_RUST_OPENSSL_RSA, RULE_RUST_OPENSSL_RSA);
    add(RE_RUST_OPENSSL_EC, RULE_RUST_OPENSSL_EC);
    add(RE_RUST_OPENSSL_DSA, RULE_RUST_OPENSSL_DSA);
    add(RE_RUST_OPENSSL_DH, RULE_RUST_OPENSSL_DH);
    add(RE_RUST_RING_X25519, RULE_RUST_RING_X25519);
    add(RE_RUST_BARE_X25519, RULE_RUST_BARE_X25519);
    add(RE_RUST_BARE_SIGNINGKEY, RULE_RUST_BARE_SIGNINGKEY);
    // jsonwebtoken Algorithm enum variants — resolve the family per match: the
    // RS*/PS* variants are RSASSA (RSA), ES* is ECDSA, EdDSA is Ed25519.
    eachMatch(RE_RUST_JWT_ALG, content, (m) => {
      const prefix = m[1];
      const algorithm: AlgorithmFamily =
        prefix === undefined ? "EdDSA" : prefix === "ES" ? "ECDSA" : "RSA";
      findings.push(
        findingFromRule(
          RULE_RUST_JWT_ALGORITHM,
          { file, content, index: m.index, matchLength: m[0].length },
          { algorithm },
        ),
      );
    });
    add(RE_RUST_TLS_ACCEPT_INVALID, RULE_RUST_TLS_ACCEPT_INVALID);
    add(RE_RUST_TLS_DANGEROUS, RULE_RUST_TLS_DANGEROUS);

    // Type-alias resolution: `use x25519_dalek::{EphemeralSecret as MontgomerySecret}`
    // then `MontgomerySecret::random_from_rng(` — the braced+renamed `use` defeats
    // the `::`-qualified rules. Match the aliased type's construction calls; runs
    // on the ORIGINAL content so locations stay exact, and fires only for an alias
    // explicitly bound to a known crypto type (precision-safe).
    for (const { alias, rule } of collectRustTypeAliases(content)) {
      const a = escapeRustRe(alias);
      add(
        new RegExp(`\\b${a}::(?:new|random|random_from_rng|generate|from_bytes)\\s*\\(`, "g"),
        rule,
      );
    }
    return findings;
  },
};
