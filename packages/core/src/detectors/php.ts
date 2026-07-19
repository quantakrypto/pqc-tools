/**
 * Source-code detector for classical asymmetric cryptography in PHP — one of the
 * most-deployed backend languages, previously uncovered. Handles the three
 * dominant crypto surfaces:
 *
 *  - **ext/openssl** — `openssl_pkey_new()` (classified by its
 *    `OPENSSL_KEYTYPE_*` config, defaulting to RSA), `openssl_public_encrypt` /
 *    `openssl_private_decrypt` / `openssl_seal` / `openssl_open` (RSA), and
 *    `openssl_sign` / `openssl_verify`.
 *  - **phpseclib3** — `RSA::createKey()` / `EC::createKey()` / `DSA::createKey()`.
 *  - **libsodium** — `sodium_crypto_box`/`kx` keypairs (X25519) and
 *    `sodium_crypto_sign` keypairs (Ed25519).
 *
 * Lexical, like the other packs; the `openssl_*` / `sodium_crypto_*` prefixes and
 * `OPENSSL_KEYTYPE_*` constants are distinctive, so the false-positive rate is low.
 *
 * HNDL: RSA encryption and (EC/X)DH key agreement are harvest-now-decrypt-later
 * exposed (hndl:true); ECDSA / DSA / Ed25519 signatures are hndl:false but
 * forgeable. `openssl_pkey_new` EC and `EC::createKey` are ambiguous (feed BOTH
 * ECDSA and ECDH), classified conservatively as key-exchange-capable (hndl:true).
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { PHP_EXTENSIONS, eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

const RE_PHP_PKEY_NEW = /\bopenssl_pkey_new\s*\(/g;
// public_encrypt/private_decrypt (direct RSA) plus seal/open (RSA-envelope: seal
// encrypts a random symmetric key under each recipient's RSA public key, open
// decrypts it with the private key) — all RSA key transport, harvest-now exposed.
const RE_PHP_RSA_CRYPT = /\bopenssl_(?:public_encrypt|private_decrypt|seal|open)\s*\(/g;
const RE_PHP_SIGN = /\bopenssl_(?:sign|verify)\s*\(/g;
// phpseclib3 factory methods. The class names are generic, so require `::createKey`.
const RE_PHP_SECLIB = /\b(RSA|EC|DSA|DH)::createKey\s*\(/g;
// libsodium X25519 (box / kx / scalarmult) and Ed25519 (sign) key pairs.
const RE_PHP_SODIUM_X25519 =
  /\bsodium_crypto_(?:box|kx)_(?:seed_)?keypair\s*\(|\bsodium_crypto_scalarmult(?:_base)?\s*\(/g;
const RE_PHP_SODIUM_ED25519 = /\bsodium_crypto_sign_(?:seed_)?keypair\s*\(/g;

/** Key-type classification for `openssl_pkey_new`, keyed by its config constant. */
interface KeyInfo {
  algo: Finding["algorithm"];
  cat: Finding["category"];
  sev: Finding["severity"];
  hndl: boolean;
  label: string;
  remediation?: string;
}
const HYBRID = "hybrid X25519MLKEM768 (ML-KEM-768) for key agreement; ML-DSA-65 (FIPS 204) to sign";

const RULE_PHP_KEYGEN: RuleMeta = {
  id: "php-openssl-keygen",
  title: "PHP openssl key generation",
  description: "openssl_pkey_new (RSA/EC/DSA/DH, by OPENSSL_KEYTYPE_*)",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical key pair via PHP openssl_pkey_new — not quantum-safe.",
};
const RULE_PHP_RSA_CRYPT: RuleMeta = {
  id: "php-openssl-rsa-crypt",
  title: "PHP openssl RSA public-key encryption",
  description: "openssl_public_encrypt / openssl_private_decrypt / openssl_seal / openssl_open",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key encryption/decryption (PHP openssl) is harvest-now-decrypt-later exposed.",
};
const RULE_PHP_SIGN: RuleMeta = {
  id: "php-openssl-sign",
  title: "PHP openssl signature",
  description: "openssl_sign / openssl_verify",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical signature via PHP openssl (RSA/ECDSA/DSA) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_PHP_SECLIB: RuleMeta = {
  id: "php-phpseclib-keygen",
  title: "PHP phpseclib key generation",
  description: "phpseclib3 RSA/EC/DSA/DH ::createKey",
  category: "kem",
  severity: "high",
  confidence: "medium",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical key pair via phpseclib3 (createKey) — not quantum-safe.",
};
const RULE_PHP_SODIUM_X25519: RuleMeta = {
  id: "php-sodium-x25519",
  title: "PHP libsodium X25519 key agreement",
  description: "sodium_crypto_box/kx keypair + scalarmult",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "libsodium crypto_box/kx (PHP) uses X25519 key agreement — modern but classical, harvest-now-decrypt-later exposed.",
};
const RULE_PHP_SODIUM_ED25519: RuleMeta = {
  id: "php-sodium-ed25519",
  title: "PHP libsodium Ed25519 signature",
  description: "sodium_crypto_sign keypair",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "libsodium crypto_sign (PHP) uses Ed25519 — classical and forgeable by a quantum attacker.",
};

/** phpseclib class name → its classification. */
const SECLIB_INFO: Record<string, KeyInfo> = {
  RSA: { algo: "RSA", cat: "kem", sev: "high", hndl: true, label: "RSA" },
  EC: {
    algo: "ECDH",
    cat: "key-exchange",
    sev: "high",
    hndl: true,
    label: "EC (ECDSA/ECDH)",
    remediation: HYBRID,
  },
  DSA: { algo: "DSA", cat: "signature", sev: "high", hndl: false, label: "DSA" },
  DH: { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "Diffie-Hellman" },
};

/** Classify `openssl_pkey_new` by the `OPENSSL_KEYTYPE_*` constant in its config.
 * The window is bounded to the current statement (up to the next `;`, capped at
 * 300 chars) so it can't bleed into a following `openssl_pkey_new` call's key
 * type. Defaults to RSA — openssl_pkey_new's own default private_key_type is RSA
 * when none is given. */
function classifyPkeyNew(content: string, index: number): KeyInfo {
  const semi = content.indexOf(";", index);
  const end = Math.min(index + 300, semi === -1 ? content.length : semi);
  const w = content.slice(index, end);
  if (/\bOPENSSL_KEYTYPE_EC\b/.test(w)) return SECLIB_INFO.EC;
  if (/\bOPENSSL_KEYTYPE_DSA\b/.test(w)) return SECLIB_INFO.DSA;
  if (/\bOPENSSL_KEYTYPE_DH\b/.test(w)) return SECLIB_INFO.DH;
  return SECLIB_INFO.RSA;
}

/** Detects classical asymmetric crypto in PHP (openssl, phpseclib, libsodium). */
export const phpDetector: Detector = {
  id: "php-crypto",
  description: "Classical asymmetric crypto in PHP (openssl, phpseclib3, libsodium)",
  scope: "source",
  language: "php",
  rules: [
    RULE_PHP_KEYGEN,
    RULE_PHP_RSA_CRYPT,
    RULE_PHP_SIGN,
    RULE_PHP_SECLIB,
    RULE_PHP_SODIUM_X25519,
    RULE_PHP_SODIUM_ED25519,
  ],
  appliesTo: (f) => hasExtension(f, PHP_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta): void =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );

    // openssl_pkey_new — one finding per call, classified by its key-type config.
    eachMatch(RE_PHP_PKEY_NEW, content, (m) => {
      const info = classifyPkeyNew(content, m.index);
      findings.push(
        findingFromRule(
          RULE_PHP_KEYGEN,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `PHP openssl ${info.label} key generation`,
            category: info.cat,
            severity: info.sev,
            algorithm: info.algo,
            hndl: info.hndl,
            message: `Generates a classical ${info.label} key pair via PHP openssl_pkey_new — not quantum-safe.`,
            ...(info.remediation ? { remediation: info.remediation } : {}),
          },
        ),
      );
    });

    add(RE_PHP_RSA_CRYPT, RULE_PHP_RSA_CRYPT);
    add(RE_PHP_SIGN, RULE_PHP_SIGN);

    // phpseclib3 ::createKey — classify by the class (RSA/EC/DSA/DH).
    eachMatch(RE_PHP_SECLIB, content, (m) => {
      const info = SECLIB_INFO[m[1]];
      findings.push(
        findingFromRule(
          RULE_PHP_SECLIB,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `PHP phpseclib ${info.label} key generation`,
            category: info.cat,
            severity: info.sev,
            algorithm: info.algo,
            hndl: info.hndl,
            message: `Generates a classical ${info.label} key pair via phpseclib3 createKey — not quantum-safe.`,
            ...(info.remediation ? { remediation: info.remediation } : {}),
          },
        ),
      );
    });

    add(RE_PHP_SODIUM_X25519, RULE_PHP_SODIUM_X25519);
    add(RE_PHP_SODIUM_ED25519, RULE_PHP_SODIUM_ED25519);
    return findings;
  },
};
