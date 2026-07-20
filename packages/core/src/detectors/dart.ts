/**
 * Source detector for classical asymmetric cryptography in Dart / Flutter.
 *
 * Dart has no asymmetric crypto in its standard library, so real-world code
 * reaches for one of the two dominant pub.dev packages, and both expose their
 * primitives through distinctive class names — which makes a lexical scan (the
 * same zero-dependency strategy as every other language pack here) precise:
 *
 *  - package:pointycastle (a Bouncy Castle port). RSA via `RSAKeyGenerator`,
 *    `RSAEngine`, `RSASigner`, `PSSSigner`; EC via `ECKeyGenerator`,
 *    `ECDSASigner`, `ECDHBasicAgreement`; Edwards via `Ed25519`.
 *  - package:cryptography (Dart-native). RSA via `RsaPss`, `RsaSsaPkcs1v15`;
 *    EC via `Ecdsa`, `Ecdh`; modern curves via `Ed25519`, `X25519`.
 *
 * HNDL (harvest-now-decrypt-later) reasoning — the field that drives urgency:
 *  - RSA encryption (`RSAEngine`) and RSA key generation (`RSAKeyGenerator`,
 *    which yields keys that can decrypt) are confidentiality surfaces → hndl:true.
 *  - (EC)DH key agreement (`ECDHBasicAgreement`, `Ecdh`, `X25519`) is the classic
 *    HNDL target — recorded ciphertext is decryptable once the curve falls → hndl:true.
 *  - Signatures (`RSASigner`/`PSSSigner`/`RsaPss`/`RsaSsaPkcs1v15`, `ECDSASigner`/
 *    `Ecdsa`, `Ed25519`) are forgeable by a quantum attacker but not retroactively
 *    breakable → hndl:false.
 *  - `ECKeyGenerator` is ambiguous (an EC key can feed either ECDSA or ECDH); it is
 *    classified conservatively as an ECDSA signing key (hndl:false), the Dart default.
 *
 * Comment suppression is C-style (`//` line + `/* … *\/` block), matching Dart's
 * lexer, so commented-out crypto is not reported. The regexes are `\b`-anchored on
 * the library-specific identifiers above; none matches a bare `RSA`/`EC` substring,
 * keeping false positives low. A cheap substring fast-reject skips the regex work on
 * the overwhelming majority of `.dart` files that touch no asymmetric crypto.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
  DART_EXTENSIONS,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// RSA key generation / raw RSA encryption engine (pointycastle). Both are
// confidentiality-capable (a keypair can decrypt; the engine encrypts) → kem.
const RE_DART_RSA_KEYGEN = /\b(?:RSAKeyGenerator|RSAEngine)\b/g;
// RSA signature schemes: pointycastle `RSASigner`/`PSSSigner`, cryptography
// `RsaPss`/`RsaSsaPkcs1v15`. Distinct casing keeps these off the keygen rule.
const RE_DART_RSA_SIGN = /\b(?:RSASigner|PSSSigner|RsaPss|RsaSsaPkcs1v15)\b/g;
// ECDSA signing + EC key generation. pointycastle `ECDSASigner`/`ECKeyGenerator`,
// cryptography `Ecdsa`. `\bEcdsa\b` requires a boundary, so `EcdsaP256`-style
// concatenations (rare) and the all-caps `ECDSASigner` don't double-fire here.
const RE_DART_ECDSA = /\b(?:ECDSASigner|ECKeyGenerator|Ecdsa)\b/g;
// ECDH key agreement: pointycastle `ECDHBasicAgreement`, cryptography `Ecdh`.
// `\bEcdh\b` cannot match inside `Ecdsa` (different letters), so no overlap.
const RE_DART_ECDH = /\b(?:ECDHBasicAgreement|Ecdh)\b/g;
// Ed25519 signer (both packages spell it `Ed25519`).
const RE_DART_ED25519 = /\bEd25519\b/g;
// X25519 key agreement (cryptography `X25519`).
const RE_DART_X25519 = /\bX25519\b/g;

// Cheap fast-reject: distinctive substrings that gate the (precise) regex work.
// If none is present the file cannot contain any of the tracked identifiers.
const DART_FAST_REJECT: readonly string[] = [
  "RSA",
  "Rsa",
  "ECDSA",
  "Ecdsa",
  "ECDH",
  "Ecdh",
  "ECKeyGenerator",
  "PSSSigner",
  "Ed25519",
  "X25519",
];

const RULE_DART_RSA_KEYGEN: RuleMeta = {
  id: "dart-rsa-keygen",
  title: "Dart RSA key generation / encryption",
  description: "pointycastle RSAKeyGenerator / RSAEngine",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical RSA key generation / encryption (Dart, pointycastle) is not quantum-safe and RSA encryption is harvest-now-decrypt-later exposed.",
  remediation:
    "Migrate to PQC (ML-KEM-768 for encryption / key transport) as Dart crypto packages add support.",
};
const RULE_DART_RSA_SIGN: RuleMeta = {
  id: "dart-rsa-sign",
  title: "Dart RSA signature",
  description: "pointycastle RSASigner/PSSSigner, cryptography RsaPss/RsaSsaPkcs1v15",
  category: "signature",
  severity: "medium",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA signature (Dart) is forgeable by a quantum attacker.",
  remediation:
    "Migrate to PQC signatures (ML-DSA-65, FIPS 204) as Dart crypto packages add support.",
};
const RULE_DART_ECDSA: RuleMeta = {
  id: "dart-ecdsa",
  title: "Dart ECDSA signature / EC key generation",
  description: "pointycastle ECDSASigner/ECKeyGenerator, cryptography Ecdsa",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing / EC key generation (Dart) is forgeable by a quantum attacker.",
  remediation:
    "Migrate to PQC signatures (ML-DSA-65, FIPS 204) as Dart crypto packages add support.",
};
const RULE_DART_ECDH: RuleMeta = {
  id: "dart-ecdh",
  title: "Dart ECDH key agreement",
  description: "pointycastle ECDHBasicAgreement, cryptography Ecdh",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman key agreement (Dart) is broken by Shor's algorithm (harvest-now-decrypt-later).",
  remediation:
    "Migrate key agreement to hybrid X25519MLKEM768 (ML-KEM-768) as Dart crypto packages add support.",
};
const RULE_DART_ED25519: RuleMeta = {
  id: "dart-ed25519",
  title: "Dart Ed25519 signature",
  description: "pointycastle / cryptography Ed25519 signer",
  category: "signature",
  // `low`, aligned with Ed25519 across the other source packs (swift/rust/go/…) —
  // the same primitive must not flip CI exit codes based on which language wrote it.
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Ed25519 (Dart) is a modern but still classical signature scheme, forgeable by a quantum attacker.",
  remediation:
    "Migrate to PQC signatures (ML-DSA-65, FIPS 204) as Dart crypto packages add support.",
};
const RULE_DART_X25519: RuleMeta = {
  id: "dart-x25519",
  title: "Dart X25519 key agreement",
  description: "cryptography X25519 key agreement",
  category: "key-exchange",
  severity: "medium",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "X25519 (Dart) is modern but still classical key agreement — harvest-now-decrypt-later exposed.",
  remediation:
    "Migrate key agreement to hybrid X25519MLKEM768 (ML-KEM-768) as Dart crypto packages add support.",
};

/** Detects classical asymmetric crypto in Dart / Flutter (pointycastle, cryptography). */
export const dartDetector: Detector = {
  id: "dart-crypto",
  description: "Classical asymmetric crypto in Dart / Flutter (pointycastle, cryptography)",
  scope: "source",
  language: "dart",
  rules: [
    RULE_DART_RSA_KEYGEN,
    RULE_DART_RSA_SIGN,
    RULE_DART_ECDSA,
    RULE_DART_ECDH,
    RULE_DART_ED25519,
    RULE_DART_X25519,
  ],
  appliesTo: (f) => hasExtension(f, DART_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Fast-reject: nothing to do unless a distinctive token appears.
    if (!DART_FAST_REJECT.some((t) => content.includes(t))) return [];

    // Suppress C-style comments so commented-out crypto isn't reported. Offsets
    // are preserved (chars → spaces), so finding line/column stay exact.
    const masked = maskCommentLines(maskBlockComments(content), ["//"]);

    const findings: Finding[] = [];
    // Scan the masked text, but build the finding (its snippet) from the ORIGINAL
    // `content` so a line with a trailing comment renders live, not blanked.
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, masked, (m) =>
        findings.push(
          findingFromRule(rule, {
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        ),
      );
    add(RE_DART_RSA_KEYGEN, RULE_DART_RSA_KEYGEN);
    add(RE_DART_RSA_SIGN, RULE_DART_RSA_SIGN);
    add(RE_DART_ECDSA, RULE_DART_ECDSA);
    add(RE_DART_ECDH, RULE_DART_ECDH);
    add(RE_DART_ED25519, RULE_DART_ED25519);
    add(RE_DART_X25519, RULE_DART_X25519);
    return findings;
  },
};
