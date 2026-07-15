/**
 * Config detector: classical key material in JSON Web Keys (JWK / JWKS, RFC 7517
 * / 7518). JWKs appear in `.json` / `.jwks` files, OIDC discovery documents, and
 * config — a real key-material surface the source packs (which look at *code*)
 * and the PEM detector (which looks at PEM markers) both miss.
 *
 * Detection keys off the JWK's distinctive JSON fields:
 *  - `"kty":"RSA"`                          → classical RSA key.
 *  - `"crv":"P-256"|"P-384"|"P-521"|…`      → classical EC key (ECDSA + ECDH).
 *  - `"crv":"Ed25519"|"Ed448"`              → EdDSA signing key.
 *  - `"crv":"X25519"|"X448"`                → classical Montgomery-curve key agreement.
 *
 * Keying EC/OKP off `crv` (present in every EC/OKP JWK) rather than `kty` avoids
 * double-counting a single key, and `"kty"`/`"crv"` are specific enough to RFC
 * 7517 that the false-positive risk on ordinary JSON is low.
 *
 * HNDL: RSA and (EC)DH / X25519 / X448 key agreement are harvest-now-decrypt-later
 * exposed (hndl:true); EdDSA signing keys are hndl:false but forgeable. A JWKS is
 * usually PUBLIC keys, so severity is medium — the exposure is a classical key
 * pair, not necessarily an embedded secret.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

interface JwkRule {
  re: RegExp;
  meta: RuleMeta;
}

const JWK_RULES: JwkRule[] = [
  {
    re: /"kty"\s*:\s*"RSA"/g,
    meta: {
      id: "jwk-rsa",
      title: "RSA JSON Web Key (JWK)",
      description: 'JWK with "kty":"RSA" (RFC 7518)',
      category: "certificate",
      severity: "medium",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: "RSA JSON Web Key (JWK); classical RSA, not quantum-safe.",
      remediation: "Re-issue with PQC keys (ML-KEM-768 for encryption, ML-DSA-65 for signatures).",
    },
  },
  {
    re: /"crv"\s*:\s*"(?:P-256K?|P-384|P-521|secp256k1)"/g,
    meta: {
      id: "jwk-ec",
      title: "EC JSON Web Key (JWK)",
      description: 'JWK with an "crv" naming a NIST/secp curve (RFC 7518)',
      category: "key-exchange",
      severity: "medium",
      confidence: "high",
      algorithm: "ECDH",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Elliptic-curve JSON Web Key (JWK); a classical EC key feeds BOTH ECDSA signatures and ECDH key agreement — the ECDH path is harvest-now-decrypt-later exposed.",
      remediation:
        "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
    },
  },
  {
    re: /"crv"\s*:\s*"Ed(?:25519|448)"/g,
    meta: {
      id: "jwk-eddsa",
      title: "EdDSA JSON Web Key (JWK)",
      description: 'JWK OKP key with "crv":"Ed25519"/"Ed448" (RFC 8037)',
      category: "signature",
      severity: "low",
      confidence: "high",
      algorithm: "EdDSA",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "EdDSA (Ed25519/Ed448) JSON Web Key (JWK); classical and forgeable by a quantum attacker.",
      remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
    },
  },
  {
    re: /"crv"\s*:\s*"X(?:25519|448)"/g,
    meta: {
      id: "jwk-xdh",
      title: "X25519/X448 JSON Web Key (JWK)",
      description: 'JWK OKP key with "crv":"X25519"/"X448" (RFC 8037)',
      category: "key-exchange",
      severity: "medium",
      confidence: "high",
      algorithm: "X25519",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "X25519/X448 JSON Web Key (JWK); modern but classical key agreement, and harvest-now-decrypt-later exposed.",
      remediation: "Migrate key agreement to hybrid X25519MLKEM768 (ML-KEM-768).",
    },
  },
];

/** Detects classical JSON Web Key (JWK/JWKS) material in any JSON/text file. */
export const jwkDetector: Detector = {
  id: "jwk-material",
  description: "Classical key material in JSON Web Keys (JWK / JWKS)",
  scope: "config",
  language: "any",
  rules: JWK_RULES.map((r) => r.meta),
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    // Fast reject: a JWK always has one of these two members.
    if (!content.includes('"kty"') && !content.includes('"crv"')) return [];
    const findings: Finding[] = [];
    for (const rule of JWK_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(
          findingFromRule(rule.meta, {
            file,
            content,
            index: m.index,
            matchLength: m[0].length,
          }),
        );
      });
    }
    return findings;
  },
};
