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
 * Usage-aware classification: when a key's surrounding `"use"` / `"alg"` marks it
 * as a SIGNING key (`use:"sig"`, or an `RS`/`PS`/`ES` signature alg), the finding
 * is a `signature` (`hndl:false`) — a signing key is forgeable at a CRQC but not
 * harvest-now exposed. An encryption/unspecified key stays `hndl:true`.
 *
 * Deferrals to avoid double-counting: skipped on doc extensions (a README JWK
 * example is not live) and inside CloudFormation/ARM templates, where the
 * cloudformation detector owns the `kty` of a `Microsoft.KeyVault` key resource.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  enclosingObject,
  findingFromRule,
  hasExtension,
} from "../detect-utils.js";
import { isCloudTemplateFile } from "./cloudformation.js";
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

/**
 * True when THIS key's own object marks it as a signing key via `use`/`alg`. The
 * caller passes the enclosing `{…}` object so a neighbouring key in a JWKS array
 * can't contaminate the result, and an explicit `"use":"enc"` on the key always
 * wins (never classify an encryption key as a signature).
 */
function isSigningUse(objectText: string, sigAlg: RegExp): boolean {
  if (/"use"\s*:\s*"enc"/.test(objectText)) return false;
  return /"use"\s*:\s*"sig"/.test(objectText) || sigAlg.test(objectText);
}

const RSA_SIG_ALG = /"alg"\s*:\s*"(?:RS|PS)(?:256|384|512)"/;
const EC_SIG_ALG = /"alg"\s*:\s*"ES(?:256K?|384|512)"/;

/** Detects classical JSON Web Key (JWK/JWKS) material in any JSON/text file. */
export const jwkDetector: Detector = {
  id: "jwk-material",
  description: "Classical key material in JSON Web Keys (JWK / JWKS)",
  scope: "config",
  language: "any",
  rules: JWK_RULES.map((r) => r.meta),
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Fast reject: a JWK always has one of these two members.
    if (!content.includes('"kty"') && !content.includes('"crv"')) return [];
    // In a CloudFormation/ARM template FILE the cloudformation detector owns the key
    // resource `kty`; defer to it so a Key Vault key is not counted twice. (Gated to
    // the template extensions it actually scans, so a `.ts` that merely mentions a
    // marker string is still covered here.)
    if (isCloudTemplateFile(file, content)) return [];

    const findings: Finding[] = [];
    for (const rule of JWK_RULES) {
      eachMatch(rule.re, content, (m) => {
        const at = { file, content, index: m.index, matchLength: m[0].length };
        // Analyse the key's OWN enclosing object so a neighbouring key in a JWKS
        // array can't flip this key's sig/enc classification.
        const obj = enclosingObject(content, m.index);
        let overrides;
        if (rule.meta.id === "jwk-rsa" && isSigningUse(obj, RSA_SIG_ALG)) {
          overrides = {
            category: "signature" as const,
            hndl: false,
            message:
              "RSA JSON Web Key (JWK) used for signing (RS*/PS*); forgeable by a quantum attacker.",
          };
        } else if (rule.meta.id === "jwk-ec" && isSigningUse(obj, EC_SIG_ALG)) {
          overrides = {
            category: "signature" as const,
            algorithm: "ECDSA" as const,
            hndl: false,
            message:
              "Elliptic-curve JSON Web Key (JWK) used for ECDSA signing; forgeable by a quantum attacker.",
          };
        }
        findings.push(findingFromRule(rule.meta, at, overrides));
      });
    }
    return findings;
  },
};
