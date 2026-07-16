/**
 * Config detector: classical KEY-MANAGEMENT (JWE) algorithms in JOSE. This is
 * distinct from the JWS signature side (RS256/ES256, handled elsewhere) and from
 * the JWK key-material detector: here we flag the `alg` values that wrap a
 * content-encryption key with classical asymmetric crypto, because the encrypted
 * payload is CONFIDENTIALITY — harvest-now-decrypt-later exposed. A JWE token
 * captured today (from a log, an audit trail, a stored assertion) is decryptable
 * once the wrapping key falls to a CRQC.
 *
 * Covered `alg` (RFC 7518 §4) values:
 *  - `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5`  → RSA key encryption.
 *  - `ECDH-ES`, `ECDH-ES+A128KW`, …        → classical EC Diffie-Hellman key agreement.
 *
 * These exact strings are JOSE identifiers, so a content-level match is precise;
 * the detector applies to any file (config, JSON, source) after a fast reject.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule } from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

interface JoseRule {
  re: RegExp;
  meta: RuleMeta;
}

const JOSE_RULES: JoseRule[] = [
  {
    re: /"alg"\s*:\s*"RSA(?:-OAEP(?:-256)?|1_5)"/g,
    meta: {
      id: "jose-jwe-rsa",
      title: "JWE RSA key wrapping",
      description: 'JWE "alg" of RSA-OAEP / RSA-OAEP-256 / RSA1_5 (RFC 7518)',
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "JWE wraps the content-encryption key with classical RSA (RSA-OAEP/RSA1_5); the encrypted payload is harvest-now-decrypt-later exposed.",
      remediation:
        "Plan migration to a post-quantum KEM (ML-KEM-768) for key wrapping as JOSE/COSE PQ algorithms are standardised.",
    },
  },
  {
    re: /"alg"\s*:\s*"ECDH-ES(?:\+A\d{3}KW)?"/g,
    meta: {
      id: "jose-jwe-ecdh",
      title: "JWE ECDH-ES key agreement",
      description: 'JWE "alg" of ECDH-ES / ECDH-ES+A*KW (RFC 7518)',
      category: "key-exchange",
      severity: "high",
      confidence: "high",
      algorithm: "ECDH",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "JWE derives the content-encryption key via classical ECDH-ES; the encrypted payload is harvest-now-decrypt-later exposed.",
      remediation:
        "Plan migration to hybrid post-quantum key agreement (X25519MLKEM768) as JOSE PQ algorithms are standardised.",
    },
  },
];

/** Detects classical JWE key-management (`alg`) values in JOSE tokens/config. */
export const joseDetector: Detector = {
  id: "jose-jwe-keymgmt",
  description: "Classical JWE key-management algorithms (RSA-OAEP, ECDH-ES) — confidentiality, HNDL",
  scope: "config",
  language: "any",
  rules: JOSE_RULES.map((r) => r.meta),
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    // Fast reject: no JOSE key-management alg token present.
    if (!content.includes("RSA-OAEP") && !content.includes("RSA1_5") && !content.includes("ECDH-ES")) {
      return [];
    }
    const findings: Finding[] = [];
    for (const rule of JOSE_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(
          findingFromRule(rule.meta, { file, content, index: m.index, matchLength: m[0].length }),
        );
      });
    }
    return findings;
  },
};
