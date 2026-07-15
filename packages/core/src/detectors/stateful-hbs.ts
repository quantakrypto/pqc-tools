/**
 * Config / source-agnostic detector: stateful hash-based signatures
 * (NIST SP 800-208) — LMS, HSS, XMSS and XMSSMT.
 *
 * These schemes ARE quantum-safe and NIST-approved (SP 800-208, for firmware /
 * secure-boot signing), so this is NOT a "broken crypto" finding. The hazard it
 * flags is STATE MANAGEMENT: each private key holds a bounded set of one-time
 * key indices, and reusing an index is catastrophic (it enables signature
 * forgery). The detector therefore surfaces the usage so a reviewer can confirm
 * rigorous state handling exists — or migrate to a stateless scheme.
 *
 * Like {@link pemDetector}, this is a `scope: "config"`, `language: "any"`
 * detector that runs on every text file, because the distinctive LMS/XMSS
 * parameter strings and library tokens (`LMS_SHA256_M32_H10`, `pyhsslms`,
 * `XMSS-SHA2_10_256`, …) appear identically across languages, config, and docs.
 * Every rule's metadata lives in the {@link RuleMeta} declaration below; the
 * regexes are tightly bounded and `\b`-anchored to stay high-signal.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule } from "../detect-utils.js";
import { CWE_RISKY_PRIMITIVE } from "../cwe.js";

/**
 * Shared remediation for every stateful-HBS finding: these are approved but
 * STATEFUL, so the reviewer must confirm state management before trusting them.
 */
const STATEFUL_HBS_REMEDIATION =
  "LMS/HSS/XMSS/XMSSMT are NIST-approved (SP 800-208) but STATEFUL: the signer " +
  "must NEVER reuse a one-time key index (reuse enables signature forgery). Use " +
  "only with rigorous, crash-safe state management; otherwise prefer the " +
  "stateless ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).";

/** A stateful-HBS rule: its catalog metadata plus the token regex that triggers it. */
interface HbsRule {
  /** Global regex matching the distinctive token. */
  re: RegExp;
  meta: RuleMeta;
}

const HBS_RULES: HbsRule[] = [
  {
    // LMS parameter set, e.g. LMS_SHA256_M32_H10 / LMS_SHAKE_M24_H10 (SP 800-208
    // adds SHAKE256 and the 192-bit M24/N24 sets to RFC 8554's SHA-256 sets).
    re: /\bLMS_(?:SHA256|SHAKE(?:256)?)_[MN]\d+_[HW]\d+\b/g,
    meta: {
      id: "stateful-hbs-lms-param",
      title: "LMS parameter set (stateful hash-based signature)",
      description: "LMS/HSS one-time-signature parameter string (SP 800-208)",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message:
        "LMS parameter set — NIST-approved (SP 800-208) but STATEFUL: reusing a one-time key index is catastrophic.",
      remediation: STATEFUL_HBS_REMEDIATION,
    },
  },
  {
    // HSS keygen (hierarchical LMS), e.g. pyhsslms.hss_generate_private_key(...).
    re: /\bhss_generate_private_key\b/g,
    meta: {
      id: "stateful-hbs-hss-keygen",
      title: "HSS private-key generation (stateful hash-based signature)",
      description: "HSS (hierarchical LMS) private-key generation call (SP 800-208)",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message:
        "HSS private-key generation — NIST-approved (SP 800-208) but STATEFUL: never reuse a one-time key index.",
      remediation: STATEFUL_HBS_REMEDIATION,
    },
  },
  {
    // pyhsslms — the Python LMS/HSS library import token.
    re: /\bpyhsslms\b/g,
    meta: {
      id: "stateful-hbs-pyhsslms",
      title: "pyhsslms library (stateful LMS/HSS signatures)",
      description: "Reference to the pyhsslms LMS/HSS library (SP 800-208)",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message:
        "pyhsslms (LMS/HSS) — NIST-approved (SP 800-208) but STATEFUL: the signer must never reuse a one-time key index.",
      remediation: STATEFUL_HBS_REMEDIATION,
    },
  },
  {
    // XMSS parameter set, e.g. XMSS-SHA2_10_256 / XMSS-SHAKE256_10_192 (SP 800-208
    // adds the SHAKE256 and 192-bit variants to RFC 8391's SHA-2/256 sets).
    re: /\bXMSS-(?:SHA2|SHAKE(?:256)?)_\d+_(?:192|256)\b/g,
    meta: {
      id: "stateful-hbs-xmss-param",
      title: "XMSS parameter set (stateful hash-based signature)",
      description: "XMSS one-time-signature parameter string (SP 800-208)",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message:
        "XMSS parameter set — NIST-approved (SP 800-208) but STATEFUL: reusing a one-time key index is catastrophic.",
      remediation: STATEFUL_HBS_REMEDIATION,
    },
  },
  {
    // XMSSMT (multi-tree XMSS) parameter set, e.g. XMSSMT-SHA2_20/2_256 or the
    // SP 800-208 SHAKE256 variant XMSSMT-SHAKE256_20/2_256.
    re: /\bXMSSMT-(?:SHA2|SHAKE(?:256)?)_\d+\b/g,
    meta: {
      id: "stateful-hbs-xmssmt-param",
      title: "XMSSMT parameter set (stateful hash-based signature)",
      description: "XMSSMT (multi-tree XMSS) parameter string (SP 800-208)",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message:
        "XMSSMT parameter set — NIST-approved (SP 800-208) but STATEFUL: never reuse a one-time key index.",
      remediation: STATEFUL_HBS_REMEDIATION,
    },
  },
  {
    // XMSS keypair generation, e.g. xmss_keypair(...) (liboqs / xmss reference).
    re: /\bxmss_keypair\b/g,
    meta: {
      id: "stateful-hbs-xmss-keypair",
      title: "XMSS keypair generation (stateful hash-based signature)",
      description: "XMSS keypair-generation call (SP 800-208)",
      category: "signature",
      severity: "medium",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message:
        "XMSS keypair generation — NIST-approved (SP 800-208) but STATEFUL: the signer must never reuse a one-time key index.",
      remediation: STATEFUL_HBS_REMEDIATION,
    },
  },
];

/** Detects stateful hash-based signature (SP 800-208) usage in arbitrary files. */
export const statefulHbsDetector: Detector = {
  id: "stateful-hbs",
  description:
    "Stateful hash-based signatures (NIST SP 800-208: LMS / HSS / XMSS / XMSSMT) in any file",
  scope: "config",
  language: "any",
  rules: HBS_RULES.map((r) => r.meta),
  // Applies to every text file; the walker already filters out binaries.
  appliesTo: () => true,
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    for (const rule of HBS_RULES) {
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
