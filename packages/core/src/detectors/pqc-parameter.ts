/**
 * Config/any-scope detector: post-quantum KEM parameter / size sanity checks.
 *
 * WHY THIS LIVES IN A PQC-READINESS TOOL.
 * The rest of qScan flags *classical* crypto that must migrate to PQC. This
 * detector is the mirror image: it inspects code that has ALREADY reached for a
 * post-quantum KEM and flags two ways that migration can be quietly wrong —
 * using a *pre-standard* Kyber while claiming FIPS 203, and an internally
 * *inconsistent* parameter set (a byte size that names one ML-KEM/Kyber level
 * while the code advertises a different one). Neither is "quantum-broken", but
 * both defeat the point of migrating: a round-3 Kyber is not interoperable with
 * (nor validated as) FIPS 203 ML-KEM, and a size/level mismatch is a latent bug
 * or a mislabelled security claim. Both rules are `category: "kem"`,
 * `hndl: false` (this is about a PQC primitive's correctness, not a classical
 * confidentiality secret exposed to harvest-now-decrypt-later).
 *
 * RULE 1 — `pqc-prestandard-kem` (medium).
 * Curated identifiers for the well-known PRE-FIPS-203, round-3 CRYSTALS-Kyber
 * packages and APIs (the `pqc_kyber` / `pqcrypto-kyber` / `safe_pqc_kyber` /
 * `crystals-kyber` crates & npm packages, the reference `crypto_kem_kyber768_*`
 * / `pqcrystals_kyber*` API, and the round-3 `Kyber512/768/1024` parameter
 * names). These are NOT ML-KEM: FIPS 203 changed the KDF/domain separation and
 * the algorithm names, so a `Kyber768` build is not a `ML-KEM-768` build. The
 * finding names the exact identifier matched. Confidence starts LOW (using a
 * round-3 Kyber may be a deliberate, documented choice) and is RAISED when the
 * same file also makes a FIPS-203 / ML-KEM / NIST claim — the strong signal that
 * pre-standard Kyber is being passed off as the standard.
 *
 * RULE 2 — `pqc-parameter-mismatch` (medium, LOWER confidence, deliberately
 * conservative). A curated table of the distinctive ML-KEM / Kyber byte sizes:
 *   512  → pk 800,  sk 1632            (ct 768 is intentionally omitted: it
 *                                       collides with the level number 768)
 *   768  → pk 1184, sk 2400, ct 1088
 *   1024 → pk 1568, sk 3168            (pk and ct are both 1568)
 * The rule fires ONLY when a file (already in a Kyber / ML-KEM context) contains
 * one of these exact sizes as a standalone integer AND advertises a DIFFERENT
 * parameter level in text (`ML-KEM-1024`, `Kyber-1024`, …) AND does NOT also
 * advertise the size's own level. So `pk = 1184` (an ML-KEM-768 public key) in a
 * file that calls itself `ML-KEM-1024` fires; a file that mentions both 768 and
 * 1024 (a multi-parameter module) stays silent. Otherwise silent.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
} from "../detect-utils.js";

// --- Rule 1: pre-standard round-3 Kyber identifiers -----------------------------
// Package / crate names for the round-3 CRYSTALS-Kyber implementations that
// predate FIPS 203 ML-KEM (Rust crates, npm packages, Python bindings).
const RE_KYBER_PKG =
  /\b(?:pqc[_-]?kyber|pqcrypto[_-]kyber|safe_pqc_kyber|crystals[_-]kyber|kyber[_-]crystals|py[_-]?kyber)\b/gi;
// The reference-implementation C API and its language wrappers.
const RE_KYBER_API = /\b(?:crypto_kem_kyber(?:512|768|1024)|pqcrystals_kyber(?:512|768|1024))\w*/gi;
// Round-3 parameter names — distinct from the FIPS 203 `ML-KEM-512/768/1024`.
const RE_KYBER_PARAM = /\bKyber-?(?:512|768|1024)\b/gi;
// The generic project name.
const RE_CRYSTALS_KYBER = /\bCRYSTALS[_-]?Kyber\b/gi;

const PRESTANDARD_RES: readonly RegExp[] = [
  RE_KYBER_PKG,
  RE_KYBER_API,
  RE_KYBER_PARAM,
  RE_CRYSTALS_KYBER,
];

/** A FIPS-203 / ML-KEM / NIST claim in the same file — the confidence booster. */
const RE_STANDARD_CLAIM = /\bFIPS[\s-]?203\b|\bML-?KEM\b|\bNIST\b/i;

const RULE_PRESTANDARD: RuleMeta = {
  id: "pqc-prestandard-kem",
  title: "Pre-standard (round-3) Kyber, not FIPS 203 ML-KEM",
  description:
    "A pre-FIPS-203, round-3 CRYSTALS-Kyber package/parameter set used where FIPS 203 ML-KEM is intended",
  category: "kem",
  severity: "medium",
  confidence: "low",
  algorithm: "unknown",
  hndl: false,
  message:
    "Uses pre-standard round-3 Kyber; this is not FIPS 203 ML-KEM (different KDF/domain separation and not interoperable). Migrate to a FIPS 203 ML-KEM implementation.",
  remediation:
    "Replace the round-3 Kyber dependency with a FIPS 203 ML-KEM implementation (e.g. ML-KEM-768 / hybrid X25519MLKEM768) and re-run KATs against the FIPS 203 vectors.",
};

// --- Rule 2: ML-KEM / Kyber size ↔ parameter-level mismatch ----------------------
/** Distinctive ML-KEM/Kyber byte sizes → the parameter level they belong to. */
const SIZE_TO_LEVEL: ReadonlyMap<number, 512 | 768 | 1024> = new Map([
  [800, 512],
  [1632, 512],
  [1184, 768],
  [2400, 768],
  [1088, 768],
  [1568, 1024],
  [3168, 1024],
]);
// Standalone integer tokens for the distinctive sizes (never inside a longer
// number or a decimal), so `11840` / `1.088` don't match.
const RE_SIZE = /(?<![\d.])(800|1632|1184|2400|1088|1568|3168)(?![\d.])/g;
// An advertised parameter level: `ML-KEM-768`, `MLKEM768`, `Kyber-768`, `Kyber768`.
const RE_ADVERTISED_LEVEL = /(?:ML-?KEM|Kyber)-?(512|768|1024)\b/gi;

const RULE_MISMATCH: RuleMeta = {
  id: "pqc-parameter-mismatch",
  title: "ML-KEM/Kyber size does not match the advertised parameter set",
  description:
    "A ML-KEM/Kyber key or ciphertext byte size names one parameter level while the code advertises a different one",
  category: "kem",
  severity: "medium",
  confidence: "low",
  algorithm: "unknown",
  hndl: false,
  message:
    "A ML-KEM/Kyber byte size does not match the advertised parameter set — likely a mislabelled security level or a copied constant.",
};

/** Collect the distinct advertised parameter levels named in `content`. */
function advertisedLevels(content: string): Set<number> {
  const levels = new Set<number>();
  eachMatch(RE_ADVERTISED_LEVEL, content, (m) => levels.add(Number.parseInt(m[1], 10)));
  return levels;
}

/**
 * Detector: post-quantum KEM parameter / size checks. Fast-rejects any file that
 * does not mention Kyber or ML-KEM at all, so it never touches ordinary code.
 */
export const pqcParameterDetector: Detector = {
  id: "pqc-parameter",
  description:
    "Post-quantum KEM parameter checks: pre-standard round-3 Kyber, and ML-KEM/Kyber size ↔ parameter-set mismatch",
  scope: "config",
  language: "any",
  rules: [RULE_PRESTANDARD, RULE_MISMATCH],
  // Skip prose/docs: a design note discussing Kyber is not live code.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Fast reject: only files that actually reach for a Kyber / ML-KEM KEM.
    if (!/kyber|ml-?kem/i.test(content)) return [];

    // Mask comments so a commented-out identifier or a migration note can't fire.
    const scan = maskCommentLines(maskBlockComments(content), ["//", "#", ";"]);
    const findings: Finding[] = [];

    // Rule 1 — pre-standard round-3 Kyber identifiers. The FIPS-203/ML-KEM/NIST
    // *claim* is read from the ORIGINAL content (not the comment-masked copy): a
    // "FIPS 203 compliant" claim in a comment/docstring is exactly the mislabel
    // signal we want to boost confidence on.
    const claimPresent = RE_STANDARD_CLAIM.test(content);
    for (const re of PRESTANDARD_RES) {
      eachMatch(re, scan, (m) => {
        const id = m[0];
        findings.push(
          findingFromRule(
            RULE_PRESTANDARD,
            { file, content, index: m.index, matchLength: id.length },
            {
              // A co-located FIPS-203/ML-KEM/NIST claim is the strong signal that
              // pre-standard Kyber is being passed off as the standard.
              confidence: claimPresent ? "high" : "low",
              message: `Uses pre-standard round-3 Kyber (${id}); not FIPS 203 ML-KEM${
                claimPresent ? " despite a FIPS-203/ML-KEM/NIST claim in the same file" : ""
              }. Migrate to a FIPS 203 ML-KEM implementation.`,
            },
          ),
        );
      });
    }

    // Rule 2 — size ↔ advertised-level mismatch (conservative). The advertised
    // parameter level is read from the ORIGINAL content, since it is very often a
    // comment/docstring label (`// ML-KEM-1024 key sizes`) sitting above the
    // constant. The SIZE token itself is read from the masked copy, so a
    // commented-out constant can't fire. Only meaningful when a level is advertised.
    const advertised = advertisedLevels(content);
    if (advertised.size > 0) {
      // Dedupe by (size,line) so the same constant isn't reported twice.
      const seen = new Set<string>();
      eachMatch(RE_SIZE, scan, (m) => {
        const size = Number.parseInt(m[0], 10);
        const level = SIZE_TO_LEVEL.get(size);
        if (level === undefined) return;
        // Silent when the size's own level is also advertised (a multi-parameter
        // file), or when nothing conflicting is advertised.
        if (advertised.has(level)) return;
        const conflict = [...advertised].find((l) => l !== level);
        if (conflict === undefined) return;
        const key = `${size}:${m.index}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push(
          findingFromRule(
            RULE_MISMATCH,
            { file, content, index: m.index, matchLength: m[0].length },
            {
              message: `Byte size ${size} matches ML-KEM-${level} but the code advertises ML-KEM-${conflict}; parameter-set mismatch (mislabelled level or a copied constant).`,
            },
          ),
        );
      });
    }

    return findings;
  },
};
