/**
 * Single source of truth for the post-quantum standards this tool depends on.
 *
 * The scanner's credibility rests on its recommendations tracking the current
 * NIST / CNSA / IETF state. That tracking used to be ad-hoc — facts were spread
 * across `remediation.ts` with no dates, no citations, and nothing to catch code
 * drifting from the published standards. This module makes the standards facts
 * explicit, dated, and cited, and the companion drift test
 * (`test/standards.test.ts`) fails the build if the runtime constants
 * (`TIER_PARAMS`, `PQC_TRANSITION_NOTE`, `STATEFUL_HBS_NOTE`) fall out of sync
 * with what is recorded here.
 *
 * ## Cadence
 *
 * Re-verify every quarter (see `docs/standards/pqc-standards.md` for the runbook).
 * On each review: check the sources below for changes, update the facts + their
 * `asOf`, and roll `lastReviewed` / `nextReview` forward. `scripts/standards-check.mjs`
 * (advisory, runs in CI) flags when `nextReview` has passed so a review can't be
 * silently skipped. `standardsReviewStatus(now)` is the pure predicate behind it.
 */

/** A single standards fact with its citation and when it was last verified. */
export interface StandardsCitation {
  /** One-line statement of the fact. */
  readonly summary: string;
  /** Spec identifier / publication (and URL where stable). */
  readonly source: string;
  /** `YYYY-MM` — when this fact was last verified against its source. */
  readonly asOf: string;
}

/** The full post-quantum standards snapshot the tool tracks. */
export interface PqcStandards {
  /** `YYYY-MM-DD` — when the whole snapshot was last reviewed. */
  readonly lastReviewed: string;
  /** `YYYY-MM-DD` — when the next review is due. */
  readonly nextReview: string;
  /** Cadence, in months, between reviews. */
  readonly reviewIntervalMonths: number;

  /** NIST's finalized PQC FIPS (the recommendation targets). */
  readonly fips: {
    readonly mlKem: StandardsCitation; // FIPS 203
    readonly mlDsa: StandardsCitation; // FIPS 204
    readonly slhDsa: StandardsCitation; // FIPS 205
  };

  /**
   * CNSA 2.0 security tiers → the KEM / signature parameter sets. These MUST
   * mirror `remediation.TIER_PARAMS`; the drift test asserts they stay identical.
   */
  readonly cnsa: {
    readonly category3: { readonly kem: string; readonly signature: string };
    readonly category5: { readonly kem: string; readonly signature: string };
    readonly source: string;
    readonly asOf: string;
  };

  /** Stateful hash-based signatures (firmware / boot signing). */
  readonly statefulHbs: StandardsCitation; // SP 800-208

  /** The migration deadline the transition note surfaces. */
  readonly transitionTimeline: {
    /** Year after which classical public-key crypto is deprecated. */
    readonly deprecateAfter: number;
    /** Year after which it is disallowed. */
    readonly disallowAfter: number;
    readonly source: string;
    readonly asOf: string;
  };

  /** Emerging / backup standards worth tracking beyond the current FIPS. */
  readonly emerging: readonly StandardsCitation[];

  /** Recommended hybrid key-exchange groups. */
  readonly hybrids: readonly StandardsCitation[];
}

/**
 * The current snapshot. Update on each quarterly review; the drift test keeps the
 * runtime remediation constants aligned with it.
 */
export const PQC_STANDARDS: PqcStandards = {
  lastReviewed: "2026-07-19",
  nextReview: "2026-10-19",
  reviewIntervalMonths: 3,

  fips: {
    mlKem: {
      summary: "ML-KEM (Kyber) key encapsulation — finalized August 2024.",
      source: "NIST FIPS 203",
      asOf: "2026-07",
    },
    mlDsa: {
      summary: "ML-DSA (Dilithium) lattice signatures — finalized August 2024.",
      source: "NIST FIPS 204",
      asOf: "2026-07",
    },
    slhDsa: {
      summary: "SLH-DSA (SPHINCS+) stateless hash-based signatures — finalized August 2024.",
      source: "NIST FIPS 205",
      asOf: "2026-07",
    },
  },

  cnsa: {
    category3: { kem: "ML-KEM-768 (FIPS 203)", signature: "ML-DSA-65 (FIPS 204)" },
    category5: { kem: "ML-KEM-1024 (FIPS 203)", signature: "ML-DSA-87 (FIPS 204)" },
    source: "NSA CNSA 2.0 (national-security systems; 2030/2033 migration milestones)",
    asOf: "2026-07",
  },

  statefulHbs: {
    summary:
      "LMS/HSS and XMSS/XMSSMT stateful hash-based signatures (incl. the SHAKE256 and " +
      "192-bit parameter sets) are approved for firmware/boot signing, but are STATEFUL.",
    source: "NIST SP 800-208",
    asOf: "2026-07",
  },

  transitionTimeline: {
    deprecateAfter: 2030,
    disallowAfter: 2035,
    source: "NIST IR 8547 (transition to post-quantum cryptography standards)",
    asOf: "2026-07",
  },

  emerging: [
    {
      summary:
        "HQC — NIST's code-based backup KEM (selected March 2025; draft FIPS expected ~2026), a " +
        "diversity hedge against ML-KEM's lattice assumption.",
      source: "NIST PQC (HQC selection)",
      asOf: "2026-07",
    },
    {
      summary: "FN-DSA / Falcon — compact lattice signatures.",
      source: "NIST draft FIPS 206",
      asOf: "2026-07",
    },
    {
      summary: "X-Wing — X25519 + ML-KEM-768 hybrid KEM for HPKE-style encryption.",
      source: "IETF draft-connolly-cfrg-xwing-kem",
      asOf: "2026-07",
    },
  ],

  hybrids: [
    {
      summary: "X25519MLKEM768 — the default TLS 1.3 hybrid key-exchange group.",
      source: "IETF draft-ietf-tls-ecdhe-mlkem",
      asOf: "2026-07",
    },
    {
      summary: "SecP384r1MLKEM1024 — the Category-5 / CNSA hybrid key-exchange group.",
      source: "IETF draft-ietf-tls-ecdhe-mlkem",
      asOf: "2026-07",
    },
  ],
};

/** Result of {@link standardsReviewStatus}. */
export interface StandardsReviewStatus {
  /** True when `now` is on or after `nextReview` — a review is due. */
  readonly due: boolean;
  /** The `nextReview` date being compared against (`YYYY-MM-DD`). */
  readonly nextReview: string;
  /** Whole days from `now` until `nextReview` (negative when overdue). */
  readonly daysUntil: number;
}

/**
 * Whether a standards review is due as of `now`. Pure (takes `now` explicitly) so
 * it is deterministic in tests; the CI script passes the real clock. Compares on
 * whole UTC days so a same-day run is not spuriously "overdue".
 */
export function standardsReviewStatus(
  now: Date,
  standards: PqcStandards = PQC_STANDARDS,
): StandardsReviewStatus {
  const MS_PER_DAY = 86_400_000;
  const next = Date.parse(`${standards.nextReview}T00:00:00Z`);
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const daysUntil = Math.round((next - today) / MS_PER_DAY);
  return { due: daysUntil <= 0, nextReview: standards.nextReview, daysUntil };
}
