/**
 * Selectable STANDARDS PROFILES — the regime a scan's remediation, deadlines, and
 * hybrid guidance are tailored to. Different national/regional authorities agree on
 * the PQC primitives (ML-KEM / ML-DSA) but diverge on two things this tool must not
 * hardcode: (a) the required PARAMETER SETS (a commercial ML-KEM-768 vs a
 * national-security ML-KEM-1024), and (b) the HYBRID STANCE — whether classical+PQC
 * hybridization is required, recommended, or optional during the transition. Baking
 * in NIST/CNSA's "hybrids optional" is wrong for an ANSSI or BSI audience, where
 * hybrid is required. `--profile <id>` selects the regime; `--policy` composes an
 * org's own exceptions on top.
 *
 * Like {@link PqcStandards}, every profile carries a citation + `asOf` date and is
 * re-verified on the quarterly standards cadence. These are guidance summaries, not
 * legal advice — consult the cited source of record.
 */

/** Whether classical+PQC hybridization is required during the transition, per regime. */
export type HybridStance = "required" | "recommended" | "optional";

/** A regime's PQC guidance profile. */
export interface StandardsProfile {
  /** Stable id used by `--profile` (kebab-case). */
  readonly id: string;
  /** Human-readable name. */
  readonly name: string;
  /** The authority / document of record. */
  readonly authority: string;
  /** The KEM / signature parameter sets this regime calls for. */
  readonly paramSets: { readonly kem: string; readonly signature: string };
  /** Whether hybridization is required / recommended / optional under this regime. */
  readonly hybridStance: HybridStance;
  /** One-line regime-specific hybrid guidance surfaced in remediation. */
  readonly hybridGuidance: string;
  /** Year after which classical public-key crypto is deprecated under this regime. */
  readonly deprecateAfter: number;
  /** Year after which it is disallowed. */
  readonly disallowAfter: number;
  /** Spec identifier / publication of record. */
  readonly citation: string;
  /** `YYYY-MM` — when this profile was last verified against its source. */
  readonly asOf: string;
}

/** The default profile id when `--profile` is not given. */
export const DEFAULT_PROFILE_ID = "nist";

/**
 * Built-in regime profiles. Facts reflect each authority's published PQC-transition
 * position as of the `asOf` date; verify against the cited source before relying on a
 * deadline or a hybrid mandate for a compliance decision.
 */
export const STANDARDS_PROFILES: Readonly<Record<string, StandardsProfile>> = {
  nist: {
    id: "nist",
    name: "NIST (general / commercial)",
    authority: "NIST",
    paramSets: { kem: "ML-KEM-768 (FIPS 203)", signature: "ML-DSA-65 (FIPS 204)" },
    hybridStance: "recommended",
    hybridGuidance:
      "Hybrid key establishment (e.g. X25519MLKEM768) is permitted and recommended during the transition; pure ML-KEM is also acceptable (SP 800-227 / IR 8547).",
    deprecateAfter: 2030,
    disallowAfter: 2035,
    citation: "NIST IR 8547 + FIPS 203/204/205",
    asOf: "2026-07",
  },
  "cnsa-2.0": {
    id: "cnsa-2.0",
    name: "NSA CNSA 2.0 (national-security systems)",
    authority: "NSA",
    paramSets: { kem: "ML-KEM-1024 (FIPS 203)", signature: "ML-DSA-87 (FIPS 204)" },
    hybridStance: "optional",
    hybridGuidance:
      "CNSA 2.0 targets pure PQC and does not require hybrids; if a hybrid TLS group is used, it must be SecP384r1MLKEM1024 — X25519MLKEM768's ML-KEM-768 component is sub-CNSA.",
    deprecateAfter: 2030,
    disallowAfter: 2035,
    citation: "NSA CNSA 2.0 (2030/2033/2035 migration milestones)",
    asOf: "2026-07",
  },
  "bsi-tr-02102": {
    id: "bsi-tr-02102",
    name: "BSI TR-02102 (Germany)",
    authority: "BSI",
    paramSets: { kem: "ML-KEM-768 (FIPS 203)", signature: "ML-DSA-65 (FIPS 204)" },
    hybridStance: "required",
    hybridGuidance:
      "BSI requires PQC be deployed in HYBRID with an established classical scheme during the transition (defense-in-depth); FrodoKEM is the conservative KEM alternative to ML-KEM, and XMSS/LMS are approved for firmware signing.",
    deprecateAfter: 2030,
    disallowAfter: 2035,
    citation: "BSI TR-02102-1 (Kryptographische Verfahren)",
    asOf: "2026-07",
  },
  anssi: {
    id: "anssi",
    name: "ANSSI (France)",
    authority: "ANSSI",
    paramSets: { kem: "ML-KEM-1024 (FIPS 203)", signature: "ML-DSA-87 (FIPS 204)" },
    hybridStance: "required",
    hybridGuidance:
      "ANSSI requires HYBRIDIZATION (classical + PQC) throughout the transition phase and does not endorse pure PQC alone yet; use the highest parameter set for long-lived assurance.",
    deprecateAfter: 2030,
    disallowAfter: 2035,
    citation: "ANSSI — PQC transition position papers",
    asOf: "2026-07",
  },
  "uk-ncsc": {
    id: "uk-ncsc",
    name: "UK NCSC",
    authority: "NCSC",
    paramSets: { kem: "ML-KEM-768 (FIPS 203)", signature: "ML-DSA-65 (FIPS 204)" },
    hybridStance: "recommended",
    hybridGuidance:
      "NCSC recommends ML-KEM / ML-DSA and is broadly agnostic on hybridization (recommended, not mandated); its migration milestones are earlier — discovery/plan by 2028, high-priority migration by 2031, complete by 2035.",
    deprecateAfter: 2031,
    disallowAfter: 2035,
    citation: "NCSC — Preparing for quantum-safe cryptography / PQC migration timeline",
    asOf: "2026-07",
  },
};

/** All built-in profile ids, in a stable order (default first). */
export function standardsProfileIds(): string[] {
  return [
    DEFAULT_PROFILE_ID,
    ...Object.keys(STANDARDS_PROFILES).filter((id) => id !== DEFAULT_PROFILE_ID),
  ];
}

/** Look up a built-in profile by id, or `undefined` when unknown. */
export function getStandardsProfile(id: string): StandardsProfile | undefined {
  return STANDARDS_PROFILES[id];
}

/** The default profile (NIST). Always defined. */
export function defaultStandardsProfile(): StandardsProfile {
  return STANDARDS_PROFILES[DEFAULT_PROFILE_ID];
}
