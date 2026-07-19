/**
 * Machine-readable cryptography policy → per-finding verdicts for the ISO/IEC
 * 27001 A.8.24 evidence report (docs/compliance/iso27001-a8.24-evidence.md §4).
 *
 * An organization supplies a policy listing which classical algorithm families it
 * prohibits, permits, or is actively transitioning off. `buildPolicyMapping` then
 * flags each qScan finding as `conformant` / `violation` / `transition-pending`
 * against that policy — turning the neutral inventory into audit-ready evidence
 * that the org *assesses* its cryptography against a defined policy.
 *
 * Honesty boundary: without a policy the report stays neutral inventory and the
 * ORG owns the conformance judgment (COMPLIANCE.md §3). The policy is a permit-
 * list: a classical family not named anywhere defaults to a violation (unmanaged
 * crypto is a policy gap), overridable via `defaultVerdict`.
 */
import type { AlgorithmFamily, Finding } from "./types.js";

/** The three verdicts a finding can carry against a policy. */
export type PolicyVerdict = "conformant" | "violation" | "transition-pending";

/** The complete set of algorithm families a policy may reference. */
const ALGORITHM_FAMILIES: readonly AlgorithmFamily[] = [
  "RSA",
  "ECDH",
  "ECDSA",
  "EdDSA",
  "DH",
  "DSA",
  "X25519",
  "X448",
  "ECIES",
  "unknown",
];

/** An organization-supplied cryptography policy (from a JSON file). */
export interface CryptoPolicy {
  /** Human name / version of the policy, recorded in the evidence report. */
  name?: string;
  /** Families the org explicitly accepts (e.g. short-lived signatures) → conformant. */
  permitted?: AlgorithmFamily[];
  /** Families the org prohibits outright → violation. */
  prohibited?: AlgorithmFamily[];
  /** Families being actively migrated, allowed within the window → transition-pending. */
  inTransition?: AlgorithmFamily[];
  /** Optional migration deadline (ISO date / year), recorded for context. */
  transitionDeadline?: string;
  /** Verdict for a family named in none of the lists. Default: `"violation"`. */
  defaultVerdict?: PolicyVerdict;
}

/** One finding's verdict against the policy. */
export interface PolicyFindingVerdict {
  ruleId: string;
  algorithm: AlgorithmFamily | "unknown";
  file: string;
  line: number;
  verdict: PolicyVerdict;
  reason: string;
}

/** The `policyMapping` block added to the evidence report. */
export interface PolicyMapping {
  policyName: string | null;
  transitionDeadline: string | null;
  summary: Record<PolicyVerdict, number>;
  findings: PolicyFindingVerdict[];
}

/** Resolve one algorithm family's verdict + a human reason against a policy. */
export function verdictForAlgorithm(
  algorithm: AlgorithmFamily | undefined,
  policy: CryptoPolicy,
): { verdict: PolicyVerdict; reason: string } {
  const algo = algorithm ?? "unknown";
  if (policy.prohibited?.includes(algo)) {
    return { verdict: "violation", reason: `${algo} is prohibited by the policy.` };
  }
  if (policy.inTransition?.includes(algo)) {
    return {
      verdict: "transition-pending",
      reason: `${algo} is being migrated (in the policy's transition set).`,
    };
  }
  if (policy.permitted?.includes(algo)) {
    return { verdict: "conformant", reason: `${algo} is permitted by the policy.` };
  }
  const fallback = policy.defaultVerdict ?? "violation";
  return {
    verdict: fallback,
    reason: `${algo} is not named in the policy (default verdict: ${fallback}).`,
  };
}

/**
 * Map every finding to a policy verdict, with per-verdict counts. Deterministic:
 * the same findings + policy always yield the same mapping (safe to hash in the
 * A.8.24 evidence attestation).
 */
export function buildPolicyMapping(
  findings: readonly Finding[],
  policy: CryptoPolicy,
): PolicyMapping {
  const summary: Record<PolicyVerdict, number> = {
    conformant: 0,
    violation: 0,
    "transition-pending": 0,
  };
  const mapped: PolicyFindingVerdict[] = findings.map((f) => {
    const { verdict, reason } = verdictForAlgorithm(f.algorithm, policy);
    summary[verdict]++;
    return {
      ruleId: f.ruleId,
      algorithm: f.algorithm ?? "unknown",
      file: f.location.file,
      line: f.location.line,
      verdict,
      reason,
    };
  });
  return {
    policyName: policy.name ?? null,
    transitionDeadline: policy.transitionDeadline ?? null,
    summary,
    findings: mapped,
  };
}

/**
 * Validate + normalize a parsed policy object (from an operator's JSON file).
 * Throws a `TypeError` with a clear message on anything malformed — a bad policy
 * file must fail loudly, never silently degrade the evidence verdict.
 */
export function parseCryptoPolicy(raw: unknown): CryptoPolicy {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError("crypto policy must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const validFamilies = new Set<string>(ALGORITHM_FAMILIES);
  const list = (key: string): AlgorithmFamily[] | undefined => {
    const v = obj[key];
    if (v === undefined) return undefined;
    if (!Array.isArray(v))
      throw new TypeError(`policy "${key}" must be an array of algorithm families`);
    for (const item of v) {
      if (typeof item !== "string" || !validFamilies.has(item)) {
        throw new TypeError(
          `policy "${key}" has an unknown algorithm family ${JSON.stringify(item)}; expected one of ${ALGORITHM_FAMILIES.join(", ")}`,
        );
      }
    }
    return v as AlgorithmFamily[];
  };
  const verdicts = new Set<PolicyVerdict>(["conformant", "violation", "transition-pending"]);
  let defaultVerdict: PolicyVerdict | undefined;
  if (obj.defaultVerdict !== undefined) {
    if (
      typeof obj.defaultVerdict !== "string" ||
      !verdicts.has(obj.defaultVerdict as PolicyVerdict)
    ) {
      throw new TypeError(`policy "defaultVerdict" must be one of ${[...verdicts].join(", ")}`);
    }
    defaultVerdict = obj.defaultVerdict as PolicyVerdict;
  }
  if (obj.name !== undefined && typeof obj.name !== "string") {
    throw new TypeError('policy "name" must be a string');
  }
  if (obj.transitionDeadline !== undefined && typeof obj.transitionDeadline !== "string") {
    throw new TypeError('policy "transitionDeadline" must be a string');
  }
  return {
    ...(obj.name !== undefined ? { name: obj.name as string } : {}),
    ...(list("permitted") ? { permitted: list("permitted") } : {}),
    ...(list("prohibited") ? { prohibited: list("prohibited") } : {}),
    ...(list("inTransition") ? { inTransition: list("inTransition") } : {}),
    ...(obj.transitionDeadline !== undefined
      ? { transitionDeadline: obj.transitionDeadline as string }
      : {}),
    ...(defaultVerdict !== undefined ? { defaultVerdict } : {}),
  };
}
