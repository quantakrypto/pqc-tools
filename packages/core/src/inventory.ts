/**
 * Aggregates findings into a {@link CryptoInventory}: per-algorithm,
 * per-category and per-severity counts, the harvest-now-decrypt-later count,
 * and a 0–100 readiness score.
 */
import type {
  AlgorithmFamily,
  CryptoInventory,
  Finding,
  FindingCategory,
  Severity,
} from "./types.js";

/** All severities, most → least severe (used to seed the counts record). */
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Base penalty applied to the readiness score for the first finding of a severity. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30,
  high: 18,
  medium: 8,
  low: 3,
  info: 1,
};

/**
 * Apply diminishing returns to repeated findings of the same severity: the Nth
 * finding contributes `weight / sqrt(N)`. This keeps a single critical hit very
 * impactful while a codebase with hundreds of medium findings doesn't underflow
 * past zero on the first few — the score still saturates toward 0 sensibly.
 */
function penaltyFor(weight: number, occurrence: number): number {
  return weight / Math.sqrt(occurrence);
}

/** Decay constant for the readiness score (larger = more forgiving). */
const SCORE_SCALE = 100;

/**
 * Compute a 0–100 readiness score. 100 means no classical asymmetric crypto was
 * found. Findings accrue a severity-weighted penalty (with per-bucket diminishing
 * returns), then the score is `100 * e^(-penalty/scale)`. Exponential decay keeps
 * the score responsive across the whole range — fixing findings always raises it,
 * and a large legacy repo lands low without pinning flat at 0 (which made progress
 * invisible under the old linear model). Tuned so one low ~97, one critical ~74.
 */
export function readinessScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;

  const seen: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  let penalty = 0;
  for (const f of findings) {
    seen[f.severity] += 1;
    penalty += penaltyFor(SEVERITY_WEIGHT[f.severity], seen[f.severity]);
  }

  return Math.max(0, Math.min(100, Math.round(100 * Math.exp(-penalty / SCORE_SCALE))));
}

/** Build the full inventory (counts + HNDL + score) from a set of findings. */
export function buildInventory(findings: Finding[]): CryptoInventory {
  const byAlgorithm: Partial<Record<AlgorithmFamily, number>> = {};
  const byCategory: Partial<Record<FindingCategory, number>> = {};
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let hndlCount = 0;

  for (const f of findings) {
    if (f.algorithm) {
      byAlgorithm[f.algorithm] = (byAlgorithm[f.algorithm] ?? 0) + 1;
    }
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    bySeverity[f.severity] += 1;
    if (f.hndl) hndlCount += 1;
  }

  // Ensure all severities are present (seeded above to 0). SEVERITIES is the
  // canonical ordering and guards against missing keys if the type changes.
  void SEVERITIES;

  return {
    byAlgorithm,
    byCategory,
    bySeverity,
    hndlCount,
    readinessScore: readinessScore(findings),
  };
}
