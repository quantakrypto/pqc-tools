/**
 * Rule resolution for {@link explain_finding}.
 *
 * Core's detectors are coarse-grained: a single {@link Detector} (e.g. the
 * `crypto-libs` detector) emits many distinct `ruleId`s (`forge-rsa-keygen`,
 * `elliptic-ec`, `node-rsa`, …) that do NOT share the detector's `id` as a
 * prefix. The old MCP `explain_finding` matched `ruleId` against `detector.id`
 * by prefix and therefore returned "no matching detector" for every real
 * library finding (P0-5).
 *
 * This module resolves a finding's `ruleId` against core's rule catalog
 * ({@link defaultRegistry.ruleCatalog}) — the single source of truth declared by
 * the detectors themselves. There is no hand-curated table to keep in sync: the
 * ruleId → { detector, algorithm } mapping is derived from the catalog at load
 * time, so a new rule added in core is resolvable here the moment it ships. The
 * one non-detector rule (`dep-vulnerable`, produced by the manifest scanner
 * rather than a {@link Detector}) is supplemented explicitly. Unknown rules fall
 * back to a prefix match against the detector id space, then to unresolved.
 * Pure and synchronous — no I/O — so it is directly unit-testable.
 */

import { defaultRegistry, detectors } from "@quantakrypto/core";
import type { AlgorithmFamily, Detector, RuleMeta } from "@quantakrypto/core";

/** A resolved rule: the detector it belongs to (if any) and its algorithm. */
export interface ResolvedRule {
  /** The rule id that was looked up (echoed for convenience). */
  ruleId: string;
  /** The detector that emits this rule, when one could be resolved. */
  detector?: { id: string; description: string };
  /** The classical algorithm family the rule concerns, when known. */
  algorithm?: AlgorithmFamily;
  /** The catalog metadata for the rule, when it is a known core rule. */
  meta?: RuleMeta;
  /** How the match was made — useful for tests and diagnostics. */
  via: "index" | "detector-id" | "prefix" | "unresolved";
}

/**
 * Rules that are NOT emitted by a {@link Detector} and so are absent from the
 * catalog, but are still canonical core ruleIds. Today that is only the
 * dependency-manifest scanner's `dep-vulnerable` rule.
 */
const EXTRA_RULES: Record<string, { algorithm: AlgorithmFamily }> = {
  "dep-vulnerable": { algorithm: "unknown" },
};

/** Build an id → Detector lookup over the active detector set (registry first). */
function detectorMap(): Map<string, Detector> {
  const map = new Map<string, Detector>();
  const all = (() => {
    try {
      return defaultRegistry.all();
    } catch {
      return detectors;
    }
  })();
  for (const d of all) map.set(d.id, d);
  return map;
}

/**
 * Resolve a finding's `ruleId` to its detector and algorithm.
 *
 * Resolution order:
 *   1. The core rule catalog — the authoritative path for every detector rule.
 *   2. The {@link EXTRA_RULES} supplement (non-detector rules, e.g. dependencies).
 *   3. Exact detector id (a rule that IS a detector id, e.g. a future 1:1 rule).
 *   4. Prefix against the detector id space (`node-crypto-*`, `pem-*`, …).
 *   5. Unresolved — caller falls back to the algorithm remediation.
 *
 * Pure: depends only on its argument and the static core detector set.
 */
export function resolveRule(ruleId: string): ResolvedRule {
  const id = ruleId.trim();

  // 1. Catalog — the authoritative path for known core detector rules.
  const entry = (() => {
    try {
      return defaultRegistry.forRule(id);
    } catch {
      return undefined;
    }
  })();
  if (entry) {
    return {
      ruleId: id,
      detector: { id: entry.detector.id, description: entry.detector.description },
      algorithm: entry.rule.algorithm ?? "unknown",
      meta: entry.rule,
      via: "index",
    };
  }

  // 2. Non-detector supplement (dependency scanner, …).
  const extra = EXTRA_RULES[id];
  if (extra) {
    return { ruleId: id, algorithm: extra.algorithm, via: "index" };
  }

  const detectorsById = detectorMap();

  // 3. Exact detector id.
  const exact = detectorsById.get(id);
  if (exact) {
    return {
      ruleId: id,
      detector: { id: exact.id, description: exact.description },
      via: "detector-id",
    };
  }

  // 4. Longest-prefix detector id (e.g. `node-crypto-foo` → `node-crypto`).
  let best: Detector | undefined;
  for (const det of detectorsById.values()) {
    if (id === det.id || id.startsWith(`${det.id}-`)) {
      if (!best || det.id.length > best.id.length) best = det;
    }
  }
  if (best) {
    return {
      ruleId: id,
      detector: { id: best.id, description: best.description },
      via: "prefix",
    };
  }

  // 5. Unresolved.
  return { ruleId: id, via: "unresolved" };
}

/** Exposed for tests: the set of canonical rule ids resolvable via the catalog. */
export const KNOWN_RULE_IDS: readonly string[] = (() => {
  const ids: string[] = [];
  try {
    for (const r of defaultRegistry.ruleCatalog()) ids.push(r.id);
  } catch {
    // ignore — an empty/broken catalog just yields the supplement below.
  }
  ids.push(...Object.keys(EXTRA_RULES));
  return ids;
})();
