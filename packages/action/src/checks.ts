/**
 * Which checks a run performs, and the configuration each one needs.
 *
 * The action used to run qScan and nothing else, so a repository that wanted
 * conformance or endpoint coverage committed two more workflow files, each
 * shelling out to `npx` and post-processing the JSON with inline `jq`. That put
 * the reporting logic in every user's repository, where we cannot fix it: a bug
 * in the jq is frozen into every repo that already committed it.
 *
 * One `checks` input replaces those files. The seven useful combinations are
 * just subsets of three, so there is nothing to enumerate.
 *
 * `checks` defaults to `scan`, which is exactly what v1 did, so an existing
 * workflow keeps working untouched.
 */

/** The checks this action can run. `scan` is qScan, and always available. */
export const CHECK_IDS = ["scan", "conformance", "probe"] as const;
export type CheckId = (typeof CHECK_IDS)[number];

export function isCheckId(value: string): value is CheckId {
  return (CHECK_IDS as readonly string[]).includes(value);
}

/**
 * Parse the `checks` input: comma- or space-separated ids, case-insensitive,
 * de-duplicated, order-preserving.
 *
 * Throws on an unknown id rather than ignoring it. Silently dropping a typo
 * would report a clean run for a check that never happened, which is the exact
 * failure mode this whole change exists to remove.
 */
export function parseChecks(raw: string): CheckId[] {
  const tokens = raw
    .split(/[\s,]+/)
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
  if (tokens.length === 0) return ["scan"];

  const out: CheckId[] = [];
  for (const token of tokens) {
    if (!isCheckId(token)) {
      throw new TypeError(
        `unknown check "${token}" — checks must be a subset of ${CHECK_IDS.join(", ")}`,
      );
    }
    if (!out.includes(token)) out.push(token);
  }
  return out;
}

/**
 * Reduce whatever was typed to the bare hostname qProbe expects.
 *
 * A full URL is the obvious thing to paste, and qProbe refuses it — correctly,
 * since `--i-own-this` is an ownership attestation and `https://mine@theirs.com`
 * resolves to `theirs.com`. Normalising here means the attestation still names
 * one host explicitly, and the host it names is the one that gets probed.
 */
export function normalizeProbeTarget(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    // `hostname` keeps IPv6 literals bracketed; qProbe wants the address itself.
    return new URL(withScheme).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return trimmed.split(/[/?#]/)[0]?.split("@").pop()?.split(":")[0] ?? trimmed;
  }
}

/**
 * Validate that every selected check has the configuration it needs, BEFORE any
 * of them run.
 *
 * Failing here rather than mid-run means a three-check workflow does not spend
 * two minutes scanning only to die on a missing probe target, and the message
 * names the input to set rather than surfacing a tool's own confusion about an
 * empty argument.
 */
export function assertCheckConfig(
  checks: readonly CheckId[],
  cfg: { probeTarget: string; conformanceImpl: string; probeIOwnThis?: boolean },
): void {
  const missing: string[] = [];
  if (checks.includes("probe") && !cfg.probeTarget.trim()) {
    missing.push('probe-target (a host you own, e.g. "api.example.com")');
  }
  if (checks.includes("probe") && cfg.probeIOwnThis === false) {
    // The attestation is the control. Refusing here means it is caught when the
    // workflow is written, not after a probe has already gone out.
    missing.push('i-own-this: "true" (you must attest you are authorised to probe that host)');
  }
  if (checks.includes("conformance") && !cfg.conformanceImpl.trim()) {
    missing.push('conformance-impl (how to run your implementation, e.g. "node ./impl.js")');
  }
  if (missing.length > 0) {
    throw new TypeError(`missing required input(s) for the selected checks: ${missing.join("; ")}`);
  }
}
