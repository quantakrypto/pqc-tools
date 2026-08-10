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
 * Reduce an explicitly-written URL to the host qProbe expects. Anything else is
 * returned untouched, for qProbe's own parser to accept or refuse.
 *
 * A URL is the obvious thing to paste into `probe-target`, and `action.yml` has
 * always said one is accepted. It was not: this function existed, was exported,
 * was tested, and was never called, so `https://example.com` reached qProbe raw
 * and was refused. A blog repo probing `https://leonacosta.com` failed on every
 * run for that reason, reported as the generic "Check produced no valid report".
 *
 * Why the narrow rule, rather than normalising everything:
 *
 * An earlier version of this DID normalise everything, by prepending `https://`
 * to a bare string and reading the URL's host. That turned
 * `our-api.example.com@evil.test` into `evil.test`, so a reviewer reading the
 * committed workflow saw one host attested and a different host was probed.
 * `i-own-this` is an ownership attestation; the committed line has to name the
 * host that gets probed.
 *
 * So: only a string that already carries a scheme is treated as a URL, and only
 * when its authority has no userinfo. `https://mine@theirs.com` is refused for
 * the same reason as the bare form, rather than silently becoming `theirs.com`.
 * Everything else goes to `parseTarget` unchanged, which is still the single
 * enforcement point for "one host, named explicitly".
 */
export function normalizeProbeTarget(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  try {
    const url = new URL(trimmed);
    // Userinfo makes the probed host different from the one a reader sees first.
    // Hand it back untouched so parseTarget refuses it and says why.
    if (url.username || url.password) return trimmed;
    if (!url.hostname) return trimmed;
    // `hostname` keeps IPv6 literals bracketed. qProbe wants the bare address
    // when there is no port, and the bracketed form when there is: stripping
    // the brackets off `[2001:db8::1]:8443` would leave `2001:db8::1:8443`,
    // which qProbe reads as one long host with the default port.
    if (!url.port) return url.hostname.replace(/^\[|\]$/g, "");
    return `${url.hostname}:${url.port}`;
  } catch {
    return trimmed;
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
