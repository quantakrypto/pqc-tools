/**
 * Ownership attestation — the first-class authorization gate for active probing.
 *
 * qProbe MUST NOT connect to an endpoint until the operator has attested they are
 * authorized to test it. Attestation comes from exactly one of:
 *   - `--i-own-this`            : an explicit per-run attestation for the target(s).
 *   - `--owned-hosts <file>`    : an ownership manifest (one host per line, `#`
 *                                 comments allowed); every target host must appear.
 *
 * With neither, {@link authorizeTargets} throws and NOTHING connects. This is a
 * code-enforced control, not a prompt: see THREAT-MODEL.md §Authorization.
 */
import type { Target } from "./target.js";

export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

export interface AttestationInput {
  /** `--i-own-this` was passed. */
  iOwnThis: boolean;
  /** Parsed contents of an ownership manifest, if `--owned-hosts` was given. */
  ownedHosts?: readonly string[];
}

/** Parse an ownership manifest file's text into a host allow-list. */
export function parseOwnedHosts(text: string): string[] {
  return (
    text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l !== "" && !l.startsWith("#"))
      // A manifest line may be `host` or `host:port`; ownership is per host.
      .map((l) => (l.startsWith("[") ? l : l.split(":")[0]))
  );
}

/**
 * Authorize a set of targets or throw {@link AttestationError}. Returns silently
 * when every target is covered by the attestation. No network I/O happens here or
 * anywhere upstream of a successful return.
 */
export function authorizeTargets(targets: readonly Target[], attest: AttestationInput): void {
  if (targets.length === 0) throw new AttestationError("no targets to authorize");

  if (attest.ownedHosts && attest.ownedHosts.length > 0) {
    const owned = new Set(attest.ownedHosts.map((h) => h.toLowerCase()));
    const missing = targets.filter((t) => !owned.has(t.host.toLowerCase()));
    if (missing.length > 0) {
      throw new AttestationError(
        `not authorized: ${missing.map((t) => t.host).join(", ")} not in the ownership manifest. ` +
          `Add the host(s) to the manifest, or pass --i-own-this only for endpoints you control.`,
      );
    }
    return;
  }

  if (attest.iOwnThis) return;

  throw new AttestationError(
    "refusing to probe: no ownership attestation. Pass --i-own-this (endpoints you control) " +
      "or --owned-hosts <manifest>. Active probing of endpoints you do not own may be unlawful; " +
      "see THREAT-MODEL.md.",
  );
}
