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

/**
 * Extract the host from a manifest line, matching {@link parseTarget}'s host
 * normalization so a manifest entry and a target reduce to the SAME host string.
 * Handles `host`, `host:port`, bracketed IPv6 `[::1]` / `[::1]:443`, and bare IPv6
 * `2001:db8::1`. (Previously IPv6 lines kept their brackets/port or were truncated
 * at the first colon, so no IPv6 endpoint could ever match the manifest.)
 */
function manifestHost(line: string): string {
  if (line.startsWith("[")) {
    const end = line.indexOf("]");
    return end < 0 ? line : line.slice(1, end); // [ipv6] or [ipv6]:port -> ipv6
  }
  const idx = line.lastIndexOf(":");
  // Exactly one ':' -> host:port. Multiple ':' with no brackets -> bare IPv6 (no port).
  if (idx >= 0 && line.indexOf(":") === idx) return line.slice(0, idx);
  return line;
}

/** Parse an ownership manifest file's text into a host allow-list. */
export function parseOwnedHosts(text: string): string[] {
  return (
    text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l !== "" && !l.startsWith("#"))
      // A manifest line may be `host` or `host:port` (IPv6 bracketed or bare);
      // ownership is per host, normalized the same way targets are.
      .map(manifestHost)
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
