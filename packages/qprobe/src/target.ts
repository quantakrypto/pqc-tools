/**
 * Target parsing + validation. qProbe opens real network connections, so the
 * FIRST job is to refuse anything that looks like a scan of infrastructure the
 * operator has not named one host at a time: CIDR blocks, IP ranges, wildcards,
 * and comma-separated lists are rejected outright (see THREAT-MODEL.md). A target
 * is exactly one `host` or `host:port`.
 */

/** A single validated endpoint. */
export interface Target {
  host: string;
  port: number;
}

export class TargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetError";
  }
}

/** IPv4 range in the last octet, e.g. `10.0.0.1-50`, or a full-range dash form. */
const IP_RANGE = /^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d{1,3}/;

/** A URI scheme prefix: `https://`, `ssh://`, `ldaps://`. */
const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/** A CIDR suffix proper: a slash followed by a prefix length and nothing else. */
const CIDR_SUFFIX = /\/\d{1,3}$/;

/**
 * The host someone probably meant, for the error message only.
 *
 * Never used to accept the input: a target has to be named as one host, because
 * `--i-own-this` is an ownership attestation and `https://mine.com@theirs.com/`
 * resolves to `theirs.com`. Suggesting the answer while still refusing keeps the
 * attestation explicit and the fix one copy-paste away.
 */
function suggestHost(raw: string): string | null {
  try {
    const url = new URL(SCHEME.test(raw) ? raw : `https://${raw}`);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    return host || null;
  } catch {
    return null;
  }
}

/**
 * Parse and validate a single target. Throws {@link TargetError} for anything
 * that is not a single host / host:port — the refusal is a security control, not
 * a convenience check.
 *
 * @param input   e.g. "example.com", "example.com:8443", "10.0.0.5:22"
 * @param defaultPort port to use when the input carries none
 */
export function parseTarget(input: string, defaultPort: number): Target {
  const raw = input.trim();
  if (raw === "") throw new TargetError("empty target");

  // A URL is still refused — a target is one named host, not something with a
  // scheme, credentials and a path — but it must be refused for the right reason.
  // This check has to come before the slash check below: `https://example.com`
  // contains slashes, so it used to be reported as a CIDR block, which described
  // a mistake the operator had not made.
  if (SCHEME.test(raw)) {
    const host = suggestHost(raw);
    throw new TargetError(
      `refusing URL "${raw}" — qProbe takes a host, not a URL${host ? `. Try: ${host}` : "."}`,
    );
  }

  // Credentials name one host to a reader and connect to another
  // (`https://mine.com@theirs.com`), which an ownership attestation cannot allow.
  if (raw.includes("@")) {
    const host = suggestHost(raw);
    throw new TargetError(
      `refusing target with credentials "${raw}" — name the host directly${host ? `. Try: ${host}` : "."}`,
    );
  }

  // Range / sweep / list markers are refused BEFORE any parsing.
  if (raw.includes("/")) {
    // Distinguish an actual CIDR block from a path someone pasted: only a
    // trailing prefix length is a range. Both are refused; only one is a sweep.
    if (CIDR_SUFFIX.test(raw)) {
      throw new TargetError(
        `refusing CIDR block "${raw}" — qProbe probes one host at a time, not ranges.`,
      );
    }
    const host = suggestHost(raw);
    throw new TargetError(
      `refusing target with a path "${raw}" — qProbe probes a host, not a URL path${host ? `. Try: ${host}` : "."}`,
    );
  }
  if (raw.includes("*")) {
    throw new TargetError(`refusing wildcard target "${raw}".`);
  }
  if (raw.includes(",")) {
    throw new TargetError(
      `refusing target list "${raw}" — pass one target per invocation / manifest line.`,
    );
  }
  if (/\s/.test(raw)) {
    throw new TargetError(`invalid target "${raw}" (whitespace).`);
  }
  if (IP_RANGE.test(raw)) {
    throw new TargetError(`refusing IP range "${raw}" — qProbe probes one host at a time.`);
  }

  // Split host:port (IPv6 in brackets is supported: [::1]:443).
  let host: string;
  let portStr: string | undefined;
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    if (end < 0) throw new TargetError(`invalid IPv6 target "${raw}" (missing ]).`);
    host = raw.slice(1, end);
    const rest = raw.slice(end + 1);
    if (rest.startsWith(":")) portStr = rest.slice(1);
    else if (rest !== "") throw new TargetError(`invalid target "${raw}".`);
  } else {
    const idx = raw.lastIndexOf(":");
    // A single ':' → host:port. Multiple ':' with no brackets → bare IPv6 (no port).
    if (idx >= 0 && raw.indexOf(":") === idx) {
      host = raw.slice(0, idx);
      portStr = raw.slice(idx + 1);
    } else {
      host = raw;
    }
  }

  if (host === "") throw new TargetError(`invalid target "${raw}" (empty host).`);

  let port = defaultPort;
  if (portStr !== undefined) {
    if (!/^\d+$/.test(portStr)) throw new TargetError(`invalid port "${portStr}" in "${raw}".`);
    port = Number(portStr);
    if (port < 1 || port > 65535) throw new TargetError(`port out of range in "${raw}".`);
  }

  return { host, port };
}
