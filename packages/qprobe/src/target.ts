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

  // Range / sweep / list markers are refused BEFORE any parsing.
  if (raw.includes("/")) {
    throw new TargetError(
      `refusing CIDR block "${raw}" — qProbe probes one host at a time, not ranges.`,
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
