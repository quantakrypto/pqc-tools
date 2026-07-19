/**
 * @quantakrypto/qprobe — active post-quantum readiness probing of live TLS/SSH
 * endpoints you OWN. The programmatic API. See THREAT-MODEL.md for the
 * authorization model; {@link runProbe} refuses to touch the network until
 * {@link authorizeTargets} passes.
 *
 * Findings are `@quantakrypto/core` Findings, so they compose with qScan output
 * and score through the same `buildInventory`.
 */
import type { CryptoInventory, Finding } from "@quantakrypto/core";
import { buildInventory } from "@quantakrypto/core";
import type { Target } from "./target.js";
import { authorizeTargets, type AttestationInput } from "./attest.js";
import {
  probeTlsNegotiated,
  probeHybridSupport,
  type TlsNegotiated,
  type HybridSupport,
} from "./tls.js";
import { probeSsh, type SshProbeResult } from "./ssh.js";
import { probeSmtpStartTls } from "./smtp.js";
import { probeLineStartTls, IMAP_DIALOG, POP3_DIALOG } from "./starttls.js";
import { probePostgresSsl } from "./postgres.js";
import { classifyTls, classifySsh } from "./classify.js";

export type { Target } from "./target.js";
export { parseTarget, TargetError } from "./target.js";
export {
  authorizeTargets,
  parseOwnedHosts,
  AttestationError,
  type AttestationInput,
} from "./attest.js";
// Only TYPES from the network modules are public — the socket-opening functions
// (probeTlsNegotiated / probeHybridSupport / probeSsh) are intentionally NOT
// re-exported, so `runProbe` (which authorizes first) is the sole public entry
// that performs network I/O. This keeps the THREAT-MODEL invariant true at the
// package API boundary, not just in the CLI.
export type { TlsNegotiated, HybridSupport } from "./tls.js";
export type { SshProbeResult, KexInit } from "./ssh.js";
export { PQ_SSH_KEX } from "./ssh.js";
export * from "./clienthello.js"; // pure byte codec — no network
export { certSignatureAlgorithm, decodeOid, oidToSignatureFamily } from "./x509.js"; // pure DER parse
export { smtpAdvertisesStartTls, smtpReplyComplete } from "./smtp.js"; // pure SMTP reply framing
export { classifyTls, classifySsh } from "./classify.js";
export { toScanResult, toSarifReport, toCbomReport, toJsonReport } from "./report.js";

export type ProbeMode = "tls" | "ssh" | "smtp" | "imap" | "pop3" | "postgres";

/** Re-export the pure STARTTLS/SSLRequest builders for testing (not the probes). */
export { IMAP_DIALOG, POP3_DIALOG } from "./starttls.js";
export { sslRequestFrame } from "./postgres.js";

export interface EndpointReport {
  target: Target;
  mode: ProbeMode;
  tls?: TlsNegotiated;
  hybrid?: HybridSupport;
  ssh?: SshProbeResult;
  /** Human-readable positive signals (good news), e.g. hybrid TLS selected. */
  positives: string[];
  findings: Finding[];
}

/**
 * Choose a probe mode for "auto" from the well-known port: SSH on 22, SMTP
 * STARTTLS on 25/587, IMAP on 143, POP3 on 110, PostgreSQL on 5432, TLS otherwise
 * (which covers direct-TLS services like HTTPS 443, IMAPS 993, and DoT 853).
 */
export function resolveMode(target: Target, mode: ProbeMode | "auto"): ProbeMode {
  if (mode !== "auto") return mode;
  if (target.port === 22) return "ssh";
  if (target.port === 25 || target.port === 587) return "smtp";
  if (target.port === 143) return "imap";
  if (target.port === 110) return "pop3";
  if (target.port === 5432) return "postgres";
  return "tls";
}

/**
 * Probe a single endpoint. INTERNAL — not exported, because it performs network
 * I/O without checking authorization; only {@link runProbe} (which authorizes
 * first) may reach it. Assumes authorization has already been granted.
 */
async function probeEndpoint(
  target: Target,
  mode: ProbeMode,
  opts: { servername?: string; timeoutMs?: number } = {},
): Promise<EndpointReport> {
  const positives: string[] = [];
  if (mode === "ssh") {
    const ssh = await probeSsh(target.host, target.port, opts.timeoutMs);
    if (ssh.pqKexOffered) positives.push("PQC SSH key exchange offered");
    return { target, mode, ssh, positives, findings: classifySsh(target, ssh) };
  }
  if (mode === "smtp" || mode === "imap" || mode === "pop3" || mode === "postgres") {
    // Upgrade to TLS via the protocol's own mechanism (STARTTLS / STLS / SSLRequest),
    // then the same negotiated inspection. No hybrid probe over an upgraded socket, so
    // classify with an "inconclusive" hybrid result rather than claim we tested a
    // hybrid group we never advertised.
    let tls: TlsNegotiated;
    if (mode === "smtp") tls = await probeSmtpStartTls(target.host, target.port, opts);
    else if (mode === "imap")
      tls = await probeLineStartTls(target.host, target.port, IMAP_DIALOG, opts);
    else if (mode === "pop3")
      tls = await probeLineStartTls(target.host, target.port, POP3_DIALOG, opts);
    else tls = await probePostgresSsl(target.host, target.port, opts);
    const hybrid: HybridSupport = { hybridSelected: false, error: `not probed (${mode})` };
    return { target, mode, tls, hybrid, positives, findings: classifyTls(target, tls, hybrid) };
  }
  const [tls, hybrid] = await Promise.all([
    probeTlsNegotiated(target.host, target.port, opts),
    probeHybridSupport(target.host, target.port, opts),
  ]);
  if (hybrid.hybridSelected) positives.push("PQC-hybrid TLS (X25519MLKEM768) selected");
  return { target, mode, tls, hybrid, positives, findings: classifyTls(target, tls, hybrid) };
}

export interface RunOptions {
  targets: Target[];
  mode: ProbeMode | "auto";
  attest: AttestationInput;
  servername?: string;
  timeoutMs?: number;
  /** Minimum spacing between endpoint connections (politeness / rate-limit). */
  minIntervalMs?: number;
}

export interface RunResult {
  reports: EndpointReport[];
  findings: Finding[];
  inventory: CryptoInventory;
}

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Authorize (throws {@link AttestationError} / {@link TargetError} on failure — no
 * network I/O happens before a successful authorization) then probe every target
 * sequentially with a minimum interval between connections.
 */
export async function runProbe(opts: RunOptions): Promise<RunResult> {
  authorizeTargets(opts.targets, opts.attest); // gate — throws before any connection

  const reports: EndpointReport[] = [];
  const interval = opts.minIntervalMs ?? 250;
  for (let i = 0; i < opts.targets.length; i++) {
    if (i > 0 && interval > 0) await delay(interval);
    const target = opts.targets[i];
    const mode = resolveMode(target, opts.mode);
    reports.push(
      await probeEndpoint(target, mode, { servername: opts.servername, timeoutMs: opts.timeoutMs }),
    );
  }
  const findings = reports.flatMap((r) => r.findings);
  return { reports, findings, inventory: buildInventory(findings) };
}
