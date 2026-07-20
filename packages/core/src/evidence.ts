/**
 * ISO/IEC 27001:2022 Annex A 8.24 evidence-chain export
 * (docs/compliance/iso27001-a8.24-evidence.md).
 *
 * Emits a self-describing readiness report bundling the scan result, crypto
 * inventory, and CycloneDX CBOM, plus an attestation carrying a DETERMINISTIC
 * content hash — the same scan over the same commit + config yields the same
 * hash (the volatile scan timestamp is deliberately excluded from the hashed
 * body). Signing + RFC-3161 timestamping are left to an EXTERNAL, vetted signer
 * (ADR-0004: this project performs no cryptography itself — it orchestrates a
 * signer, it does not implement one). SHA-256 here is an integrity hash (a Node
 * built-in), not an asymmetric primitive.
 *
 * Honesty boundary: this artifact is EVIDENCE for A.8.24, not the control. The
 * organization still owns the cryptography policy, key management, and the
 * conformance judgment. A clean scan is the absence of detected candidates, not
 * proof of quantum-safety (qScan is lexical). See docs/COMPLIANCE.md §3.
 */
import { createHash } from "node:crypto";

import type { ScanResult } from "./types.js";
import { toCbom } from "./cbom.js";
import { VERSION } from "./version.js";
import { buildPolicyMapping } from "./policy.js";
import type { CryptoPolicy, PolicyMapping } from "./policy.js";

/** Stable per-finding record for the evidence body (deterministic per commit). */
export interface EvidenceFinding {
  ruleId: string;
  algorithm?: string;
  severity: string;
  hndl: boolean;
  file: string;
  line: number;
}

export interface ReadinessReport {
  reportType: "quantakrypto-readiness";
  specVersion: 1;
  subject: {
    repository: string | null;
    commit: string | null;
    scannedRoot: string;
    scanTimeUtc: string;
  };
  tool: { name: "qScan"; version: string };
  inventory: ScanResult["inventory"];
  findings: EvidenceFinding[];
  /** §4 policy verdicts, present only when a crypto policy was supplied. */
  policyMapping?: PolicyMapping;
  cbom: unknown;
  attestation: {
    /** sha256 over the canonicalized deterministic body (excludes scanTimeUtc). */
    contentHash: string;
    /**
     * RFC-3161 / transparency-log token over `contentHash`, produced by an EXTERNAL
     * timestamper (opaque string, e.g. base64). `null` until {@link signReadinessReport}
     * runs one.
     */
    timestamp: string | null;
    /**
     * Detached signature over `contentHash`, produced by an EXTERNAL signer (opaque
     * string, e.g. base64/PEM). `null` until {@link signReadinessReport} runs one.
     */
    signature: string | null;
    /** Non-sensitive provenance label of the signer (e.g. "openssl", "cosign"). */
    signedWith?: string;
    /** Non-sensitive provenance label of the timestamper (e.g. "openssl-ts"). */
    timestampedWith?: string;
  };
}

/** Canonical JSON: object keys sorted recursively, so the hash is reproducible. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = canonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

export interface ReadinessReportOptions {
  /** Repository URL (e.g. from `GITHUB_REPOSITORY`); omitted → null. */
  repository?: string;
  /** Full commit SHA (e.g. from `GITHUB_SHA`); omitted → null. */
  commit?: string;
  /** Optional org cryptography policy — adds the §4 `policyMapping` verdicts. */
  policy?: CryptoPolicy;
}

/**
 * Build the A.8.24 readiness report for a scan result. The attestation's
 * `contentHash` covers everything EXCEPT the scan timestamp and the attestation
 * block itself, so re-running the same scan on the same commit is verifiable.
 */
export function buildReadinessReport(
  result: ScanResult,
  opts: ReadinessReportOptions = {},
): ReadinessReport {
  const findings: EvidenceFinding[] = result.findings.map((f) => ({
    ruleId: f.ruleId,
    ...(f.algorithm ? { algorithm: f.algorithm } : {}),
    severity: f.severity,
    hndl: f.hndl,
    file: f.location.file,
    line: f.location.line,
  }));

  // The CBOM is a deterministic *view* of the (hashed) findings + inventory, but
  // its CycloneDX envelope carries a volatile timestamp/serial — so it is
  // EXCLUDED from the hashed body (its integrity follows from its hashed inputs)
  // to keep the content hash reproducible across scan runs on the same commit.
  // §4: if the org supplied a crypto policy, attest the per-finding verdicts too.
  // Deterministic (same findings + policy → same mapping), so it is hashed.
  const policyMapping = opts.policy ? buildPolicyMapping(result.findings, opts.policy) : undefined;

  const hashableBody = {
    reportType: "quantakrypto-readiness",
    specVersion: 1,
    subject: {
      repository: opts.repository ?? null,
      commit: opts.commit ?? null,
      scannedRoot: result.root,
    },
    tool: { name: "qScan", version: VERSION },
    inventory: result.inventory,
    findings,
    ...(policyMapping ? { policyMapping } : {}),
  };
  const contentHash =
    "sha256:" +
    createHash("sha256")
      .update(JSON.stringify(canonicalize(hashableBody)))
      .digest("hex");

  return {
    ...hashableBody,
    subject: { ...hashableBody.subject, scanTimeUtc: result.finishedAt },
    cbom: toCbom(result),
    attestation: { contentHash, timestamp: null, signature: null },
  } as ReadinessReport;
}

/**
 * An EXTERNAL signer/timestamper the tool orchestrates. Per ADR-0004 the tool
 * implements no cryptography: it hands the payload to an operator-provided signer
 * (an `openssl`/`cosign` invocation, an RFC-3161 TSA client, …) and records what
 * comes back. `label` is a short, non-sensitive provenance string (e.g. the signer
 * program name) — NOT the full command, which may contain a key path.
 */
export interface EvidenceSigner {
  label: string;
  /**
   * Produce a detached signature / timestamp token (opaque string) over `payload`.
   * May be async so a future signer can shell out OR call a KMS / RFC-3161 TSA over
   * the network without foreclosing that once this contract freezes at 1.0.
   */
  sign(payload: string): string | Promise<string>;
}

/** Options for {@link signReadinessReport}: a detached-signature and/or a timestamp signer. */
export interface SignEvidenceOptions {
  signer?: EvidenceSigner;
  timestamper?: EvidenceSigner;
}

/**
 * Fill a readiness report's attestation with a detached signature and/or RFC-3161
 * timestamp, produced by EXTERNAL signers over the report's `contentHash`. Pure
 * orchestration: it invokes the injected signers and records their opaque output
 * plus a provenance label — it performs no cryptography itself (ADR-0004). Returns a
 * NEW report; the hashed body is untouched (attestation is excluded from the hash),
 * so signing never changes `contentHash`.
 */
export async function signReadinessReport(
  report: ReadinessReport,
  opts: SignEvidenceOptions,
): Promise<ReadinessReport> {
  const payload = report.attestation.contentHash;
  const signature = opts.signer ? await opts.signer.sign(payload) : report.attestation.signature;
  const timestamp = opts.timestamper
    ? await opts.timestamper.sign(payload)
    : report.attestation.timestamp;
  return {
    ...report,
    attestation: {
      ...report.attestation,
      signature,
      timestamp,
      ...(opts.signer ? { signedWith: opts.signer.label } : {}),
      ...(opts.timestamper ? { timestampedWith: opts.timestamper.label } : {}),
    },
  };
}
