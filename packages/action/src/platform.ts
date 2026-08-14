import { readFileSync } from "node:fs";

import { fingerprintFinding } from "@quantakrypto/core";

/**
 * Reporting a check result back to quantakrypto.com.
 *
 * This is the code that used to live as `jq` inside every user's workflow file.
 * That was the real defect behind everything else: the payload logic sat in
 * repositories we do not control, so fixing it fixed nothing that was already
 * committed. A conformance run whose implementation could not be started was
 * reported as ~35 high-severity crypto defects, and correcting the jq only
 * changed what NEW repositories would generate.
 *
 * Moving it here makes it versioned, tested, and fixed for everyone on their
 * next run. Nothing in the user's workflow decides what a result means.
 */

/** The payload POSTed to /api/github/scan-result. */
export interface ResultPayload {
  auditRunId: string;
  token: string;
  /** `complete` = a verdict was reached. `failed` = the check did not produce one. */
  status: "complete" | "failed";
  /** 0-100 for scored checks, null for pass/fail ones. */
  score: number | null;
  summary: string;
  findings: PayloadFinding[];
  /**
   * Every algorithm the scan found, safe and unsafe, grouped and posture-classified.
   *
   * Sent because "what cryptography do we use" is a different question from
   * "what is wrong with it", and the platform could only ever answer the second.
   * A repository that had migrated correctly looked identical to one using no
   * cryptography at all: both showed nothing and 100/100.
   *
   * Absent on a check that has no inventory to report (conformance, probe) and
   * on any run from a version of the action that predates it, so the platform
   * has to treat missing and empty as different.
   */
  assets?: PayloadAsset[];
}

/** One algorithm in use, with how much of it there is and a few example sites. */
export interface PayloadAsset {
  algorithm: string;
  kind: string;
  posture: string;
  count: number;
  locations: { file: string; line?: number }[];
}

export interface PayloadFinding {
  rule?: string;
  severity?: string;
  file?: string;
  line?: number;
  message?: string;
  /**
   * Stable identity for this finding across runs.
   *
   * The same SHA-256 of (rule, file, normalized snippet) that the baseline uses,
   * deliberately excluding line and column so an unrelated edit that shifts code
   * up or down a file does not resurface a finding as new.
   *
   * The platform needs it to say anything durable about a specific finding:
   * "this one is accepted risk until March", "this one is the same one you saw
   * last week". Without it the platform falls back to rule + path, which breaks
   * the moment the code moves file and cannot tell two hits of one rule in one
   * file apart.
   */
  fingerprint?: string;
  /**
   * What to do about it.
   *
   * Every detector already produces this, either explicitly or derived from the
   * algorithm family, and it is in the JSON report and the SARIF `help` text.
   * It was not in this payload, so the platform showed people a list of
   * problems and no next step, while the tool that found them knew one all
   * along. "Your readiness is 97, here is why, here is what raises it" is the
   * whole job; without this the platform could only do the first two thirds.
   */
  remediation?: string;
}

/**
 * The only origin a result may be posted to.
 *
 * `resultUrl` arrives in the dispatch payload, and firing a repository_dispatch
 * needs `contents: write` — which any repo collaborator has. Without this pin,
 * whoever composes that payload chooses where a token-bearing POST lands: plain
 * http, or an arbitrary host, or (on a self-hosted runner) an address inside the
 * private network. Pinning turns an SSRF primitive into a fixed destination.
 */
export const RESULT_ORIGIN = "https://quantakrypto.com";

/** How long to wait for the platform before giving up on a report. */
const POST_TIMEOUT_MS = 10_000;

/**
 * Is this a result URL we are willing to send a credential to?
 *
 * https only, and only our own origin. Exported so the rule is testable and so
 * there is exactly one place it lives.
 */
export function isAllowedResultUrl(raw: string): boolean {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && url.origin === RESULT_ORIGIN;
  } catch {
    return false;
  }
}

/** The dispatch context the platform sends when it triggers a run. */
export interface DispatchContext {
  auditRunId: string;
  token: string;
  resultUrl: string;
  /** The repository_dispatch event_type, which names the check that was asked for. */
  eventType: string | null;
}

/**
 * Cap on posted findings. The server keeps up to 500, so this is our own limit,
 * not its truncation point — chosen to match what the jq it replaces posted, so
 * a repository sees the same number of findings before and after the migration.
 */
const MAX_FINDINGS = 200;

/**
 * Read the dispatch context from the workflow event payload.
 *
 * Returns null for any run that was not started by the platform — a push, a pull
 * request, a manual `workflow_dispatch`. Those are ordinary CI runs and must not
 * try to report anywhere; the action still gates the build exactly as before.
 */
export function readDispatchContext(env: NodeJS.ProcessEnv = process.env): DispatchContext | null {
  const path = env["GITHUB_EVENT_PATH"];
  if (!path) return null;
  // Only a repository_dispatch carries a platform payload. Nothing else should
  // be able to present one, and narrowing here costs nothing.
  if (env["GITHUB_EVENT_NAME"] && env["GITHUB_EVENT_NAME"] !== "repository_dispatch") return null;
  try {
    const event = JSON.parse(readFileSync(path, "utf8")) as {
      action?: unknown;
      client_payload?: { auditRunId?: unknown; token?: unknown; resultUrl?: unknown };
    };
    const p = event.client_payload;
    if (!p) return null;
    const auditRunId = typeof p.auditRunId === "string" ? p.auditRunId : "";
    const token = typeof p.token === "string" ? p.token : "";
    const resultUrl = typeof p.resultUrl === "string" ? p.resultUrl : "";
    // All three are required to report. A partial payload is not a half-report,
    // it is a run we cannot attribute, so we stay quiet rather than guess.
    if (!auditRunId || !token || !resultUrl) return null;
    // Refuse to carry the token anywhere but our own origin over https.
    if (!isAllowedResultUrl(resultUrl)) return null;
    return {
      auditRunId,
      token,
      resultUrl,
      eventType: typeof event.action === "string" ? event.action : null,
    };
  } catch {
    return null;
  }
}

/** qScan/qProbe findings → the payload shape, capped. */
export function toPayloadFindings(
  findings: readonly {
    ruleId?: string;
    severity?: string;
    title?: string;
    remediation?: string;
    location?: { file?: string; line?: number; snippet?: string };
  }[],
): PayloadFinding[] {
  return findings.slice(0, MAX_FINDINGS).map((f) => ({
    ...(f.ruleId ? { rule: f.ruleId } : {}),
    ...(f.severity ? { severity: f.severity } : {}),
    ...(f.location?.file ? { file: f.location.file } : {}),
    ...(typeof f.location?.line === "number" ? { line: f.location.line } : {}),
    ...(f.title ? { message: f.title } : {}),
    ...(f.remediation ? { remediation: f.remediation } : {}),
    ...(fingerprintOf(f) ? { fingerprint: fingerprintOf(f) } : {}),
  }));
}

/**
 * The finding's baseline fingerprint, when we have enough to compute one.
 *
 * Reuses core's `fingerprintFinding` rather than hashing here, so the id the
 * platform stores is the SAME id `qscan --write-baseline` produces. One
 * identity for a finding across CI and the dashboard, not two that agree until
 * one of them is edited.
 *
 * qProbe findings have no snippet; the hash is still stable for them because
 * the rule and the target host are.
 */
function fingerprintOf(f: {
  ruleId?: string;
  location?: { file?: string; snippet?: string };
}): string | undefined {
  if (!f.ruleId || !f.location?.file) return undefined;
  return fingerprintFinding({
    ruleId: f.ruleId,
    location: { file: f.location.file, snippet: f.location.snippet },
  } as Parameters<typeof fingerprintFinding>[0]);
}

/** A scored check (qScan, qProbe): score plus findings. */
export function scoredResult(
  tool: string,
  score: number | null,
  findings: readonly Parameters<typeof toPayloadFindings>[0][number][],
  assets?: readonly PayloadAsset[],
): Omit<ResultPayload, "auditRunId" | "token"> {
  const n = findings.length;
  return {
    status: "complete",
    score,
    summary: `${tool}: ${n} finding(s), readiness ${score ?? "?"}/100`,
    findings: toPayloadFindings(findings),
    // Capped for the same reason the findings are: this is evidence, not a
    // dump. An inventory with more distinct algorithms than this is not a
    // repository, it is a corpus.
    ...(assets?.length ? { assets: assets.slice(0, MAX_ASSETS).map(toPayloadAsset) } : {}),
  };
}

/** Cap on distinct algorithms posted. */
const MAX_ASSETS = 100;

/** Trim an inventory asset to what the platform renders. */
function toPayloadAsset(a: PayloadAsset): PayloadAsset {
  return {
    algorithm: a.algorithm,
    kind: a.kind,
    posture: a.posture,
    count: a.count,
    // A few example sites, not every one: the count already carries the scale,
    // and the locations are only there so a reader can go and look.
    locations: (a.locations ?? []).slice(0, 5).map((l) => ({ file: l.file, line: l.line })),
  };
}

/** The Sieve report fields this module reads. Structural, so tests need no fixture plumbing. */
export interface SieveLike {
  param?: string;
  overall?: string;
  impl?: readonly string[];
  counts?: { pass?: number; fail?: number; skip?: number };
  categories?: readonly {
    category?: string;
    checks?: readonly { name?: string; status?: string; detail?: string }[];
  }[];
}

/**
 * Turn a Sieve report into a result.
 *
 * The important case is `overall === "ERROR"`, which Sieve reports when the
 * implementation under test could not be run at all. That is not a conformance
 * verdict, so it is posted as `failed`: the platform keeps such a run out of
 * badges and the posture series instead of recording ~35 invented defects. The
 * findings collapse to the one thing the owner can act on.
 *
 * `counts.pass === 0` is checked as well, so this stays correct against Sieve
 * versions released before the ERROR verdict existed.
 */
export function conformanceResult(
  report: SieveLike,
  workflowPath: string,
): Omit<ResultPayload, "auditRunId" | "token"> {
  const param = report.param ?? "?";
  const failing = (report.categories ?? []).flatMap((c) =>
    (c.checks ?? [])
      .filter((k) => k.status === "fail")
      .map((k) => ({
        rule: `${c.category ?? "?"}/${k.name ?? "?"}`,
        severity: "high",
        message: k.detail ?? "",
      })),
  );

  const neverRan = report.overall === "ERROR" || (report.counts?.pass ?? 0) === 0;
  if (neverRan && failing.length > 0) {
    const impl = (report.impl ?? []).join(" ");
    return {
      status: "failed",
      score: null,
      summary: `Sieve ${param}: could not run the implementation, no conformance verdict`,
      findings: [
        {
          rule: "harness/implementation-not-runnable",
          severity: "high",
          message:
            `Sieve could not run the implementation under test, so this run says nothing about ` +
            `conformance. First error: ${failing[0]?.message ?? "unknown"}.`,
          remediation:
            `Point conformance-impl (currently: ${impl || "unset"}) at a real executable in this ` +
            `repository, in ${workflowPath}, then re-run.`,
        },
      ],
    };
  }

  return {
    status: "complete",
    score: null,
    summary: `Sieve ${param}: ${report.overall ?? "?"}, ${failing.length} failing check(s)`,
    findings: failing.slice(0, MAX_FINDINGS),
  };
}

/** A check that threw before producing a report. */
export function crashedResult(
  tool: string,
  message: string,
): Omit<ResultPayload, "auditRunId" | "token"> {
  return {
    status: "failed",
    score: null,
    summary: `${tool} did not produce a result: ${message}`,
    findings: [],
  };
}

/**
 * POST a result. Returns whether it was accepted.
 *
 * Never throws: a reporting failure must not fail the user's build, because the
 * check itself already ran and its verdict is on the job summary either way.
 */
export async function postResult(
  ctx: DispatchContext,
  result: Omit<ResultPayload, "auditRunId" | "token">,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  const payload: ResultPayload = { auditRunId: ctx.auditRunId, token: ctx.token, ...result };
  try {
    const res = await fetchImpl(ctx.resultUrl, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "quantakrypto-action" },
      body: JSON.stringify(payload),
      // The token is in the BODY, so undici's cross-origin header stripping does
      // not protect it: a 307/308 re-sends method and body to the new origin
      // intact. Refusing redirects outright is the only thing that does.
      redirect: "error",
      // An unreachable endpoint must not burn the job's billed minutes up to
      // GitHub's six-hour ceiling.
      signal: AbortSignal.timeout(POST_TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}
