import { readFileSync } from "node:fs";
import type { CheckId } from "./checks.js";

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
}

export interface PayloadFinding {
  rule?: string;
  severity?: string;
  file?: string;
  line?: number;
  message?: string;
}

/** The dispatch context the platform sends when it triggers a run. */
export interface DispatchContext {
  auditRunId: string;
  token: string;
  resultUrl: string;
  /** The repository_dispatch event_type, which names the check that was asked for. */
  eventType: string | null;
}

/** Cap matching the server's own truncation, so we never post more than it keeps. */
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
    location?: { file?: string; line?: number };
  }[],
): PayloadFinding[] {
  return findings.slice(0, MAX_FINDINGS).map((f) => ({
    ...(f.ruleId ? { rule: f.ruleId } : {}),
    ...(f.severity ? { severity: f.severity } : {}),
    ...(f.location?.file ? { file: f.location.file } : {}),
    ...(typeof f.location?.line === "number" ? { line: f.location.line } : {}),
    ...(f.title ? { message: f.title } : {}),
  }));
}

/** A scored check (qScan, qProbe): score plus findings. */
export function scoredResult(
  check: CheckId,
  tool: string,
  score: number | null,
  findings: readonly Parameters<typeof toPayloadFindings>[0][number][],
): Omit<ResultPayload, "auditRunId" | "token"> {
  const n = findings.length;
  return {
    status: "complete",
    score,
    summary: `${tool}: ${n} finding(s), readiness ${score ?? "?"}/100`,
    findings: toPayloadFindings(findings),
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
            `conformance. First error: ${failing[0]?.message ?? "unknown"}. Point conformance-impl ` +
            `(currently: ${impl || "unset"}) at a real executable in this repository, in ${workflowPath}.`,
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
    });
    return res.ok;
  } catch {
    return false;
  }
}
