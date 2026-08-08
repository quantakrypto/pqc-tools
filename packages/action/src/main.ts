/**
 * quantakrypto Action entrypoint.
 *
 * Runs qScan over the repository, writes a SARIF (or JSON) report for GitHub
 * code scanning, annotates each finding inline, sets action outputs, optionally
 * comments a summary on the pull request, and fails the build when new
 * quantum-vulnerable cryptography lands.
 *
 * The scan, report rendering, and baseline live in `@quantakrypto/qscan` /
 * `@quantakrypto/core` so the Action and the CLI share one code path and one baseline
 * format — this module only adds the GitHub-runner glue (inputs, outputs,
 * annotations, PR comment, exit policy). The decision logic is factored into
 * small, pure functions so it can be tested without a real Actions environment.
 */

import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

import {
  applyBaseline,
  assertKnownMandates,
  evaluateMandates,
  fingerprintFinding,
  loadBaseline,
  mandateGateFails,
  meetsThreshold,
  parseCryptoPolicy,
  remediationFor,
  SEVERITY_ORDER,
} from "@quantakrypto/core";
import type {
  AlgorithmFamily,
  Baseline,
  CryptoPolicy,
  Finding,
  MandateEvaluation,
  MandateFindingVerdict,
  MandateGateOptions,
  ScanResult,
  Severity,
} from "@quantakrypto/core";
import { renderReport, runQscan } from "@quantakrypto/qscan";
import { assertCheckConfig, parseChecks, type CheckId } from "./checks.js";
import { runConformanceCheck, runProbeCheck } from "./extra-checks.js";
import {
  crashedResult,
  postResult,
  readDispatchContext,
  scoredResult,
  type DispatchContext,
} from "./platform.js";

import {
  appendStepSummary,
  error as annotateError,
  getBooleanInput,
  getInput,
  info,
  notice,
  setFailed,
  setOutput,
  setSecret,
  warning,
} from "./io.js";
import { mdCell } from "./escape.js";

/** Default report file when the `output` input is omitted. */
const DEFAULT_OUTPUT = "quantakrypto.sarif.json";

/** Normalised, validated inputs for a run. */
interface ActionInputs {
  /** Which checks to run. Defaults to ["scan"], which is exactly what v1 did. */
  checks: CheckId[];
  /** Host for the probe check. Required only when "probe" is selected. */
  probeTarget: string;
  /** The operator's explicit ownership attestation for the probe target. */
  probeIOwnThis: boolean;
  /** Command that runs the implementation under test, for "conformance". */
  conformanceImpl: string;
  /** Parameter set for "conformance", e.g. ml-kem-768. */
  conformanceParam: string;
  path: string;
  /** Extra exclude patterns. Empty means "just the built-in ignores". */
  ignore: string[];
  /** Restrict the walk to these patterns. Empty means "everything". */
  include: string[];
  severityThreshold: Severity;
  failOnFindings: boolean;
  format: "sarif" | "json";
  output: string;
  baseline?: string;
  commentPr: boolean;
  githubToken?: string;
  redactSnippets: boolean;
  /** `scan` (default) writes a report + gates the build; `comment-plan` posts a
   * deterministic migration plan as a PR comment and never fails the build. */
  mode: "scan" | "comment-plan";
  /** Compliance mandate ids to gate against; empty disables the mandate gate. */
  mandates: string[];
  /** Fail early when a mandate deadline is within this many months. */
  leadMonths?: number;
  /** Fail on any mandate-prohibited finding regardless of its deadline. */
  failNow: boolean;
  /**
   * Optional path to an org cryptography policy JSON (the same file the CLI's
   * `--policy` takes). When set alongside `mandate`, families the policy
   * explicitly permits / is transitioning are annotated + exempt from the early
   * gate (`lead-months` / `fail-now`); a passed disallow deadline still fails.
   */
  policy?: string;
}

/** Parse + validate the action's inputs from the environment. Pure given `env`. */
export function readInputs(env: NodeJS.ProcessEnv = process.env): ActionInputs {
  const severityThreshold = (getInput("severity-threshold", env) || "high") as Severity;
  if (!SEVERITY_ORDER.includes(severityThreshold)) {
    throw new TypeError(
      `Invalid severity-threshold "${severityThreshold}"; expected one of ${SEVERITY_ORDER.join(", ")}`,
    );
  }
  const format = (getInput("format", env) || "sarif") as "sarif" | "json";
  if (format !== "sarif" && format !== "json") {
    throw new TypeError(`Invalid format "${format}"; expected "sarif" or "json"`);
  }
  const baseline = getInput("baseline", env);
  const githubToken = getInput("github-token", env);
  const mode = (getInput("mode", env) || "scan") as "scan" | "comment-plan";
  if (mode !== "scan" && mode !== "comment-plan") {
    throw new TypeError(`Invalid mode "${mode}"; expected "scan" or "comment-plan"`);
  }
  // Comma- or space-separated mandate ids ("cnsa-2.0,nist-ir-8547"). Ids are
  // validated against the catalog in run() (assertKnownMandates), not here.
  const mandates = getInput("mandate", env)
    .split(/[\s,]+/)
    .filter((id) => id.length > 0);
  const leadMonthsRaw = getInput("lead-months", env);
  let leadMonths: number | undefined;
  if (leadMonthsRaw !== "") {
    leadMonths = Number(leadMonthsRaw);
    if (!Number.isInteger(leadMonths) || leadMonths < 0) {
      throw new TypeError(
        `Invalid lead-months "${leadMonthsRaw}"; expected a non-negative integer`,
      );
    }
  }
  const checks = parseChecks(getInput("checks", env));
  const probeTarget = getInput("probe-target", env);
  const conformanceImpl = getInput("conformance-impl", env);
  assertCheckConfig(checks, {
    probeTarget,
    conformanceImpl,
    probeIOwnThis: getBooleanInput("i-own-this", false, env),
  });

  return {
    checks,
    probeTarget,
    probeIOwnThis: getBooleanInput("i-own-this", false, env),
    conformanceImpl,
    conformanceParam: getInput("conformance-param", env) || "ml-kem-768",
    path: getInput("path", env) || ".",
    ignore: splitPatterns(getInput("ignore", env)),
    include: splitPatterns(getInput("include", env)),
    severityThreshold,
    failOnFindings: getBooleanInput("fail-on-findings", true, env),
    format,
    output: getInput("output", env) || DEFAULT_OUTPUT,
    baseline: baseline || undefined,
    commentPr: getBooleanInput("comment-pr", false, env),
    githubToken: githubToken || undefined,
    redactSnippets: getBooleanInput("redact-snippets", false, env),
    mode,
    mandates,
    leadMonths,
    failNow: getBooleanInput("fail-now", false, env),
    policy: getInput("policy", env) || undefined,
  };
}

/**
 * True when `severity` is at least as severe as `threshold`.
 *
 * Re-exported from `@quantakrypto/core` so the Action, the CLI and the SARIF
 * level mapping all agree on what "at or above a threshold" means (previously
 * this was a duplicated local definition).
 */
export { meetsThreshold };

/**
 * A stable identity for a finding, used to match it against a baseline.
 *
 * Re-exported from `@quantakrypto/core` so the Action and the CLI share one
 * fingerprint (line-insensitive sha256 of `ruleId | file | normalizedSnippet`)
 * and therefore one baseline format. Kept under this name for the Action's
 * public surface.
 */
export { fingerprintFinding as fingerprint };

/** Decide whether the run should fail the build. Pure. */
export function shouldFail(blockingCount: number, failOnFindings: boolean): boolean {
  return failOnFindings && blockingCount > 0;
}

/** Map our internal severity onto a SARIF/GitHub annotation level. */
function annotationLevel(severity: Severity): "error" | "warning" | "notice" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "notice";
}

/**
 * Emit one inline annotation per finding (errors for blocking severities).
 *
 * The finding-derived `message` and `file` are attacker-controlled (a scanned
 * fork PR names the files and can craft the message text). They are escaped for
 * the workflow-command wire format inside `io.ts` (`escapeData` for the message;
 * `escapeProperty`, which additionally encodes `,` and `:`, for `file`), so a
 * hostile finding cannot break out of the `::error file=…,line=…::message`
 * command.
 */
export function annotateFindings(findings: Finding[], threshold: Severity): void {
  for (const f of findings) {
    const level = meetsThreshold(f.severity, threshold) ? "error" : annotationLevel(f.severity);
    const message = f.remediation ? `${f.message} → ${f.remediation}` : f.message;
    const props = {
      title: `quantakrypto: ${f.title}`,
      file: f.location.file,
      line: f.location.line,
      col: f.location.column,
      endLine: f.location.endLine,
    };
    if (level === "error") annotateError(message, props);
    else if (level === "notice") notice(message, props);
    else warning(message, props);
  }
}

/** Build a Markdown summary suitable for a PR comment. Pure. */
export function buildSummary(
  result: ScanResult,
  newFindings: Finding[],
  threshold: Severity,
  mandateEval?: MandateEvaluation,
): string {
  const score = result.inventory.readinessScore;
  const blocking = newFindings.filter((f) => meetsThreshold(f.severity, threshold));
  const lines: string[] = [];
  lines.push("## quantakrypto — Quantum Readiness Scan");
  lines.push("");
  lines.push(`**Readiness score:** ${score}/100`);
  lines.push(
    `**New findings:** ${newFindings.length} (${blocking.length} at or above \`${threshold}\`)`,
  );
  lines.push("");
  if (blocking.length === 0) {
    lines.push("No new quantum-vulnerable cryptography at or above the threshold. ✅");
    if (mandateEval) {
      lines.push("");
      lines.push(buildMandateSection(mandateEval));
    }
    return lines.join("\n");
  }
  lines.push("| Severity | Rule | File | Message |");
  lines.push("| --- | --- | --- | --- |");
  for (const f of blocking.slice(0, 50)) {
    // Every cell carries finding-derived (attacker-controlled) text. Escape each
    // one so a crafted filename/message cannot break the table or inject HTML.
    const loc = mdCell(`${f.location.file}:${f.location.line}`);
    const rule = mdCell(f.ruleId);
    const msg = mdCell(f.message);
    lines.push(`| ${f.severity} | \`${rule}\` | ${loc} | ${msg} |`);
  }
  if (blocking.length > 50) lines.push(`| … | | | _${blocking.length - 50} more_ |`);
  if (mandateEval) {
    lines.push("");
    lines.push(buildMandateSection(mandateEval));
  }
  lines.push("");
  lines.push("<sub>Reported by [quantakrypto](https://quantakrypto.com/tools).</sub>");
  return lines.join("\n");
}

/** Render order + label for mandate verdict rows: worst first. */
const MANDATE_ROW_ORDER: Record<MandateFindingVerdict["status"], number> = {
  violation: 0,
  deprecated: 1,
  due: 2,
  conformant: 3,
};

/** The Deadline cell / failure-message phrase for one verdict row. Pure. */
function mandateDeadlinePhrase(r: MandateFindingVerdict): string {
  if (r.status === "violation") return `overdue since ${r.effective}`;
  if (r.status === "deprecated") {
    // The passed DEPRECATE date is a warning; the upcoming DISALLOW date is
    // what eventually fails the build, so show both when the mandate has one.
    return (
      `deprecated since ${r.effective}` +
      (r.disallowEffective ? `; disallow ${r.disallowEffective}` : "")
    );
  }
  return `${r.effective} (${r.monthsUntil} mo)`;
}

/**
 * Build the Markdown mandate section of the job summary / PR comment. Pure.
 *
 * One row per (prohibited finding × mandate) verdict — violations first, then
 * deprecated, then due, earliest deadline first — each naming the governing
 * clause and its deadline. Deadline-aware by design: `due`/`deprecated` rows
 * report without failing, so the section is the early-warning surface, not just
 * the failure explanation. `file` is finding-derived (attacker-controlled in a
 * fork PR) and escaped; clause/deadline/citation come from the bundled catalog.
 */
export function buildMandateSection(ev: MandateEvaluation): string {
  const lines: string[] = [];
  lines.push("### Compliance mandates");
  lines.push("");
  lines.push(
    `**Mandates:** ${ev.mandates.map((m) => `\`${m}\``).join(", ")} · ` +
      `**Violations:** ${ev.summary.violation} · **Deprecated:** ${ev.summary.deprecated} · ` +
      `**Due:** ${ev.summary.due}` +
      // Policy composition: how many rows the org is knowingly managing (exempt
      // from the early gate), so a reader sees why fail-now may not have fired.
      (ev.acknowledged > 0
        ? ` · **Acknowledged:** ${ev.acknowledged}${ev.policyName ? ` (${mdCell(ev.policyName)})` : ""}`
        : "") +
      (ev.nextDeadline ? ` · next deadline ${ev.nextDeadline}` : ""),
  );
  lines.push("");
  if (ev.findings.length === 0) {
    lines.push("No mandate-prohibited cryptography found. ✅");
    return lines.join("\n");
  }
  const rows = [...ev.findings].sort((a, b) => {
    if (a.status !== b.status) return MANDATE_ROW_ORDER[a.status] - MANDATE_ROW_ORDER[b.status];
    return a.effective.localeCompare(b.effective);
  });
  // A "Policy" column is added only when an org policy composed in (policyName set),
  // so runs without --policy keep the original five-column table unchanged.
  const withPolicy = ev.policyName !== null;
  lines.push(
    withPolicy
      ? "| Status | Clause | Deadline | File | Algorithm | Policy |"
      : "| Status | Clause | Deadline | File | Algorithm |",
  );
  lines.push(
    withPolicy ? "| --- | --- | --- | --- | --- | --- |" : "| --- | --- | --- | --- | --- |",
  );
  for (const r of rows.slice(0, 50)) {
    const icon = r.status === "violation" ? "🔴" : r.status === "deprecated" ? "🟠" : "🟡";
    const loc = mdCell(`${r.file}:${r.line}`);
    const base = `| ${icon} ${r.status} | ${mdCell(r.clause)} | ${mandateDeadlinePhrase(r)} | ${loc} | ${mdCell(r.algorithm)} |`;
    if (withPolicy) {
      const policyCell = r.acknowledged
        ? `${mdCell(r.policyVerdict ?? "acknowledged")} ✓`
        : (r.policyVerdict ?? "—");
      lines.push(`${base} ${policyCell} |`);
    } else {
      lines.push(base);
    }
  }
  if (rows.length > 50) {
    lines.push(
      withPolicy
        ? `| … | | | | | _${rows.length - 50} more_ |`
        : `| … | | | | _${rows.length - 50} more_ |`,
    );
  }
  return lines.join("\n");
}

/**
 * The verdict rows that trip the mandate gate under `opts` — the explanatory
 * complement of core's `mandateGateFails`, mirroring its precedence: violations
 * once a DISALLOW deadline has passed, every prohibited row under `failNow`,
 * rows whose disallow deadline sits inside the window under `leadMonths`.
 * Empty when the gate passes. Pure.
 *
 * Mirrors the gate's policy composition: the early tiers (`failNow` /
 * `leadMonths`) exclude policy-`acknowledged` rows (core exempts them), so the
 * failure message names only the rows that actually failed the build. A
 * `violation` is unfiltered — a passed disallow deadline fails regardless of
 * acknowledgement, exactly as the gate does.
 */
export function mandateGateRows(
  ev: MandateEvaluation,
  opts: MandateGateOptions = {},
): MandateFindingVerdict[] {
  if (ev.hasViolation) return ev.findings.filter((v) => v.status === "violation");
  const gated = ev.findings.filter((v) => !v.acknowledged);
  if (opts.failNow) return gated;
  if (opts.leadMonths !== undefined) {
    const lead = opts.leadMonths;
    return gated.filter((v) => v.monthsUntilDisallow !== null && v.monthsUntilDisallow <= lead);
  }
  return [];
}

/**
 * One-line failure reason naming each violated clause, its deadline, and the
 * citation — so the red X says WHICH regulation failed the build, not a count.
 * Clauses are deduplicated (many findings can violate one clause). Pure.
 */
export function describeMandateFailure(
  ev: MandateEvaluation,
  opts: MandateGateOptions = {},
): string {
  const rows = mandateGateRows(ev, opts);
  const seen = new Set<string>();
  const clauses: string[] = [];
  for (const r of rows) {
    if (seen.has(r.clause)) continue;
    seen.add(r.clause);
    const when =
      r.status === "violation"
        ? `deadline ${r.effective} passed`
        : `disallow deadline ${r.disallowEffective ?? r.effective}`;
    clauses.push(`"${r.clause}" (${when}) [${r.citation}]`);
  }
  return `mandate gate: ${rows.length} prohibited finding(s) — ${clauses.join("; ")}`;
}

/**
 * Build a deterministic, HNDL-first PQC migration plan for a PR comment. Pure
 * and model-free: findings are grouped by algorithm family and ordered so
 * harvest-now-decrypt-later (confidentiality) families come first, each with the
 * canonical post-quantum replacement.
 */
export function buildPlanComment(result: ScanResult): string {
  const findings = result.findings;
  const lines: string[] = ["## quantakrypto — PQC Migration Plan", ""];
  lines.push(
    `**Readiness score:** ${result.inventory.readinessScore}/100 · **HNDL-exposed findings:** ${result.inventory.hndlCount}`,
  );
  lines.push("");
  if (findings.length === 0) {
    lines.push("No quantum-vulnerable cryptography detected. Nothing to migrate. ✅");
    lines.push("");
    lines.push(
      "<sub>Deterministic, model-free plan from [quantakrypto](https://quantakrypto.com/tools).</sub>",
    );
    return lines.join("\n");
  }

  const byAlgo = new Map<string, Finding[]>();
  for (const f of findings) {
    const a = f.algorithm ?? "unknown";
    const list = byAlgo.get(a);
    if (list) list.push(f);
    else byAlgo.set(a, [f]);
  }
  // HNDL / confidentiality families first, then signatures, then unknown.
  const PRIORITY = [
    "RSA",
    "ECDH",
    "DH",
    "X25519",
    "X448",
    "ECIES",
    "ECDSA",
    "EdDSA",
    "DSA",
    "unknown",
  ];
  const rank = (a: string) => {
    const i = PRIORITY.indexOf(a);
    return i === -1 ? PRIORITY.length : i;
  };
  const algos = [...byAlgo.keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));

  lines.push("Migrate in this order (harvest-now-decrypt-later exposure first):");
  lines.push("");
  let step = 1;
  for (const algo of algos) {
    const group = byAlgo.get(algo) ?? [];
    const hndlCount = group.filter((f) => f.hndl).length;
    const rec =
      remediationFor(algo as AlgorithmFamily)?.recommendation ?? "review for PQC migration";
    const uniqueFiles = [...new Set(group.map((f) => f.location.file))];
    const shown = uniqueFiles.slice(0, 5).map(mdCell).join(", ");
    const more = uniqueFiles.length > 5 ? ` (+${uniqueFiles.length - 5} more)` : "";
    lines.push(
      `${step}. **${mdCell(algo)}** — ${group.length} finding(s)${hndlCount ? `, ${hndlCount} HNDL` : ""}. Migrate to ${mdCell(rec)}.`,
    );
    lines.push(`   _Files:_ ${shown}${more}`);
    step++;
  }
  lines.push("");
  lines.push(
    "<sub>Deterministic, model-free plan from [quantakrypto](https://quantakrypto.com/tools).</sub>",
  );
  return lines.join("\n");
}

/** Minimal GitHub PR context derived from the runner environment. */
interface PullRequestContext {
  owner: string;
  repo: string;
  prNumber: number;
  apiUrl: string;
}

/**
 * Derive PR context from the `GITHUB_*` env + event payload, or return
 * undefined when not running on a pull request. Never throws.
 */
async function readPullRequestContext(
  env: NodeJS.ProcessEnv = process.env,
): Promise<PullRequestContext | undefined> {
  try {
    const repository = env["GITHUB_REPOSITORY"];
    const eventPath = env["GITHUB_EVENT_PATH"];
    if (!repository || !eventPath) return undefined;
    const [owner, repo] = repository.split("/");
    if (!owner || !repo) return undefined;
    const payload = JSON.parse(await readFile(eventPath, "utf8")) as {
      pull_request?: { number?: number };
      number?: number;
    };
    const prNumber = payload.pull_request?.number ?? payload.number;
    if (typeof prNumber !== "number") return undefined;
    const apiUrl = env["GITHUB_API_URL"] || "https://api.github.com";
    return { owner, repo, prNumber, apiUrl };
  } catch {
    return undefined;
  }
}

/** Hidden marker so we can find and update our own comment instead of stacking. */
const COMMENT_MARKER = "<!-- quantakrypto-action -->";

/** Find the id of our previous comment on the PR (by marker), if any. */
async function findExistingComment(
  ctx: PullRequestContext,
  headers: Record<string, string>,
): Promise<number | null> {
  const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments?per_page=100`;
  const res = await fetch(url, { headers });
  if (!res.ok) return null;
  const comments = (await res.json()) as Array<{ id: number; body?: string }>;
  const mine = comments.find((c) => typeof c.body === "string" && c.body.includes(COMMENT_MARKER));
  return mine ? mine.id : null;
}

/**
 * Upsert a summary comment on a pull request: update our previous comment (found
 * by a hidden marker) if it exists, otherwise create one — so re-running on every
 * push edits a single comment instead of stacking a new one each time. Best-effort:
 * any failure is logged as a warning and swallowed so commenting never breaks CI.
 */
async function commentOnPullRequest(
  ctx: PullRequestContext,
  token: string,
  body: string,
): Promise<boolean> {
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "quantakrypto-action",
  };
  const markedBody = `${COMMENT_MARKER}\n${body}`;
  try {
    const existingId = await findExistingComment(ctx, headers);
    const url = existingId
      ? `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/comments/${existingId}`
      : `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments`;
    const res = await fetch(url, {
      method: existingId ? "PATCH" : "POST",
      headers,
      body: JSON.stringify({ body: markedBody }),
    });
    if (!res.ok) {
      warning(`Could not comment on PR #${ctx.prNumber}: ${res.status} ${res.statusText}`);
      return false;
    }
    return true;
  } catch (err) {
    warning(`Could not comment on PR: ${(err as Error).message}`);
    return false;
  }
}

/**
 * Resolve a possibly-relative path against the GitHub workspace (or cwd).
 *
 * The `output`/`baseline` inputs are workflow-author-supplied but flow into
 * `writeFile`/`readFile`, so a relative `../../etc/...` (or a crafted absolute
 * path) must not be allowed to escape the workspace and read/write arbitrary
 * files on the runner. We resolve the path and assert it stays inside
 * `resolve(workspace) + sep`, throwing otherwise.
 */
function resolveInWorkspace(p: string, env: NodeJS.ProcessEnv): string {
  const workspace = resolve(env["GITHUB_WORKSPACE"] || process.cwd());
  const resolved = isAbsolute(p) ? resolve(p) : resolve(workspace, p);
  // The workspace itself is allowed; anything below it must sit under "<ws>/".
  if (resolved !== workspace && !resolved.startsWith(workspace + sep)) {
    throw new Error(`path "${p}" escapes the workspace (${workspace})`);
  }
  return resolved;
}

/**
 * Load the shared `@quantakrypto/core` baseline (the `{ version, fingerprints }`
 * format written by `qscan --write-baseline`). `loadBaseline` is tolerant of a
 * missing/unparseable file, so it degrades to "suppress nothing" — but a
 * workflow that DID set `baseline:` and expects suppression would then fail on
 * old findings with no explanation. So we warn (loudly, once) when the named
 * file is missing or loads no fingerprints, rather than degrading silently.
 */
async function loadBaselineSet(baselinePath: string, env: NodeJS.ProcessEnv): Promise<Baseline> {
  const abs = resolveInWorkspace(baselinePath, env);
  const present = await access(abs).then(
    () => true,
    () => false,
  );
  if (!present) {
    warning(
      `baseline file not found at "${baselinePath}" — no findings will be suppressed. ` +
        `Create it with: qscan --write-baseline ${baselinePath}`,
    );
    return loadBaseline(abs);
  }
  const baseline = await loadBaseline(abs);
  if (baseline.fingerprints.length === 0) {
    warning(
      `baseline file "${baselinePath}" loaded 0 fingerprints — it may be empty or malformed; ` +
        `no findings will be suppressed.`,
    );
  }
  return baseline;
}

/**
 * Where the single workflow lives, quoted in the conformance failure message so
 * the owner is told which file to edit rather than which tool complained.
 */
export const WORKFLOW_PATH = ".github/workflows/quantakrypto.yml";

/**
 * The repository_dispatch event type the platform sends per check. A run started
 * by the dashboard names exactly one check, even though the workflow may be
 * configured to run several.
 */
const DISPATCH_EVENT: Record<CheckId, string> = {
  scan: "quantakrypto-scan",
  conformance: "quantakrypto-conformance",
  probe: "quantakrypto-probe",
};

/**
 * Did this dispatch ask for this check?
 *
 * One audit run id belongs to one check. A workflow set to `checks: scan,probe`
 * still receives a single dispatch naming one of them, so only that check may
 * post against the id — otherwise the second result would overwrite the first
 * and the dashboard would show a probe verdict under a scan run.
 *
 * A run with no recognisable event type (a manual dispatch that somehow carried
 * a client_payload) reports nothing, which is the safe direction.
 */
export function dispatchAskedFor(eventType: string | null, check: CheckId): boolean {
  return eventType === DISPATCH_EVENT[check];
}

/** The check a dispatch event names, or null when it names none of ours. */
export function checkForDispatchEvent(eventType: string | null): CheckId | null {
  if (!eventType) return null;
  for (const id of Object.keys(DISPATCH_EVENT) as CheckId[]) {
    if (DISPATCH_EVENT[id] === eventType) return id;
  }
  return null;
}

/**
 * Post a result and say so when it does not land.
 *
 * A dropped report is invisible from the dashboard — the run simply sits there
 * until it goes stale an hour later — so the job log is the only place the
 * operator can find out. Still never fatal: the check ran, and its verdict is on
 * the job summary either way.
 */
async function report(
  dispatch: DispatchContext,
  result: Parameters<typeof postResult>[1],
): Promise<void> {
  if (!(await postResult(dispatch, result))) {
    warning(
      `quantakrypto: could not report the result to ${dispatch.resultUrl}. ` +
        "The check ran; the dashboard will show this run as stale until it is re-run.",
    );
  }
}

/**
 * Split a comma- or newline-separated pattern list.
 *
 * Both separators, because a YAML block scalar is the natural way to write more
 * than two of these and a single line is the natural way to write one.
 */
export function splitPatterns(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
}

/** The full action run, parameterised on `env` for testability. */
export async function run(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const inputs = readInputs(env);

  // The dispatch context is present only when the platform triggered this run.
  // Ordinary CI (push, pull_request, manual) reports nowhere and just gates.
  const dispatch = readDispatchContext(env);
  // Redact the callback token from every later log line in this job. We never
  // print it, but the event payload it came from sits in plaintext on disk for
  // the whole job and any other step can echo it.
  if (dispatch) setSecret(dispatch.token);

  // The non-scan checks run first and independently: each reports its own result,
  // and a failure in one is a reportable outcome rather than something that takes
  // the others down with it.
  //
  // KNOWN HAZARD, not yet fixed: `conformance` executes an implementation named
  // by the workflow, with write access to the workspace, and it runs BEFORE the
  // scan reads that workspace. An implementation that deleted or rewrote the
  // crypto it was meant to be tested against would produce a clean scan, which is
  // then posted as a genuine verdict. Running the scan first would close it, but
  // the build gate below calls process.exit, so the extras cannot simply be moved
  // after it — the reorder needs the gate deferred to the end of the run.
  const extras = inputs.checks.filter((c) => c !== "scan");
  for (const check of extras) {
    info(`quantakrypto: running ${check}`);
    const result =
      check === "probe"
        ? await runProbeCheck(inputs.probeTarget, inputs.probeIOwnThis)
        : await runConformanceCheck(inputs.conformanceImpl, inputs.conformanceParam, WORKFLOW_PATH);
    info(`quantakrypto: ${check} — ${result.summary}`);
    appendStepSummary(`## quantakrypto — ${check}\n\n${result.summary}\n`, env);
    // Only the check the platform asked for may claim this run's audit id: a
    // workflow running all three has one dispatch id, and reporting three
    // different verdicts against it would overwrite the run it was asked about.
    if (dispatch && dispatchAskedFor(dispatch.eventType, check)) {
      await report(dispatch, result);
    }
  }

  // C2: the platform asked for a check this workflow is not configured to run.
  // Reporting it as failed turns an hour of "running" followed by a silent stale
  // into a message naming the input to edit.
  const asked = checkForDispatchEvent(dispatch?.eventType ?? null);
  if (dispatch && asked && !inputs.checks.includes(asked)) {
    await report(
      dispatch,
      crashedResult(
        "This workflow",
        `is not configured to run the ${asked} check. Add "${asked}" to the checks: input in ` +
          `${WORKFLOW_PATH} (currently: ${inputs.checks.join(",")}).`,
      ),
    );
    return;
  }

  if (!inputs.checks.includes("scan")) return;

  const scanRoot = resolveInWorkspace(inputs.path, env);
  info(`quantakrypto: scanning ${scanRoot} (threshold: ${inputs.severityThreshold})`);

  // comment-plan mode: post a deterministic migration plan as a PR comment and
  // stop. It never writes a report, sets outputs, or fails the build.
  if (inputs.mode === "comment-plan") {
    const { result: planResult } = await runQscan({ path: scanRoot });
    setOutput("readiness-score", String(planResult.inventory.readinessScore), env);
    // Always render the plan on the run's summary page (no token needed).
    appendStepSummary(buildPlanComment(planResult), env);
    if (inputs.githubToken) {
      const ctx = await readPullRequestContext(env);
      if (ctx) {
        await commentOnPullRequest(ctx, inputs.githubToken, buildPlanComment(planResult));
        info(`quantakrypto: posted migration plan to PR #${ctx.prNumber}.`);
      } else {
        info(
          "quantakrypto: comment-plan mode but no pull-request context found; skipping comment.",
        );
      }
    } else {
      info("quantakrypto: comment-plan mode needs github-token to post a comment; skipping.");
    }
    return;
  }

  // One code path with the CLI: qScan runs the scan and renders the report.
  // We deliberately do NOT hand the baseline to runQscan — the report (SARIF
  // for code scanning) must carry the FULL, pre-baseline result; we apply the
  // baseline ourselves below to derive the NEW findings that gate the build.
  const { result } = await runQscan({
    path: scanRoot,
    format: inputs.format,
    severityThreshold: inputs.severityThreshold,
    ...(inputs.ignore.length > 0 ? { ignore: inputs.ignore } : {}),
    ...(inputs.include.length > 0 ? { include: inputs.include } : {}),
  });

  // Apply the shared baseline so only NEW quantum-vulnerable crypto can fail.
  const baseline = inputs.baseline
    ? await loadBaselineSet(inputs.baseline, env)
    : { version: 1, fingerprints: [] as string[] };
  const { newFindings } = applyBaseline(result.findings, baseline);

  // Write the report (SARIF for code scanning, or JSON) to the output path.
  // `redact-snippets` drops `location.snippet` from every finding (sensitive
  // findings are redacted regardless) so the report can be uploaded to code
  // scanning without leaking matched source.
  // mandate: policy-as-code compliance gate. Deadline-aware — reports every
  // mandate-prohibited finding with its named clause + deadline, but fails the
  // build only once a deadline has passed (or early with lead-months / fail-now).
  // Evaluated on the RAW findings: a baseline can suppress the severity gate,
  // but must never waive a regulatory deadline. Computed BEFORE the report write
  // so the machine-readable SARIF/JSON carries the mandate verdicts too.
  let mandateEval: MandateEvaluation | undefined;
  if (inputs.mandates.length > 0) {
    // The org policy only composes with a mandate gate, so it is read — and
    // strictly parsed (parseCryptoPolicy throws on a malformed file, failing the
    // run via the entrypoint's catch) — ONLY when mandates are configured. Reading
    // it unconditionally would fail an entire scan over a broken policy the run
    // never uses. The path is workspace-guarded like every other input path.
    let policy: CryptoPolicy | undefined;
    if (inputs.policy) {
      const policyPath = resolveInWorkspace(inputs.policy, env);
      policy = parseCryptoPolicy(JSON.parse(await readFile(policyPath, "utf8")));
    }
    // A typo'd id throws here and fails the run via the entrypoint's catch —
    // a compliance gate must never silently gate against nothing. The org policy
    // (when supplied) composes in: acknowledged families are exempt from the
    // early gate but never from a passed disallow deadline.
    assertKnownMandates(inputs.mandates);
    mandateEval = evaluateMandates(result.findings, inputs.mandates, new Date(), policy);
  } else if (inputs.policy) {
    info("quantakrypto: 'policy' input is set but 'mandate' is not; the policy has no effect.");
  }

  const outputPath = resolveInWorkspace(inputs.output, env);
  await mkdir(dirname(outputPath), { recursive: true });
  // qScan's renderReport is the single source of truth for report serialization
  // (and threads redactSnippets + the full SARIF rule catalog, incl. the
  // dependency rule). The Action and CLI now share it verbatim. The mandate
  // evaluation rides along so an uploaded SARIF carries `run.properties.mandate`.
  await writeFile(
    outputPath,
    renderReport(result, inputs.format, {
      redactSnippets: inputs.redactSnippets,
      ...(mandateEval ? { mandate: mandateEval } : {}),
    }),
    "utf8",
  );
  info(`quantakrypto: wrote ${inputs.format} report to ${inputs.output}`);

  // Annotate findings inline in the diff.
  annotateFindings(newFindings, inputs.severityThreshold);

  // The findings that gate the build.
  const blocking = newFindings.filter((f) => meetsThreshold(f.severity, inputs.severityThreshold));

  // Outputs.
  setOutput("findings-count", String(blocking.length), env);
  setOutput("readiness-score", String(result.inventory.readinessScore), env);
  setOutput("sarif-file", inputs.output, env);

  // Job summary: render the same Markdown table on the run's summary page. This
  // shows the result on EVERY run — no PR context, no token — so a push build or
  // a fork PR (where commenting needs a token it may not have) still surfaces the
  // scan. Best-effort; a summary-write failure never breaks the build.
  appendStepSummary(buildSummary(result, newFindings, inputs.severityThreshold, mandateEval), env);

  // Optional PR comment (best-effort, never fatal).
  if (inputs.commentPr && inputs.githubToken) {
    const ctx = await readPullRequestContext(env);
    if (ctx) {
      const body = buildSummary(result, newFindings, inputs.severityThreshold, mandateEval);
      await commentOnPullRequest(ctx, inputs.githubToken, body);
    } else {
      info("quantakrypto: comment-pr enabled but no pull-request context found; skipping comment.");
    }
  }

  info(
    `quantakrypto: ${newFindings.length} new finding(s), ${blocking.length} at/above "${inputs.severityThreshold}"; readiness ${result.inventory.readinessScore}/100.`,
  );
  if (mandateEval) {
    info(
      `quantakrypto: mandate gate (${mandateEval.mandates.join(", ")}): ` +
        `${mandateEval.summary.violation} violation, ${mandateEval.summary.deprecated} deprecated, ` +
        `${mandateEval.summary.due} due` +
        (mandateEval.nextDeadline ? `, next deadline ${mandateEval.nextDeadline}` : "") +
        ".",
    );
  }

  // Report the scan result BEFORE the gate below, because the gate calls
  // process.exit and a failing scan is exactly the result worth recording.
  //
  // PRE-baseline findings, deliberately. The baseline is a CI convenience — it
  // says "do not fail my build on debt I have already logged" — and the platform
  // is a different consumer: it records posture. Posting post-baseline findings
  // alongside the pre-baseline score would let a repository baseline everything
  // and mint a readiness badge from `findings: []` while its own score said 40.
  // It would also be internally contradictory, reporting "0 finding(s),
  // readiness 40/100". The mandate gate already refuses to let a baseline waive
  // a deadline for the same reason.
  if (dispatch && dispatchAskedFor(dispatch.eventType, "scan")) {
    await report(dispatch, scoredResult("qScan", result.inventory.readinessScore, result.findings));
  }

  // The two gates OR: a passed compliance deadline fails the build even when
  // every finding is baselined or below the severity threshold (and vice versa).
  // The mandate gate is deliberately independent of fail-on-findings — setting
  // `mandate:` is the opt-in.
  const gateOpts: MandateGateOptions = { leadMonths: inputs.leadMonths, failNow: inputs.failNow };
  const mandateFailed = mandateEval !== undefined && mandateGateFails(mandateEval, gateOpts);
  const severityFailed = shouldFail(blocking.length, inputs.failOnFindings);

  if (severityFailed || mandateFailed) {
    const reasons: string[] = [];
    if (severityFailed) {
      reasons.push(
        `${blocking.length} quantum-vulnerable finding(s) at or above "${inputs.severityThreshold}"`,
      );
    }
    // Name the violated clause(s) + deadline + citation, not just a count.
    if (mandateFailed && mandateEval) reasons.push(describeMandateFailure(mandateEval, gateOpts));
    setFailed(`quantakrypto: ${reasons.join("; ")}.`);
    process.exit(1);
  }
}

// Run when invoked as the action's entrypoint, not when imported by tests.
// Compare this module's URL against the script Node was launched with so the
// guard holds regardless of the emitted filename (tsc's `main.js` or the
// bundled `index.js` that `action.yml` points at).
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedDirectly) {
  run().catch(async (err: unknown) => {
    const message = (err as Error).message;
    // A configuration error throws inside readInputs, BEFORE the dispatch
    // context is read, so without this the platform hears nothing at all: the
    // run sits at "running" for an hour and then goes stale, with the reason
    // visible only to whoever opens the Actions log. readDispatchContext needs
    // nothing from the inputs, so it still works here.
    const dispatch = readDispatchContext();
    if (dispatch) await postResult(dispatch, crashedResult("The quantakrypto action", message));
    setFailed(`quantakrypto: ${message}`);
    process.exit(1);
  });
}
