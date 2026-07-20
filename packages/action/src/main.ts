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
  fingerprintFinding,
  loadBaseline,
  meetsThreshold,
  remediationFor,
  SEVERITY_ORDER,
} from "@quantakrypto/core";
import type { AlgorithmFamily, Baseline, Finding, ScanResult, Severity } from "@quantakrypto/core";
import { renderReport, runQscan } from "@quantakrypto/qscan";

import {
  appendStepSummary,
  error as annotateError,
  getBooleanInput,
  getInput,
  info,
  notice,
  setFailed,
  setOutput,
  warning,
} from "./io.js";
import { mdCell } from "./escape.js";

/** Default report file when the `output` input is omitted. */
const DEFAULT_OUTPUT = "quantakrypto.sarif.json";

/** Normalised, validated inputs for a run. */
interface ActionInputs {
  path: string;
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
  return {
    path: getInput("path", env) || ".",
    severityThreshold,
    failOnFindings: getBooleanInput("fail-on-findings", true, env),
    format,
    output: getInput("output", env) || DEFAULT_OUTPUT,
    baseline: baseline || undefined,
    commentPr: getBooleanInput("comment-pr", false, env),
    githubToken: githubToken || undefined,
    redactSnippets: getBooleanInput("redact-snippets", false, env),
    mode,
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
  lines.push("");
  lines.push("<sub>Reported by [quantakrypto](https://quantakrypto.com/tools).</sub>");
  return lines.join("\n");
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

/** The full action run, parameterised on `env` for testability. */
export async function run(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const inputs = readInputs(env);

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
  const outputPath = resolveInWorkspace(inputs.output, env);
  await mkdir(dirname(outputPath), { recursive: true });
  // qScan's renderReport is the single source of truth for report serialization
  // (and threads redactSnippets + the full SARIF rule catalog, incl. the
  // dependency rule). The Action and CLI now share it verbatim.
  await writeFile(
    outputPath,
    renderReport(result, inputs.format, { redactSnippets: inputs.redactSnippets }),
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
  appendStepSummary(buildSummary(result, newFindings, inputs.severityThreshold), env);

  // Optional PR comment (best-effort, never fatal).
  if (inputs.commentPr && inputs.githubToken) {
    const ctx = await readPullRequestContext(env);
    if (ctx) {
      const body = buildSummary(result, newFindings, inputs.severityThreshold);
      await commentOnPullRequest(ctx, inputs.githubToken, body);
    } else {
      info("quantakrypto: comment-pr enabled but no pull-request context found; skipping comment.");
    }
  }

  info(
    `quantakrypto: ${newFindings.length} new finding(s), ${blocking.length} at/above "${inputs.severityThreshold}"; readiness ${result.inventory.readinessScore}/100.`,
  );

  if (shouldFail(blocking.length, inputs.failOnFindings)) {
    setFailed(
      `quantakrypto: ${blocking.length} quantum-vulnerable finding(s) at or above "${inputs.severityThreshold}".`,
    );
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
  run().catch((err: unknown) => {
    setFailed(`quantakrypto: ${(err as Error).message}`);
    process.exit(1);
  });
}
