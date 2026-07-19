/**
 * @quantakrypto/qscan — programmatic API.
 *
 * `runQscan` is the single entry point shared by the CLI (`src/cli.ts`) and by
 * `@quantakrypto/action`. It runs a scan via `@quantakrypto/core`, applies an optional
 * baseline, decides an exit code from the severity threshold, and (optionally)
 * renders a report. The CLI is a thin shell around it.
 *
 * The module also re-exports the argument-parsing and baseline helpers so
 * downstream tools can reuse them without reaching into internal paths.
 */

import { readFile } from "node:fs/promises";
import process from "node:process";

import {
  buildReadinessReport,
  changedFiles,
  parseCryptoPolicy,
  scan,
  scanParallel,
} from "@quantakrypto/core";
import type {
  Baseline,
  CryptoPolicy,
  Finding,
  ParallelScanOptions,
  ScanResult,
  SecurityTier,
} from "@quantakrypto/core";

import { applyBaseline, readBaseline, saveBaseline } from "./baseline.js";
import { defaultOptions, meetsThreshold } from "./args.js";
import type { QscanOptions } from "./args.js";
import { renderCbom, renderHuman, renderJson, renderSarif } from "./report.js";

export type { QscanOptions, ParsedArgs, ParsedRun, QscanFormat } from "./args.js";
export type { Baseline } from "./baseline.js";
export {
  ArgError,
  asFormat,
  asInt,
  asSeverity,
  defaultOptions,
  meetsThreshold,
  parseArgs,
  severityRank,
  SEVERITY_ORDER,
} from "./args.js";
export {
  applyBaseline,
  baselineFromFindings,
  BASELINE_VERSION,
  buildBaseline,
  fingerprint,
  fingerprintFinding,
  loadBaseline,
  readBaseline,
  saveBaseline,
  writeBaseline,
} from "./baseline.js";
export { renderCbom, renderHuman, renderJson, renderSarif } from "./report.js";
export { HELP_TEXT, versionLine } from "./help.js";
export {
  runRemediate,
  parseRemediateArgs,
  unifiedDiff,
  REMEDIATE_HELP,
  REMEDIATE_EXIT,
} from "./remediate-cli.js";
export type {
  RemediateMode,
  RemediateOptions,
  RemediateRun,
  RemediateHooks,
} from "./remediate-cli.js";
export { applyConfig, resolveConfig } from "./config.js";
export type { ResolvedConfig } from "./config.js";
export type { ConfigurableKey } from "./args.js";

/** Process-style exit codes qScan uses. */
export const EXIT = {
  /** No findings at/above threshold, or a baseline was written. */
  OK: 0,
  /** One or more findings at/above the severity threshold. */
  FINDINGS: 1,
  /** Usage error or I/O failure. */
  ERROR: 2,
} as const;

/** Outcome of {@link runQscan}. */
export interface QscanRun {
  /** The scan result, with the baseline already applied to `findings`. */
  result: ScanResult;
  /** Findings suppressed because their fingerprint was in the baseline. */
  suppressed: Finding[];
  /** Rendered report in the requested format (`undefined` for a baseline write). */
  report?: string;
  /** The baseline that was written, when `writeBaseline` was requested. */
  baselineWritten?: Baseline;
  /** Suggested process exit code. */
  exitCode: number;
}

/**
 * The scan implementation `runQscan` calls. Matches `@quantakrypto/core`'s `scan` /
 * `scanParallel` (parallel options are a superset of `ScanOptions`).
 * Injectable so the GitHub Action and tests can supply a custom scanner.
 */
export type ScanFn = (options: ParallelScanOptions) => Promise<ScanResult>;

/**
 * Resolve the changed-file list for incremental scans. Injectable for testing;
 * defaults to core's git-aware {@link changedFiles}.
 */
export type ChangedFilesFn = (root: string, since?: string) => Promise<string[]>;

/** Behavioral hooks for {@link runQscan}, mainly for testing. */
export interface RunQscanHooks {
  /** Emit raw ANSI color in the human report. Default: false. */
  color?: boolean;
  /** Override the scanner. Default: `scan` / `scanParallel` from `@quantakrypto/core`. */
  scanFn?: ScanFn;
  /** Override changed-file resolution. Default: `changedFiles` from `@quantakrypto/core`. */
  changedFilesFn?: ChangedFilesFn;
  /** Inject the triage function (offline testing of the `--triage` path, so the
   * exit-code invariant can be exercised without a network client or API key).
   * `import type` keeps this a compile-time-only reference — the networked agent
   * package is still only loaded via the dynamic import inside `runTriage`. */
  triageFn?: import("./triage-run.js").TriageFn;
}

/**
 * Translate resolved {@link QscanOptions} into core {@link ParallelScanOptions}.
 * `files` (the incremental file list) is layered on by {@link runQscan}.
 */
function toScanOptions(options: QscanOptions): ParallelScanOptions {
  const scanOptions: ParallelScanOptions = {
    root: options.path,
    source: options.source,
    dependencies: options.dependencies,
    config: options.config,
    noDefaultIgnores: options.noDefaultIgnores,
    scanMinified: options.scanMinified,
  };
  if (options.ignore.length > 0) scanOptions.exclude = options.ignore;
  if (options.include.length > 0) scanOptions.include = options.include;
  if (options.maxFileSize !== undefined) scanOptions.maxFileSize = options.maxFileSize;
  if (options.concurrency !== undefined) scanOptions.concurrency = options.concurrency;
  if (options.disabledRules && options.disabledRules.length > 0) {
    scanOptions.disabledRules = options.disabledRules;
  }
  if (options.cacheFile) scanOptions.cacheFile = options.cacheFile;
  return scanOptions;
}

/**
 * Run a complete qScan pass: scan → baseline → threshold → render.
 *
 * This never touches `process` or stdout; the CLI is responsible for printing
 * `report`/writing `output` and calling `process.exit(exitCode)`. That keeps
 * the function pure enough to unit-test and to embed in the GitHub Action.
 *
 * Behavior:
 *  - The walk is configured by `include` / `ignore` / `maxFileSize` /
 *    `noDefaultIgnores` / `scanMinified`.
 *  - With `changed` set, only the files git reports as changed (relative to
 *    `since`, if given) are scanned via `ScanOptions.files`. A non-git tree
 *    yields an empty list, so nothing is scanned.
 *  - With `parallel` (or `concurrency`) set, the scan is routed through core's
 *    `scanParallel`, which itself falls back to the serial path for small
 *    inputs.
 *  - When `opts.writeBaseline` is set, the scan runs, a baseline is built from
 *    *all* findings, written to disk, and `exitCode` is {@link EXIT.OK}. No
 *    report is rendered.
 *  - When `opts.baseline` is set, its fingerprints are loaded and matching
 *    findings are moved to `suppressed` (and removed from `result.findings`).
 *  - `exitCode` is {@link EXIT.FINDINGS} when any *kept* finding meets the
 *    severity threshold, else {@link EXIT.OK}.
 *
 * @throws {Error} Propagates scan / baseline I/O errors; the CLI maps these to
 *   {@link EXIT.ERROR}.
 */
export async function runQscan(
  opts: Partial<QscanOptions> & { path: string },
  hooks: RunQscanHooks = {},
): Promise<QscanRun> {
  const options: QscanOptions = { ...defaultOptions(), ...opts };
  // Route to the parallel pool when requested; both share the ScanOptions shape.
  const scanFn: ScanFn = hooks.scanFn ?? (options.parallel ? scanParallel : scan);
  const resolveChanged: ChangedFilesFn = hooks.changedFilesFn ?? changedFiles;

  const scanOptions = toScanOptions(options);

  // Incremental mode: restrict the scan to git-changed files.
  if (options.changed) {
    scanOptions.files = await resolveChanged(options.path, options.since);
  }

  const result = await scanFn(scanOptions);

  // --write-baseline: snapshot every finding, persist, and exit cleanly.
  if (options.writeBaseline) {
    const baseline = await saveBaseline(options.writeBaseline, result.findings);
    return {
      result,
      suppressed: [],
      baselineWritten: baseline,
      exitCode: EXIT.OK,
    };
  }

  // --baseline: suppress previously-accepted findings.
  //
  // The explicit `--baseline <path>` is read STRICTLY via `readBaseline`: a
  // missing or malformed file is an error (surfaced by the CLI as exit 2), not
  // silently treated as an empty baseline. Using core's tolerant `loadBaseline`
  // here would let a typo'd path (`--baseline typo.json`) suppress nothing and
  // still exit 0 — a CI footgun where a broken baseline reads as "all clear".
  let suppressed: Finding[] = [];
  if (options.baseline) {
    const fingerprints = await readBaseline(options.baseline);
    const split = applyBaseline(result.findings, fingerprints);
    result.findings = split.kept;
    suppressed = split.suppressed;
  }

  // --policy: the org cryptography policy for the evidence report's §4 verdicts.
  // Parsed strictly — a malformed policy fails loudly rather than silently
  // dropping the verdicts from the attested evidence.
  let policy: CryptoPolicy | undefined;
  if (options.policy) {
    policy = parseCryptoPolicy(JSON.parse(await readFile(options.policy, "utf8")));
  }

  // Exit code is computed from RAW severities, BEFORE triage runs, so the
  // (optional) LLM triage pass can never make a failing scan pass CI.
  const exitCode = result.findings.some((f) =>
    meetsThreshold(f.severity, options.severityThreshold),
  )
    ? EXIT.FINDINGS
    : EXIT.OK;

  // Optional BYOK triage: annotate + re-sort findings (never suppresses). The
  // agent (networked) package is loaded only here, via dynamic import.
  if (options.triage) {
    const { runTriage } = await import("./triage-run.js");
    const triaged = await runTriage(result, {
      level: options.contextLevel ?? "snippet",
      floor: options.triageFloor,
      maxFindings: options.maxFindings,
      dryRun: options.dryRun,
      provider: options.llmProvider,
      model: options.llmModel,
      // The triage RESPONSE cache must not share a path with the scan cache —
      // they are different on-disk formats and would clobber each other every
      // run, defeating both (audit: arch #1). Derive a sibling path.
      cacheFile: options.cacheFile ? `${options.cacheFile}.responses.json` : undefined,
      root: options.path,
      triageFn: hooks.triageFn,
    });
    if (triaged.preflight !== undefined) {
      return { result, suppressed, report: triaged.preflight, exitCode: EXIT.OK };
    }
  }

  return {
    result,
    suppressed,
    report: renderReport(result, options.format, {
      color: hooks.color ?? false,
      redactSnippets: options.noSnippets,
      topN: options.topN,
      tier: options.tier,
      ...(policy ? { policy } : {}),
    }),
    exitCode,
  };
}

/** Rendering controls for {@link renderReport}. */
export interface RenderReportOptions {
  /** Emit raw ANSI color in the human report. Default: false. */
  color?: boolean;
  /** Omit code snippets from the JSON/SARIF report (`--no-snippets`). */
  redactSnippets?: boolean;
  /** How many findings the human report lists (`--top N`). */
  topN?: number;
  /** CNSA security tier for the migration-targets footer (`--tier`). */
  tier?: SecurityTier;
  /** Org cryptography policy for the evidence report's §4 verdicts (`--policy`). */
  policy?: CryptoPolicy;
}

/** Render a scan result in the requested format. */
export function renderReport(
  result: ScanResult,
  format: QscanOptions["format"],
  opts: RenderReportOptions | boolean = {},
): string {
  // Back-compat: `renderReport(result, format, true)` used to mean "color on".
  const {
    color = false,
    redactSnippets = false,
    topN = undefined,
    tier = undefined,
    policy = undefined,
  } = typeof opts === "boolean" ? { color: opts, policy: undefined } : opts;
  switch (format) {
    case "json":
      return renderJson(result, { redactSnippets });
    case "sarif":
      return renderSarif(result, { redactSnippets });
    case "cbom":
      return renderCbom(result);
    case "evidence":
      // ISO A.8.24 readiness report; repo/commit come from CI env when present.
      // A `--policy` file adds the §4 conformant/violation/transition verdicts.
      return JSON.stringify(
        buildReadinessReport(result, {
          repository: process.env.GITHUB_REPOSITORY,
          commit: process.env.GITHUB_SHA,
          ...(policy ? { policy } : {}),
        }),
        null,
        2,
      );
    case "human":
    default:
      return renderHuman(result, { color, topN, tier });
  }
}

/** Re-export the core result types consumers commonly need. */
export type { Finding, ScanResult, ScanOptions } from "@quantakrypto/core";
