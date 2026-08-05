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

import { readFile, stat } from "node:fs/promises";
import * as nodePath from "node:path";
import process from "node:process";

import {
  buildCryptoAgilityManifest,
  buildInventory,
  buildReadinessReport,
  changedFiles,
  checkProvenance,
  compareFindings,
  computeHndl,
  findingScope,
  HNDL_FILENAME,
  loadHndlMap,
  parseCryptoPolicy,
  evaluateMandates,
  mandateGateFails,
  assertKnownMandates,
  scaffoldHndlYaml,
  scan,
  scanAdvisories,
  scanParallel,
  signReadinessReport,
  validateCryptoAgilityManifest,
} from "@quantakrypto/core";
import type {
  Baseline,
  CryptoPolicy,
  CycloneDxBom,
  EvidenceSigner,
  Finding,
  HndlReport,
  ManifestValidation,
  ParallelScanOptions,
  ReadinessReport,
  ScanResult,
  SecurityTier,
} from "@quantakrypto/core";
import type { MandateEvaluation } from "@quantakrypto/core";
import { commandSigner } from "./sign.js";
import { repoHeadRequest } from "./provenance-net.js";

import { applyBaseline, readBaseline, saveBaseline } from "./baseline.js";
import { defaultOptions, meetsThreshold } from "./args.js";
import type { QscanOptions } from "./args.js";
import { renderCbom, renderHuman, renderJson, renderSarif, renderVex } from "./report.js";

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
export { renderCbom, renderHuman, renderJson, renderSarif, renderVex } from "./report.js";
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
  /**
   * Non-fatal diagnostics from the `--audit` checks (a skipped tool, a network
   * hiccup). Present only when `--audit` ran; the CLI surfaces them on stderr.
   */
  auditDiagnostics?: string[];
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

  // --audit: opt-in supply-chain checks. Shell out to each present ecosystem's
  // advisory tool and verify the declared source repository resolves. Findings
  // merge into the result (so they count toward the report AND the exit code);
  // the inventory is rebuilt so the summary counts stay consistent. Both checks
  // degrade to diagnostics — never throw — so an offline run or a missing tool
  // can't fail the scan. The provenance HEAD request is injected (the networked
  // half lives in qScan; core stays offline per ADR-0005).
  let auditDiagnostics: string[] | undefined;
  if (options.audit) {
    const [advisories, provenance] = await Promise.all([
      scanAdvisories(options.path),
      checkProvenance(options.path, { network: true, head: repoHeadRequest }),
    ]);
    const extra = [...advisories.findings, ...provenance.findings];
    if (extra.length > 0) {
      result.findings = [...result.findings, ...extra].sort(compareFindings);
      result.inventory = buildInventory(result.findings);
    }
    auditDiagnostics = [...advisories.diagnostics, ...provenance.diagnostics];
  }

  // --write-baseline: snapshot every finding, persist, and exit cleanly.
  if (options.writeBaseline) {
    const baseline = await saveBaseline(options.writeBaseline, result.findings);
    return {
      result,
      suppressed: [],
      baselineWritten: baseline,
      ...(auditDiagnostics ? { auditDiagnostics } : {}),
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
  let exitCode = result.findings.some((f) => meetsThreshold(f.severity, options.severityThreshold))
    ? EXIT.FINDINGS
    : EXIT.OK;

  // --mandate: policy-as-code compliance gate. Deadline-aware — reports every
  // mandate-prohibited finding with its named clause + deadline, but fails the build
  // only once a deadline has passed (or early with --lead-months / --fail-now). Uses
  // the same RAW findings as the exit code, so triage can never flip the gate.
  let mandateEval: MandateEvaluation | undefined;
  if (options.mandates.length > 0) {
    assertKnownMandates(options.mandates);
    // Compose the org `--policy` in when one was supplied: acknowledged families
    // (permitted / in-transition) are annotated and exempt from the EARLY gates,
    // though a passed DISALLOW deadline still fails.
    mandateEval = evaluateMandates(result.findings, options.mandates, new Date(), policy);
    if (
      mandateGateFails(mandateEval, { leadMonths: options.leadMonths, failNow: options.failNow })
    ) {
      exitCode = EXIT.FINDINGS;
    }
  }

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
      return {
        result,
        suppressed,
        report: triaged.preflight,
        ...(auditDiagnostics ? { auditDiagnostics } : {}),
        exitCode: EXIT.OK,
      };
    }
  }

  // `--merge` only has an effect on a `--cbom` output. If the user asked to merge but
  // the format is not cbom, that is almost certainly a mistake (a typo'd `--cbom`, or a
  // pipeline that forgot it) — the merge files would be silently ignored and the
  // combined bill of materials never produced. Fail loudly instead of dropping data.
  if (options.mergeCboms && options.mergeCboms.length > 0 && options.format !== "cbom") {
    throw new Error(`--merge requires --format cbom (got ${options.format ?? "the human report"})`);
  }

  // `--sign` / `--timestamp` fill the evidence attestation, so they only make sense
  // with `--format evidence`. Fail loudly rather than silently ignore the signer.
  if ((options.sign || options.timestamp) && options.format !== "evidence") {
    throw new Error(
      `--sign/--timestamp require --format evidence (got ${options.format ?? "the human report"})`,
    );
  }
  // HNDL exposure (`--hndl`): read the declared data map, score every finding
  // and build the repo summary. Computed AFTER the exit code so it can never
  // change CI pass/fail - it only annotates + ranks. A missing / malformed
  // hndl.yml fails loudly (the user opted in), surfaced by the CLI as exit 2.
  let hndl: HndlReport | undefined;
  if (options.hndl) {
    const { map } = await loadHndlMap(options.path);
    hndl = computeHndl(result.findings, map);
  }

  const signer: EvidenceSigner | undefined = options.sign ? commandSigner(options.sign) : undefined;
  const timestamper: EvidenceSigner | undefined = options.timestamp
    ? commandSigner(options.timestamp)
    : undefined;

  // Load any external CBOMs to merge into a `--cbom` output (combined
  // code + infrastructure bill of materials). Only relevant for the cbom format.
  let mergeCbomsData: CycloneDxBom[] | undefined;
  if (options.format === "cbom" && options.mergeCboms && options.mergeCboms.length > 0) {
    mergeCbomsData = [];
    for (const path of options.mergeCboms) {
      let text: string;
      try {
        text = await readFile(path, "utf8");
      } catch {
        throw new Error(`--merge: cannot read CBOM file "${path}"`);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error(`--merge: "${path}" is not valid JSON`);
      }
      const bom = parsed as CycloneDxBom;
      if (bom?.bomFormat !== "CycloneDX") {
        throw new Error(`--merge: "${path}" is not a CycloneDX CBOM (missing bomFormat)`);
      }
      mergeCbomsData.push(bom);
    }
  }

  let report = renderReport(result, options.format, {
    color: hooks.color ?? false,
    redactSnippets: options.noSnippets,
    topN: options.topN,
    tier: options.tier,
    ...(options.profile ? { profile: options.profile } : {}),
    ...(policy ? { policy } : {}),
    ...(mergeCbomsData ? { mergeCboms: mergeCbomsData } : {}),
    ...(hndl ? { hndl } : {}),
    // The `--mandate` evaluation feeds the machine-readable JSON/SARIF/evidence
    // output too (not just the human block appended below).
    ...(mandateEval ? { mandate: mandateEval } : {}),
  });
  // Evidence signing is orchestrated here (async: an external signer may be async),
  // after the synchronous renderer has produced the unsigned report (ADR-0004: the
  // tool orchestrates a signer, it does not implement crypto).
  if (options.format === "evidence" && (signer || timestamper)) {
    const signed = await signReadinessReport(JSON.parse(report) as ReadinessReport, {
      signer,
      timestamper,
    });
    report = JSON.stringify(signed, null, 2);
  }

  if (mandateEval && options.format === "human") {
    report += "\n" + renderMandateBlock(mandateEval);
  }

  return {
    result,
    suppressed,
    report,
    ...(auditDiagnostics ? { auditDiagnostics } : {}),
    exitCode,
  };
}

/** A concise human compliance block appended to the default report for `--mandate`. */
function renderMandateBlock(ev: MandateEvaluation): string {
  const lines: string[] = [];
  lines.push(`Compliance mandates: ${ev.mandates.join(", ") || "(none matched)"}`);
  lines.push(
    `  ${ev.summary.violation} violation · ${ev.summary.deprecated} deprecated · ${ev.summary.due} due · ${ev.summary.conformant} conformant` +
      (ev.notInScope > 0 ? ` · ${ev.notInScope} out of scope` : "") +
      // Policy composition: how many of the above the org is knowingly managing.
      (ev.acknowledged > 0
        ? ` · ${ev.acknowledged} acknowledged${ev.policyName ? ` (${ev.policyName})` : ""}`
        : "") +
      (ev.nextDeadline ? ` · next deadline ${ev.nextDeadline}` : ""),
  );
  const rank: Record<string, number> = { violation: 0, deprecated: 1, due: 2, conformant: 3 };
  const rows = [...ev.findings].sort(
    (a, b) =>
      (rank[a.status] ?? 9) - (rank[b.status] ?? 9) || a.effective.localeCompare(b.effective),
  );
  for (const r of rows.slice(0, 12)) {
    const when =
      r.status === "violation"
        ? `disallowed since ${r.effective}`
        : r.status === "deprecated"
          ? `deprecated since ${r.effective}${r.disallowEffective ? `, disallowed ${r.disallowEffective}` : ""}`
          : `due ${r.effective} (${r.monthsUntil} mo)`;
    // Flag policy-acknowledged rows so the reader sees why the gate may not fire
    // on them (exempt from --fail-now / --lead-months, never from a violation).
    const ack = r.acknowledged ? ` · policy: ${r.policyVerdict ?? "acknowledged"}` : "";
    lines.push(`  [${r.status}] ${r.clause} · ${r.algorithm} ${r.file}:${r.line} — ${when}${ack}`);
  }
  if (rows.length > 12) lines.push(`  … and ${rows.length - 12} more`);
  return lines.join("\n");
}

/** Outcome of {@link runHndlInit}: the scaffold plus where it should be written. */
export interface HndlInitResult {
  /** Absolute path the `hndl.yml` should be written to. */
  path: string;
  /** True when a file already exists there (the CLI refuses to overwrite). */
  exists: boolean;
  /** The generated `hndl.yml` content. */
  content: string;
  /** How many findings the seeding scan produced. */
  findingsScanned: number;
  /** How many distinct data-adjacent (config-scope, HNDL) findings seeded stubs. */
  seededFindings: number;
}

/**
 * Scaffold an `hndl.yml` for a repo (`qscan hndl init`). Runs a scan to seed the
 * template with detected data-adjacent findings, then returns the generated
 * content and its target path WITHOUT writing it - the CLI owns file I/O and the
 * refuse-to-overwrite decision.
 */
export async function runHndlInit(
  opts: Partial<QscanOptions> & { path: string },
  hooks: RunQscanHooks = {},
): Promise<HndlInitResult> {
  const options: QscanOptions = { ...defaultOptions(), ...opts };
  const scanFn: ScanFn = hooks.scanFn ?? (options.parallel ? scanParallel : scan);
  const result = await scanFn(toScanOptions(options));

  const content = scaffoldHndlYaml(result.findings);
  const target = resolveHndlTarget(options.path);
  let exists = false;
  try {
    await stat(target);
    exists = true;
  } catch {
    exists = false;
  }
  const seededFindings = result.findings.filter(
    (f) => f.hndl && findingScope(f) === "config",
  ).length;
  return {
    path: target,
    exists,
    content,
    findingsScanned: result.findings.length,
    seededFindings,
  };
}

/** Resolve where `hndl init` writes: `<dir>/hndl.yml`, or an explicit `*.yml`. */
function resolveHndlTarget(root: string): string {
  const base = nodePath.basename(root);
  if (base === HNDL_FILENAME || base.endsWith(".yml") || base.endsWith(".yaml")) {
    return nodePath.resolve(root);
  }
  return nodePath.resolve(root, HNDL_FILENAME);
}

/** Outcome of {@link runCryptoAgilityEmit}: the rendered manifest and the scan. */
export interface CryptoAgilityEmitResult {
  /** The scan result the manifest was derived from. */
  result: ScanResult;
  /** The pretty-printed crypto-agility manifest JSON (no trailing newline). */
  manifest: string;
}

/**
 * Emit a crypto-agility manifest for a repo (`qscan crypto-agility emit` /
 * `--crypto-agility`). Runs a scan and derives the manifest from its inventory +
 * CBOM. This is deliberately additive: it NEVER consults the severity threshold and
 * the CLI always exits 0 (publishing a posture manifest must not fail CI). The
 * generation timestamp is stamped here (the CLI runtime), keeping the core builder
 * pure. A `--policy` file overlays its `transitionDeadline`; `--attestation` records
 * a credential URL verbatim (never fetched); `--hybrid-kex` / `--no-hybrid-kex`
 * assert hybrid-KEX use.
 */
export async function runCryptoAgilityEmit(
  opts: Partial<QscanOptions> & { path: string },
  hooks: RunQscanHooks = {},
): Promise<CryptoAgilityEmitResult> {
  const options: QscanOptions = { ...defaultOptions(), ...opts };
  const scanFn: ScanFn = hooks.scanFn ?? (options.parallel ? scanParallel : scan);
  const result = await scanFn(toScanOptions(options));

  let policy: CryptoPolicy | undefined;
  if (options.policy) {
    policy = parseCryptoPolicy(JSON.parse(await readFile(options.policy, "utf8")));
  }

  const manifest = buildCryptoAgilityManifest(result, {
    generatedAt: new Date().toISOString(),
    ...(options.attestation ? { attestationUrl: options.attestation } : {}),
    ...(options.hybridKexInUse !== undefined ? { hybridKexInUse: options.hybridKexInUse } : {}),
    ...(policy ? { policy } : {}),
    ...(process.env.GITHUB_REPOSITORY ? { repository: process.env.GITHUB_REPOSITORY } : {}),
    ...(process.env.GITHUB_SHA ? { commit: process.env.GITHUB_SHA } : {}),
  });
  return { result, manifest: JSON.stringify(manifest, null, 2) };
}

/**
 * Validate a LOCAL crypto-agility manifest file against the schema
 * (`qscan crypto-agility validate <file>`). Reads and parses the file, then defers
 * to core's {@link validateCryptoAgilityManifest}. Strictly offline: it never
 * fetches a URL (the attestation link and any remote manifest are a website-side
 * concern). Read / parse failures propagate to the CLI as an I/O error (exit 2); a
 * successfully-parsed but non-conforming manifest returns `{ valid: false }` and the
 * CLI exits non-zero.
 */
export async function runCryptoAgilityValidate(file: string): Promise<ManifestValidation> {
  const text = await readFile(file, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, errors: [`not valid JSON: ${message}`] };
  }
  return validateCryptoAgilityManifest(parsed);
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
  /** Standards regime for the migration-targets footer (`--profile`). */
  profile?: string;
  /** Org cryptography policy for the evidence report's §4 verdicts (`--policy`). */
  policy?: CryptoPolicy;
  /** External CBOMs to merge into the `cbom` output (CycloneDX bom-link). */
  mergeCboms?: CycloneDxBom[];
  /** HNDL exposure analysis (`--hndl`); annotates JSON/SARIF/human output. */
  hndl?: HndlReport;
  /**
   * Compliance-mandate evaluation (`--mandate`). Carried into the machine-readable
   * JSON (`mandateMapping`), SARIF (`run.properties.mandate`), and evidence
   * (date-pinned, hashed) output. The human block is appended separately by
   * {@link runQscan}.
   */
  mandate?: MandateEvaluation;
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
    profile = undefined,
    policy = undefined,
    mergeCboms = undefined,
    hndl = undefined,
    mandate = undefined,
  } = typeof opts === "boolean" ? { color: opts, policy: undefined } : opts;
  switch (format) {
    case "json":
      return renderJson(result, {
        redactSnippets,
        ...(hndl ? { hndl } : {}),
        ...(mandate ? { mandate } : {}),
      });
    case "sarif":
      return renderSarif(result, {
        redactSnippets,
        ...(hndl ? { hndl } : {}),
        ...(mandate ? { mandate } : {}),
      });
    case "cbom":
      return renderCbom(result, mergeCboms);
    case "vex":
      return renderVex(result);
    case "evidence": {
      // ISO A.8.24 readiness report; repo/commit come from CI env when present.
      // A `--policy` file adds the §4 conformant/violation/transition verdicts, and
      // `--mandate` adds the date-pinned, hashed `mandateMapping`. The attestation
      // is left unsigned here; signing is an async step in runQscan (an external
      // signer may be async), so this renderer stays synchronous.
      const report = buildReadinessReport(result, {
        repository: process.env.GITHUB_REPOSITORY,
        commit: process.env.GITHUB_SHA,
        ...(policy ? { policy } : {}),
        ...(mandate ? { mandate } : {}),
      });
      return JSON.stringify(report, null, 2);
    }
    case "human":
    default:
      return renderHuman(result, { color, topN, tier, profile, ...(hndl ? { hndl } : {}) });
  }
}

/** Re-export the core result types consumers commonly need. */
export type { Finding, ScanResult, ScanOptions } from "@quantakrypto/core";
