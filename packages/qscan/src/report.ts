/**
 * qScan report rendering.
 *
 * Produces the three output formats the CLI supports:
 *  - `human`  — a tasteful plain-text banner (counts, top findings, readiness
 *               score, and a one-line next step). Optional raw ANSI color.
 *  - `json`   — the structured scan result via core's `toJson`.
 *  - `sarif`  — SARIF 2.1.0 via core's `toSarif`.
 *
 * Only `human` lives here; `json`/`sarif` delegate to `@quantakrypto/core` so the
 * serialized shape stays consistent across every tool in the monorepo.
 */

import {
  ANALYZABLE_LANGUAGES_LABEL,
  defaultRegistry,
  DEP_VULNERABLE_RULE,
  SEVERITY_ORDER,
  severityRank,
  toCbom,
  toJson,
  toSarif,
} from "@quantakrypto/core";
import type { Finding, ReportOptions, ScanResult, Severity } from "@quantakrypto/core";

/** Minimal ANSI palette. Empty strings when color is disabled. */
interface Palette {
  reset: string;
  bold: string;
  dim: string;
  red: string;
  yellow: string;
  green: string;
  cyan: string;
}

const PLAIN: Palette = { reset: "", bold: "", dim: "", red: "", yellow: "", green: "", cyan: "" };
const COLOR: Palette = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
};

/**
 * Render the JSON report (pretty-printed, no trailing newline).
 *
 * Delegates to core's `toJson` for a monorepo-consistent shape. `opts` is passed
 * straight through (e.g. `{ redactSnippets: true }` for `--no-snippets`).
 */
export function renderJson(result: ScanResult, opts?: ReportOptions): string {
  return JSON.stringify(toJson(result, opts), null, 2);
}

/**
 * Render the SARIF 2.1.0 report (pretty-printed, no trailing newline).
 *
 * Delegates to core's `toSarif` — the monorepo's single source of truth for the
 * SARIF shape (schema, tool driver, rules, taxonomies). `opts` is passed through
 * (e.g. `{ redactSnippets: true }` for `--no-snippets`).
 */
export function renderSarif(result: ScanResult, opts?: ReportOptions): string {
  // Advertise the full rule catalog (not just the rules that fired) so SARIF
  // consumers see complete metadata for every rule qScan can emit. The detector
  // registry's catalog is source/config rules only; `dep-vulnerable` comes from
  // the manifest scanner, so add its generic entry — otherwise SARIF would build
  // that rule from the first dependency finding and leak one package's specifics
  // into the shared rule description.
  const catalog = [...defaultRegistry.ruleCatalog(), DEP_VULNERABLE_RULE];
  return JSON.stringify(toSarif(result, { catalog, ...opts }), null, 2);
}

/**
 * Render a CycloneDX 1.6 CBOM (cryptographic bill of materials) for the scan,
 * pretty-printed with no trailing newline. Delegates to core's `toCbom` so the
 * serialized shape stays consistent across every tool in the monorepo.
 */
export function renderCbom(result: ScanResult): string {
  return JSON.stringify(toCbom(result), null, 2);
}

/**
 * Render the human-readable banner.
 *
 * @param result The scan result.
 * @param opts.color Emit raw ANSI escapes (default: false / plain text).
 * @param opts.topN How many findings to list (default: 5).
 */
export function renderHuman(
  result: ScanResult,
  opts: { color?: boolean; topN?: number } = {},
): string {
  const c = opts.color ? COLOR : PLAIN;
  const topN = opts.topN ?? 5;
  const { findings, inventory, filesScanned } = result;
  // `analyzedFiles`: of the scanned files, how many were in a language the
  // scanner can actually inspect for crypto (JS/TS, Python, Go, Java). When it's 0 the
  // readiness score reflects no analyzable code — say so rather than imply safe.
  const analyzedFiles = result.analyzedFiles;
  const noAnalyzable = analyzedFiles === 0;
  const lines: string[] = [];

  lines.push(`${c.bold}qScan — quantum-vulnerable cryptography report${c.reset}`);
  const coverage =
    analyzedFiles === undefined
      ? ""
      : `  •  analyzed: ${analyzedFiles} (${ANALYZABLE_LANGUAGES_LABEL})`;
  lines.push(
    `${c.dim}root: ${result.root}  •  files scanned: ${filesScanned}${coverage}  •  qscan v${result.toolVersion}${c.reset}`,
  );
  // Coverage diagnostics: warn when files were skipped, so a low finding count
  // isn't mistaken for a clean scan of the whole tree.
  const diag = result.diagnostics;
  if (diag && (diag.unreadable > 0 || diag.skippedMinified > 0)) {
    const parts: string[] = [];
    if (diag.unreadable > 0) parts.push(`${diag.unreadable} unreadable`);
    if (diag.skippedMinified > 0) parts.push(`${diag.skippedMinified} skipped (minified)`);
    lines.push(`${c.yellow}Coverage: ${parts.join(", ")} — results may be incomplete.${c.reset}`);
  }
  lines.push("");

  if (findings.length === 0) {
    if (noAnalyzable && filesScanned > 0) {
      // Honesty guard: don't let a 100/100 read as "safe" when nothing the
      // scanner understands was analyzed — the crypto may live in an
      // unsupported language (Go, Java, Rust, C#, …).
      lines.push(
        `${c.yellow}No analyzable source found.${c.reset} Scanned ${filesScanned} file${
          filesScanned === 1 ? "" : "s"
        }, but none were in a supported language (${ANALYZABLE_LANGUAGES_LABEL}).`,
      );
      lines.push(
        `${c.dim}The score below covers only what qScan can read today — it is NOT a clean bill of health for this codebase.${c.reset}`,
      );
      lines.push(
        `${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100 (no analyzable source)${c.reset}`,
      );
      lines.push("");
      lines.push(
        `${c.dim}Next step:${c.reset} multi-language support is expanding; track coverage before relying on the score.`,
      );
      return lines.join("\n");
    }
    lines.push(`${c.green}No quantum-vulnerable cryptography detected.${c.reset}`);
    lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
    lines.push("");
    lines.push(`${c.dim}Next step:${c.reset} keep scanning in CI to catch regressions.`);
    return lines.join("\n");
  }

  // Severity counts, most-severe first.
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = inventory.bySeverity[sev] ?? 0;
    return n > 0 ? `${severityColor(sev, c)}${n} ${sev}${c.reset}` : null;
  }).filter((s): s is string => s !== null);

  lines.push(
    `${c.bold}${findings.length} finding${findings.length === 1 ? "" : "s"}${c.reset}  (${counts.join(", ")})`,
  );
  if (inventory.hndlCount > 0) {
    lines.push(
      `${c.yellow}${inventory.hndlCount}${c.reset} exposed to harvest-now-decrypt-later (HNDL).`,
    );
  }
  lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
  lines.push("");

  // Top findings, sorted by severity then file/line for determinism.
  const top = [...findings].sort(compareFindings).slice(0, topN);
  lines.push(`${c.bold}Top findings${c.reset}`);
  for (const f of top) {
    const loc = `${f.location.file}:${f.location.line}`;
    lines.push(
      `  ${severityColor(f.severity, c)}${f.severity.padEnd(8)}${c.reset} ${c.cyan}${f.ruleId}${c.reset}  ${loc}`,
    );
    lines.push(`           ${f.message}`);
    if (f.remediation) {
      lines.push(`           ${c.dim}→ ${f.remediation}${c.reset}`);
    }
  }
  if (findings.length > top.length) {
    lines.push(`  ${c.dim}…and ${findings.length - top.length} more${c.reset}`);
  }
  lines.push("");
  lines.push(`${c.dim}Next step:${c.reset} ${nextStep(findings)}`);

  return lines.join("\n");
}

/** Suggest a single concrete next action based on the worst finding. */
function nextStep(findings: Finding[]): string {
  const worst = [...findings].sort(compareFindings)[0];
  if (!worst) return "review the findings above.";
  // A dependency finding points at a manifest — you replace the *package*, not
  // "migrate package.json". Phrase it as a dependency swap.
  if (worst.category === "dependency") {
    return worst.remediation
      ? `replace the vulnerable dependency in ${worst.location.file} — ${worst.remediation}`
      : `replace the vulnerable dependency in ${worst.location.file}.`;
  }
  if (worst.remediation) {
    return `migrate ${worst.location.file} — ${worst.remediation}`;
  }
  return `triage ${worst.ruleId} in ${worst.location.file}:${worst.location.line}.`;
}

/** Deterministic ordering: most severe first, then file, then line. */
function compareFindings(a: Finding, b: Finding): number {
  const bySev = severityRank(a.severity) - severityRank(b.severity);
  if (bySev !== 0) return bySev;
  const byFile = a.location.file.localeCompare(b.location.file);
  if (byFile !== 0) return byFile;
  return a.location.line - b.location.line;
}

/** Color the readiness score green/yellow/red by band. */
function readiness(score: number, c: Palette): string {
  const color = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  return `${color}${score}${c.reset}`;
}

/** Map a severity to its palette color. */
function severityColor(severity: Severity, c: Palette): string {
  switch (severity) {
    case "critical":
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    default:
      return c.dim;
  }
}
