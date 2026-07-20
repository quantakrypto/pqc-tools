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
  formatProfileGuidance,
  getStandardsProfile,
  PQC_TRANSITION_NOTE,
  SEVERITY_ORDER,
  severityRank,
  STATEFUL_HBS_NOTE,
  toCbom,
  toJson,
  toOpenVex,
  toSarif,
  mergeCboms,
} from "@quantakrypto/core";
import type {
  CycloneDxBom,
  Finding,
  ReportOptions,
  ScanResult,
  SecurityTier,
  Severity,
  StandardsProfile,
} from "@quantakrypto/core";

/** Map the legacy `--tier` to its equivalent standards profile (back-compat alias). */
const TIER_TO_PROFILE: Record<SecurityTier, string> = {
  "category-3": "nist",
  "category-5": "cnsa-2.0",
};

/** Resolve the effective standards profile from `--profile` or the `--tier` alias. */
function resolveProfile(profileId?: string, tier?: SecurityTier): StandardsProfile | undefined {
  if (profileId) return getStandardsProfile(profileId);
  if (tier) return getStandardsProfile(TIER_TO_PROFILE[tier]);
  return undefined;
}

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
 *
 * When `extra` CBOMs are supplied (e.g. a qProbe endpoint CBOM), they are merged
 * with the scan CBOM via core's `mergeCboms`, producing a single combined
 * code + infrastructure bill of materials linked by CycloneDX bom-link.
 */
export function renderCbom(result: ScanResult, extra: readonly CycloneDxBom[] = []): string {
  const scanBom = toCbom(result);
  const bom = extra.length > 0 ? mergeCboms([scanBom, ...extra]) : scanBom;
  return JSON.stringify(bom, null, 2);
}

/**
 * Render an OpenVEX 0.2.0 document for the scan (pretty-printed, no trailing
 * newline). Delegates to core's `toOpenVex` so the VEX shape stays consistent
 * across the monorepo. Carries any `--triage` verdicts into `status_notes`.
 */
export function renderVex(result: ScanResult): string {
  return JSON.stringify(toOpenVex(result), null, 2);
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
  opts: { color?: boolean; topN?: number; tier?: SecurityTier; profile?: string } = {},
): string {
  const c = opts.color ? COLOR : PLAIN;
  const topN = opts.topN ?? 5;
  const { findings, inventory, filesScanned } = result;
  // `analyzedFiles`: of the scanned files, how many were in a language the
  // scanner can actually inspect for crypto (JS/TS, Python, Go, Java). When it's 0 the
  // readiness score reflects no analyzable code — say so rather than imply safe.
  const analyzedFiles = result.analyzedFiles;
  const noAnalyzable = analyzedFiles === 0;
  // Partial-coverage honesty: when the analyzable subset is only a small slice of
  // what was scanned, a high score reflects that slice, not the whole tree. We
  // surface a one-line caveat next to the score so the number isn't over-trusted.
  // Skips the zero case (handled explicitly below) and normal repos where most
  // files are analyzable.
  const lowCoverage =
    analyzedFiles !== undefined &&
    analyzedFiles > 0 &&
    filesScanned > 0 &&
    analyzedFiles / filesScanned < 0.25;
  const coverageCaveat = lowCoverage
    ? `${c.dim}Note: the score covers only ${analyzedFiles} analyzable of ${filesScanned} scanned files (${ANALYZABLE_LANGUAGES_LABEL}); crypto in unsupported languages is not reflected.${c.reset}`
    : "";
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
    if (coverageCaveat) lines.push(coverageCaveat);
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
  if (coverageCaveat) lines.push(coverageCaveat);
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

  // Regime-tailored migration targets (`--profile`, or the `--tier` alias). Surfaces
  // the parameter sets AND the regime's hybrid stance so guidance isn't regime-wrong.
  const profile = resolveProfile(opts.profile, opts.tier);
  if (profile) {
    lines.push("");
    const g = formatProfileGuidance(inventory.byAlgorithm, profile);
    lines.push(`${c.bold}${g[0]}${c.reset}`);
    for (const t of g.slice(1)) lines.push(`${c.cyan}${t}${c.reset}`);
  }

  // Forward-looking standards + the IR 8547 migration deadline (HQC / FN-DSA /
  // X-Wing) — the long-horizon guidance behind anything flagged above.
  lines.push("");
  lines.push(`${c.bold}Standards & timeline${c.reset}`);
  lines.push(`${c.dim}${PQC_TRANSITION_NOTE}${c.reset}`);
  if (findings.some((f) => f.category === "signature")) {
    lines.push(`${c.dim}${STATEFUL_HBS_NOTE}${c.reset}`);
  }

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
