/**
 * `qremediate` — apply deterministic, verified fixes to quantum-vulnerable /
 * insecure crypto findings.
 *
 * Pipeline: scan → for each finding, a codemod proposes a patch → the core
 * remediation pipeline gates it (patch-policy + verify_fix) → verified patches
 * are shown (`diff`), written (`apply`), or (Phase 3) opened as a draft PR.
 * Never auto-merges. LLM-proposed fixes (`--llm`) land in Phase 3.
 */
import { readFile as fsReadFile, writeFile as fsWriteFile } from "node:fs/promises";
import path from "node:path";

import { scan, codemodFor, remediateFindings, isManifestFile } from "@quantakrypto/core";
import type { Finding, Patch, ScanResult, VerifiedPatch, RejectedPatch } from "@quantakrypto/core";

export type RemediateMode = "diff" | "apply" | "pr";

export interface RemediateOptions {
  path: string;
  mode: RemediateMode;
  /** Use an LLM to propose fixes codemods can't (Phase 3). */
  llm: boolean;
}

export interface RemediateRun {
  output: string;
  exitCode: number;
  /** Relative paths written (apply mode). */
  written: string[];
}

export interface RemediateHooks {
  scanFn?: (root: string) => Promise<ScanResult>;
  readFile?: (abs: string) => Promise<string>;
  writeFile?: (abs: string, content: string) => Promise<void>;
  /** Phase 3: LLM patch source. */
  llmPatchSource?: (finding: Finding, content: string) => Promise<Patch | null>;
}

/** Process exit codes qremediate uses. */
export const REMEDIATE_EXIT = { OK: 0, CHANGES: 0, ERROR: 2 } as const;

/** Minimal unified diff for a localized change (3 lines of context). */
export function unifiedDiff(relPath: string, before: string, after: string): string {
  if (before === after) return "";
  const a = before.split("\n");
  const b = after.split("\n");
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length - 1;
  let endB = b.length - 1;
  while (endA >= start && endB >= start && a[endA] === b[endB]) {
    endA--;
    endB--;
  }
  const ctx = 3;
  const from = Math.max(0, start - ctx);
  const toA = Math.min(a.length - 1, endA + ctx);
  const toB = Math.min(b.length - 1, endB + ctx);
  const lines: string[] = [`--- a/${relPath}`, `+++ b/${relPath}`];
  lines.push(`@@ -${from + 1},${toA - from + 1} +${from + 1},${toB - from + 1} @@`);
  for (let i = from; i < start; i++) lines.push(` ${a[i]}`);
  for (let i = start; i <= endA; i++) lines.push(`-${a[i]}`);
  for (let i = start; i <= endB; i++) lines.push(`+${b[i]}`);
  for (let i = endA + 1; i <= toA; i++) lines.push(` ${a[i]}`);
  return lines.join("\n");
}

/** Run a complete qremediate pass. Pure w.r.t. process; the bin prints + exits. */
export async function runRemediate(
  options: RemediateOptions,
  hooks: RemediateHooks = {},
): Promise<RemediateRun> {
  const root = path.resolve(options.path);
  const readFile = hooks.readFile ?? ((abs: string) => fsReadFile(abs, "utf8"));
  const writeFile =
    hooks.writeFile ?? ((abs: string, content: string) => fsWriteFile(abs, content, "utf8"));
  const scanFn = hooks.scanFn ?? ((r: string) => scan({ root: r }));

  const result = await scanFn(root);
  const findings = result.findings;

  // Policy context: source findings' files, plus manifest files (for dep adds).
  const findingFiles = new Set(findings.map((f) => f.location.file));
  const manifestFiles = new Set(
    findings.filter((f) => isManifestFile(f.location.file)).map((f) => f.location.file),
  );

  // Codemods first; the LLM (Phase 3) fills gaps only when --llm is set.
  const patchSource = async (finding: Finding, content: string): Promise<Patch | null> => {
    const codemod = codemodFor(finding);
    if (codemod) return codemod.apply(content, finding);
    if (options.llm && hooks.llmPatchSource) return hooks.llmPatchSource(finding, content);
    return null;
  };

  // Cache file reads so multiple findings in one file read it once.
  const contentCache = new Map<string, string>();
  const readContent = async (finding: Finding): Promise<string> => {
    const abs = path.resolve(root, finding.location.file);
    let c = contentCache.get(abs);
    if (c === undefined) {
      c = await readFile(abs);
      contentCache.set(abs, c);
    }
    return c;
  };

  const rem = await remediateFindings(findings, {
    readContent,
    patchSource,
    policy: { findingFiles, manifestFiles },
  });

  // Dedupe verified patches by path (several findings in a file share one fix).
  const byPath = new Map<string, VerifiedPatch>();
  for (const vp of rem.applied) if (!byPath.has(vp.patch.path)) byPath.set(vp.patch.path, vp);
  const patches = [...byPath.values()];

  if (options.mode === "pr") {
    return {
      output:
        "qremediate: --mode pr is not available yet (draft-PR mode ships with the LLM " +
        "remediation layer). Use --mode diff or --mode apply for now.",
      exitCode: REMEDIATE_EXIT.ERROR,
      written: [],
    };
  }

  if (patches.length === 0) {
    return {
      output: summarize(findings, patches, rem.rejected, options.mode, []),
      exitCode: REMEDIATE_EXIT.OK,
      written: [],
    };
  }

  const written: string[] = [];
  const diffs: string[] = [];
  for (const vp of patches) {
    const abs = path.resolve(root, vp.patch.path);
    const before = contentCache.get(abs) ?? (await readContent(vp.finding));
    if (options.mode === "apply") {
      await writeFile(abs, vp.patch.newContent);
      written.push(vp.patch.path);
    } else {
      diffs.push(unifiedDiff(vp.patch.path, before, vp.patch.newContent));
    }
  }

  const body = options.mode === "diff" ? `${diffs.join("\n\n")}\n\n` : "";
  return {
    output: body + summarize(findings, patches, rem.rejected, options.mode, written),
    exitCode: REMEDIATE_EXIT.OK,
    written,
  };
}

function summarize(
  findings: readonly Finding[],
  patches: VerifiedPatch[],
  rejected: RejectedPatch[],
  mode: RemediateMode,
  written: string[],
): string {
  const lines: string[] = [];
  lines.push(
    `qremediate: ${findings.length} finding(s), ${patches.length} verified fix(es), ${rejected.length} not auto-fixable.`,
  );
  if (mode === "apply" && written.length) {
    lines.push(`Wrote: ${written.join(", ")}`);
  } else if (mode === "diff" && patches.length) {
    lines.push("Review the diff above, then re-run with --mode apply to write it.");
  }
  if (rejected.length) {
    lines.push("Not auto-fixed (needs review or the LLM layer):");
    for (const r of rejected.slice(0, 10)) {
      lines.push(
        `  - ${r.finding.ruleId} ${r.finding.location.file}:${r.finding.location.line} — ${r.reason}`,
      );
    }
    if (rejected.length > 10) lines.push(`  … and ${rejected.length - 10} more.`);
  }
  return lines.join("\n");
}

/** Parse qremediate argv (path + --mode + --llm + -h/-v). */
export function parseRemediateArgs(
  argv: readonly string[],
):
  | { kind: "run"; options: RemediateOptions }
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "error"; message: string } {
  const options: RemediateOptions = { path: ".", mode: "diff", llm: false };
  let positional: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    let flag = arg;
    let inline: string | undefined;
    if (arg.startsWith("--") && arg.includes("=")) {
      const eq = arg.indexOf("=");
      flag = arg.slice(0, eq);
      inline = arg.slice(eq + 1);
    }
    const take = (): string | undefined => inline ?? argv[++i];
    switch (flag) {
      case "-h":
      case "--help":
        return { kind: "help" };
      case "-v":
      case "--version":
        return { kind: "version" };
      case "--mode": {
        const v = take();
        if (v !== "diff" && v !== "apply" && v !== "pr") {
          return { kind: "error", message: `invalid --mode "${v ?? ""}" (expected diff|apply|pr)` };
        }
        options.mode = v;
        break;
      }
      case "--llm":
        options.llm = true;
        break;
      default:
        if (flag.startsWith("-")) return { kind: "error", message: `unknown option "${flag}"` };
        if (positional !== undefined)
          return { kind: "error", message: `unexpected argument "${arg}"` };
        positional = arg;
    }
  }
  if (positional !== undefined) options.path = positional;
  return { kind: "run", options };
}

export const REMEDIATE_HELP = `qremediate — apply deterministic, verified fixes for insecure crypto findings

USAGE
  qremediate [path] [--mode diff|apply|pr] [--llm]

OPTIONS
  --mode diff    Print a unified diff of every verified fix (default; writes nothing)
  --mode apply   Write verified fixes into the working tree
  --mode pr      Open a draft PR (ships with the LLM remediation layer)
  --llm          Also let a BYOK LLM propose fixes codemods can't (Phase 3)
  -h, --help     Show this help
  -v, --version  Show version

Every fix must pass the verify_fix gate (the finding is gone, no new finding) and
the patch policy (only files with findings + dependency manifests). Never merges.
`;
