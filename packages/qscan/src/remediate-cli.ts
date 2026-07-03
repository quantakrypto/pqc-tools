/**
 * `qremediate` — apply deterministic, verified fixes to quantum-vulnerable /
 * insecure crypto findings.
 *
 * Pipeline: scan → for each finding, a codemod (then optionally the LLM with
 * `--llm`) proposes a patch → the core remediation pipeline gates it
 * (patch-policy + verify_fix) → verified patches are shown (`diff`), written
 * (`apply`), or opened as a DRAFT PR (`pr`). Never auto-merges.
 */
import { readFile as fsReadFile, writeFile as fsWriteFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";

import {
  scan,
  codemodFor,
  remediateFindings,
  isManifestFile,
  fingerprintFinding,
  withWorktree,
} from "@quantakrypto/core";
import type { Finding, Patch, ScanResult, VerifiedPatch, RejectedPatch } from "@quantakrypto/core";

import type { LlmProvider } from "./args.js";

const exec = promisify(execFile);

export type RemediateMode = "diff" | "apply" | "pr";

export interface RemediateOptions {
  path: string;
  mode: RemediateMode;
  /** Use a BYOK LLM to propose fixes codemods can't. */
  llm: boolean;
  provider?: LlmProvider;
  model?: string;
}

export interface RemediateRun {
  output: string;
  exitCode: number;
  /** Relative paths written (apply mode) or included in the PR. */
  written: string[];
}

/** A verified fix set ready to become a draft PR. */
export interface DraftPrPlan {
  branch: string;
  title: string;
  body: string;
  patches: { path: string; newContent: string }[];
}

/** Open a draft PR for the plan (injectable; default shells git + gh in a worktree). */
export type OpenDraftPr = (plan: DraftPrPlan) => Promise<{ url?: string }>;

export interface RemediateHooks {
  scanFn?: (root: string) => Promise<ScanResult>;
  readFile?: (abs: string) => Promise<string>;
  writeFile?: (abs: string, content: string) => Promise<void>;
  /** LLM patch source (default wraps `@quantakrypto/agent`'s proposeFix). */
  llmPatchSource?: (finding: Finding, content: string) => Promise<Patch | null>;
  /** Draft-PR backend (default: git worktree + gh). */
  openDraftPr?: OpenDraftPr;
  resolveKey?: () => string | undefined;
  stderr?: (s: string) => void;
  /** Branch suffix (injected for deterministic tests). */
  branchSuffix?: string;
}

export const REMEDIATE_EXIT = { OK: 0, CHANGES: 0, ERROR: 2 } as const;

function envKey(provider: LlmProvider): string | undefined {
  return (
    process.env.QK_LLM_API_KEY ??
    (provider === "anthropic" ? process.env.ANTHROPIC_API_KEY : process.env.OPENAI_API_KEY)
  );
}

function defaultModel(provider: LlmProvider): string {
  return provider === "anthropic" ? "claude-sonnet-5" : "gpt-4o-mini";
}

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

/**
 * Default draft-PR backend: apply the patches inside an ephemeral worktree
 * (never touching the user's checkout), commit on a new branch, push it, and
 * `gh pr create --draft`. NEVER merges.
 */
async function defaultOpenDraftPr(root: string, plan: DraftPrPlan): Promise<{ url?: string }> {
  return withWorktree(root, async (dir) => {
    await exec("git", ["-C", dir, "checkout", "-b", plan.branch]);
    for (const p of plan.patches) {
      await fsWriteFile(path.resolve(dir, p.path), p.newContent, "utf8");
    }
    await exec("git", ["-C", dir, "add", ...plan.patches.map((p) => p.path)]);
    await exec("git", ["-C", dir, "commit", "-m", plan.title]);
    await exec("git", ["-C", dir, "push", "-u", "origin", plan.branch]);
    const { stdout } = await exec(
      "gh",
      [
        "pr",
        "create",
        "--draft",
        "--head",
        plan.branch,
        "--title",
        plan.title,
        "--body",
        plan.body,
      ],
      { cwd: dir },
    );
    return { url: stdout.trim() };
  });
}

function prBody(
  patches: VerifiedPatch[],
  rejected: RejectedPatch[],
  options: RemediateOptions,
): string {
  const lines: string[] = [
    "Automated post-quantum remediation from `qremediate`.",
    "",
    `**${patches.length} fix(es)** — each passed the verify_fix gate (finding gone, no new finding) and the patch policy.`,
    "",
  ];
  for (const vp of patches) {
    lines.push(`- \`${vp.patch.path}\` — ${vp.finding.ruleId} (${vp.patch.source})`);
  }
  if (options.llm) {
    lines.push(
      "",
      `LLM-proposed fixes were included; context shared at the \`file\` level with secrets redacted.`,
    );
  }
  if (rejected.length) {
    lines.push("", `${rejected.length} finding(s) were not auto-fixable and need review.`);
  }
  lines.push("", "This is a **draft** PR and was NOT merged. Review every change before merging.");
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
  const stderr = hooks.stderr ?? ((s: string) => void process.stderr.write(s));

  const result = await scanFn(root);
  const findings = result.findings;

  const findingFiles = new Set(findings.map((f) => f.location.file));
  const manifestFiles = new Set(
    findings.filter((f) => isManifestFile(f.location.file)).map((f) => f.location.file),
  );

  // Build the optional LLM patch source (codemods always run first).
  const provider: LlmProvider = options.provider ?? "anthropic";
  const model = options.model ?? defaultModel(provider);
  let llmSource: ((finding: Finding, content: string) => Promise<Patch | null>) | undefined =
    hooks.llmPatchSource;
  if (!llmSource && options.llm) {
    const key = hooks.resolveKey ? hooks.resolveKey() : envKey(provider);
    if (!key) {
      stderr(
        "qremediate: --llm needs an API key (QK_LLM_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY). Using codemods only.\n",
      );
    } else {
      llmSource = async (finding) => {
        const agent = await import("@quantakrypto/agent");
        const client = agent.resolveClient({ provider, model, apiKey: key });
        const proposal = await agent.proposeFix(finding, {
          client,
          readFile: (rel) => readFile(path.resolve(root, rel)),
          fingerprint: fingerprintFinding,
        });
        if (!proposal) return null;
        return {
          path: proposal.path,
          newContent: proposal.newContent,
          ruleId: finding.ruleId,
          source: "llm",
        };
      };
    }
  }

  const patchSource = async (finding: Finding, content: string): Promise<Patch | null> => {
    const codemod = codemodFor(finding);
    if (codemod) return codemod.apply(content, finding);
    if (llmSource) return llmSource(finding, content);
    return null;
  };

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

  const byPath = new Map<string, VerifiedPatch>();
  for (const vp of rem.applied) if (!byPath.has(vp.patch.path)) byPath.set(vp.patch.path, vp);
  const patches = [...byPath.values()];

  if (patches.length === 0) {
    return {
      output: summarize(findings, patches, rem.rejected, options.mode, []),
      exitCode: REMEDIATE_EXIT.OK,
      written: [],
    };
  }

  if (options.mode === "pr") {
    const openPr = hooks.openDraftPr ?? ((plan: DraftPrPlan) => defaultOpenDraftPr(root, plan));
    const suffix = hooks.branchSuffix ?? `${Date.now()}`;
    const plan: DraftPrPlan = {
      branch: `quantakrypto/remediate-${suffix}`,
      title: `qremediate: migrate ${patches.length} quantum-vulnerable finding(s)`,
      body: prBody(patches, rem.rejected, options),
      patches: patches.map((vp) => ({ path: vp.patch.path, newContent: vp.patch.newContent })),
    };
    try {
      const { url } = await openPr(plan);
      return {
        output: `qremediate: opened a DRAFT PR${url ? ` (${url})` : ""} on branch ${plan.branch} with ${patches.length} verified fix(es). Nothing was merged — review it.`,
        exitCode: REMEDIATE_EXIT.OK,
        written: plan.patches.map((p) => p.path),
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        output: `qremediate: could not open a draft PR (${msg}). No changes were pushed; run with --mode diff/apply instead.`,
        exitCode: REMEDIATE_EXIT.ERROR,
        written: [],
      };
    }
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

/** Parse qremediate argv. */
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
      case "--llm-provider": {
        const v = take();
        if (v !== "anthropic" && v !== "openai-compatible") {
          return { kind: "error", message: `invalid --llm-provider "${v ?? ""}"` };
        }
        options.provider = v;
        break;
      }
      case "--llm-model":
        options.model = take();
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
  qremediate [path] [--mode diff|apply|pr] [--llm] [--llm-provider <p>] [--llm-model <m>]

OPTIONS
  --mode diff    Print a unified diff of every verified fix (default; writes nothing)
  --mode apply   Write verified fixes into the working tree
  --mode pr      Commit verified fixes to a new branch and open a DRAFT PR (never merges)
  --llm          Also let a BYOK LLM propose fixes codemods can't (needs an API key)
  --llm-provider anthropic | openai-compatible (default: anthropic)
  --llm-model    Model id for the BYOK provider
  -h, --help     Show this help
  -v, --version  Show version

Every fix must pass the verify_fix gate (the finding is gone, no new finding) and
the patch policy (only files with findings + dependency manifests). Never merges.
`;
