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
  /** Actually write LLM-proposed fixes in `apply` mode (they are otherwise shown
   * as diffs and held back — an LLM rewrite must be reviewed, not auto-applied). */
  applyLlm?: boolean;
  /** Cap how many findings are sent to the LLM (spend/DoS guard). */
  maxLlm?: number;
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
interface DraftPrPlan {
  branch: string;
  title: string;
  body: string;
  patches: { path: string; newContent: string }[];
}

/** Open a draft PR for the plan (injectable; default shells git + gh in a worktree). */
type OpenDraftPr = (plan: DraftPrPlan) => Promise<{ url?: string }>;

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

/** Default per-run cap on paid LLM fix proposals (spend/DoS guard; override with --max-llm). */
const DEFAULT_MAX_LLM = 25;

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
    await exec("git", ["-C", dir, "add", "--", ...plan.patches.map((p) => p.path)]);
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
  const codemodN = patches.filter((p) => p.patch.source === "codemod").length;
  const llmN = patches.length - codemodN;
  const lines: string[] = [
    "Automated post-quantum remediation from `qremediate`.",
    "",
    `**${patches.length} fix(es)** — ${codemodN} deterministic codemod fix(es) and ${llmN} LLM-proposed. ` +
      `Each cleared the verify_fix gate (target finding gone, no new finding) and the patch policy.`,
    "",
  ];
  for (const vp of patches) {
    lines.push(`- \`${vp.patch.path}\` — ${vp.finding.ruleId} (${vp.patch.source})`);
  }
  if (llmN > 0) {
    lines.push(
      "",
      `⚠️ The ${llmN} LLM-proposed fix(es) are **crypto-verified, not security-reviewed**: the gate ` +
        `only proves the crypto finding is gone, not that the rest of the rewrite is safe. Read every ` +
        `LLM diff before merging. Context was shared at the \`file\` level with secrets redacted (best-effort).`,
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
  const maxLlm = options.maxLlm ?? DEFAULT_MAX_LLM;
  let llmCalls = 0;
  let llmCapHit = false;
  let baseLlmSource = hooks.llmPatchSource;
  if (!baseLlmSource && options.llm) {
    const key = hooks.resolveKey ? hooks.resolveKey() : envKey(provider);
    if (!key) {
      stderr(
        "qremediate: --llm needs an API key (QK_LLM_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY). Using codemods only.\n",
      );
    } else {
      baseLlmSource = async (finding) => {
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
  // Spend/DoS guard: cap the number of paid LLM proposals per run.
  const llmSource: ((finding: Finding, content: string) => Promise<Patch | null>) | undefined =
    baseLlmSource
      ? async (finding, content) => {
          if (llmCalls >= maxLlm) {
            llmCapHit = true;
            return null;
          }
          llmCalls++;
          return baseLlmSource!(finding, content);
        }
      : undefined;

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
  const heldBack: VerifiedPatch[] = [];
  for (const vp of patches) {
    const abs = path.resolve(root, vp.patch.path);
    const before = contentCache.get(abs) ?? (await readContent(vp.finding));
    // An LLM rewrite is only crypto-verified, not security-reviewed — never write
    // it in `apply` mode without an explicit `--apply-llm` acknowledgement. It is
    // shown as a diff to review instead. Deterministic codemods write normally.
    const holdForReview =
      options.mode === "apply" && vp.patch.source === "llm" && !options.applyLlm;
    if (options.mode === "apply" && !holdForReview) {
      await writeFile(abs, vp.patch.newContent);
      written.push(vp.patch.path);
    } else {
      if (holdForReview) heldBack.push(vp);
      diffs.push(unifiedDiff(vp.patch.path, before, vp.patch.newContent));
    }
  }

  const showDiffs = options.mode === "diff" || heldBack.length > 0;
  const body = showDiffs ? `${diffs.join("\n\n")}\n\n` : "";
  return {
    output:
      body +
      summarize(
        findings,
        patches,
        rem.rejected,
        options.mode,
        written,
        heldBack,
        llmCapHit ? maxLlm : 0,
      ),
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
  heldBack: VerifiedPatch[] = [],
  llmCapMax = 0,
): string {
  const codemodN = patches.filter((p) => p.patch.source === "codemod").length;
  const llmN = patches.length - codemodN;
  const lines: string[] = [];
  lines.push(
    `qremediate: ${findings.length} finding(s), ${patches.length} candidate fix(es) ` +
      `(${codemodN} codemod-verified, ${llmN} LLM-proposed), ${rejected.length} not auto-fixable.`,
  );
  if (mode === "apply" && written.length) {
    lines.push(`Wrote: ${written.join(", ")}`);
  }
  if (heldBack.length) {
    lines.push(
      `Held back ${heldBack.length} LLM fix(es) (shown as diffs above): crypto-verified but ` +
        `NOT security-reviewed — read them, then re-run with --apply-llm to write them.`,
    );
  } else if (mode === "diff" && patches.length) {
    lines.push(
      llmN > 0
        ? "Review the diff above — codemod fixes are deterministic; LLM fixes need a human read. Then --mode apply (add --apply-llm for the LLM ones)."
        : "Review the diff above, then re-run with --mode apply to write it.",
    );
  }
  if (llmCapMax) {
    lines.push(
      `Note: hit the --max-llm cap (${llmCapMax}); some findings were not sent to the LLM — raise it to cover more.`,
    );
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
      case "--apply-llm":
        options.applyLlm = true;
        break;
      case "--max-llm": {
        const v = take();
        const n = Number(v);
        if (!Number.isInteger(n) || n < 0) {
          return {
            kind: "error",
            message: `invalid --max-llm "${v ?? ""}" (expected a non-negative integer)`,
          };
        }
        options.maxLlm = n;
        break;
      }
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

export const REMEDIATE_HELP = `qremediate — apply verified codemod fixes (and, with --llm, crypto-verified LLM proposals) for insecure crypto findings

USAGE
  qremediate [path] [--mode diff|apply|pr] [--llm] [--apply-llm] [--max-llm N]
             [--llm-provider <p>] [--llm-model <m>]

OPTIONS
  --mode diff    Print a unified diff of every candidate fix (default; writes nothing)
  --mode apply   Write deterministic codemod fixes into the working tree
                 (LLM fixes are held back as diffs unless --apply-llm is given)
  --mode pr      Commit fixes to a new branch and open a DRAFT PR (never merges)
  --llm          Also let a BYOK LLM propose fixes codemods can't (needs an API key)
  --apply-llm    In apply mode, also write LLM fixes (only after you've read them)
  --max-llm N    Cap paid LLM proposals per run (default ${DEFAULT_MAX_LLM}; spend guard)
  --llm-provider anthropic | openai-compatible (default: anthropic)
  --llm-model    Model id for the BYOK provider
  -h, --help     Show this help
  -v, --version  Show version

Every fix must clear the verify_fix gate (target finding gone, no new finding) and
the patch policy (only files with findings + dependency manifests). Codemod fixes
are deterministic; LLM fixes are **crypto-verified, not security-reviewed** — the
gate proves the crypto is gone, not that the rewrite is safe, and the pipeline
rejects any LLM patch that adds a network/exec sink or rewrites too much. Review
LLM diffs before applying. Never merges.
`;
