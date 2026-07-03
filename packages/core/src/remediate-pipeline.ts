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
