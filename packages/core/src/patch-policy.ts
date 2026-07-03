/**
 * Patch-policy allowlist. A remediation patch may only edit a file that already
 * has a finding, or add dependencies to a manifest. Everything else — CI config,
 * lockfiles, env/secret files, unrelated source — is denied. This is the second
 * safety gate (the first is `verify_fix`): even a "verified" patch is dropped if
 * it strays outside the sanctioned surface.
 */
import type { Patch } from "./agent-types.js";

/** Files a remediation may write to. */
export interface PolicyContext {
  /** Relative paths (posix) that contain at least one finding. */
  findingFiles: Set<string>;
  /** Relative manifest paths (package.json, requirements.txt, …). */
  manifestFiles: Set<string>;
}

/**
 * Paths a patch may NEVER touch, regardless of anything else: version control,
 * CI, dependency lockfiles, and anything that looks like a secret/env file.
 */
const DENY_RE =
  /(^|\/)(\.github|\.git|node_modules)\/|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|Gemfile\.lock|poetry\.lock)$|(^|\/)\.env(\.[^/]*)?$|\.(pem|key|p12|pfx)$/i;

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
}

/** Decide whether `patch` may be applied under `ctx`. */
export function checkPatchPolicy(patch: Patch, ctx: PolicyContext): PolicyDecision {
  const p = patch.path.replace(/\\/g, "/");
  if (DENY_RE.test(p)) {
    return { allowed: false, reason: `patch touches a protected path (${p})` };
  }
  if (ctx.findingFiles.has(p)) return { allowed: true };
  if (ctx.manifestFiles.has(p)) return { allowed: true };
  return {
    allowed: false,
    reason: `patch edits ${p}, which has no finding and is not a dependency manifest`,
  };
}
