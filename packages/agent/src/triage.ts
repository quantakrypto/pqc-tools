/**
 * Triage orchestrator: for each finding at/above the severity floor, ask the LLM
 * for an exposure verdict and return a `Map<fingerprint, TriageVerdict>`. This
 * NEVER drops a finding — it only produces verdicts; qScan attaches them and
 * re-sorts, keeping every finding and the CI exit code untouched.
 */
import type { ContextLevel, Finding, Severity, TriageVerdict } from "@quantakrypto/core";
import { buildContext } from "@quantakrypto/core";

import type { LlmClient } from "./client.js";
import { TRIAGE_PROMPT_VERSION, TRIAGE_SCHEMA, TRIAGE_SYSTEM, triageUserPrompt } from "./prompt.js";
import { cacheKey, loadResponseCache, saveResponseCache } from "./response-cache.js";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface TriageOptions {
  client: LlmClient;
  level: ContextLevel;
  /** Read a file's content (for snippet/function/file levels). */
  readFile: (path: string) => Promise<string>;
  /** Stable fingerprint for a finding (shared with the baseline). */
  fingerprint: (f: Finding) => string;
  /** Triage findings at or above this seriousness. Default: medium. */
  floor?: Severity;
  /** Optional response cache path. */
  cacheFile?: string;
  /** Model id, only used to key the cache. */
  model?: string;
}

/** Produce an exposure verdict per above-floor finding. */
export async function triageFindings(
  findings: readonly Finding[],
  opts: TriageOptions,
): Promise<Map<string, TriageVerdict>> {
  const floorRank = SEVERITY_RANK[opts.floor ?? "medium"];
  const targets = findings.filter((f) => SEVERITY_RANK[f.severity] <= floorRank);
  const out = new Map<string, TriageVerdict>();
  const cache = opts.cacheFile ? await loadResponseCache(opts.cacheFile) : null;
  const model = opts.model ?? "unknown";

  for (const f of targets) {
    const fp = opts.fingerprint(f);
    const key = cacheKey({
      promptVersion: TRIAGE_PROMPT_VERSION,
      model,
      contextLevel: opts.level,
      fingerprint: fp,
    });
    if (cache?.has(key)) {
      const cached = cache.get(key) as TriageVerdict;
      out.set(fp, { ...cached, fingerprint: fp });
      continue;
    }
    const content =
      opts.level === "metadata" ? "" : await opts.readFile(f.location.file).catch(() => "");
    const ctx = buildContext(f, opts.level, content);
    const raw = (await opts.client.complete({
      system: TRIAGE_SYSTEM,
      user: triageUserPrompt(ctx),
      schema: TRIAGE_SCHEMA,
      maxTokens: 512,
    })) as { exposureScore: number; priority: "now" | "soon" | "later"; rationale: string };
    const verdict: TriageVerdict = {
      fingerprint: fp,
      exposureScore: raw.exposureScore,
      priority: raw.priority,
      rationale: raw.rationale,
    };
    out.set(fp, verdict);
    cache?.set(key, verdict);
  }

  if (opts.cacheFile && cache) await saveResponseCache(opts.cacheFile, cache);
  return out;
}
