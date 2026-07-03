/**
 * `qscan --triage` glue (BYOK plane). Runs the LLM triage pass over a scan
 * result and attaches an exposure annotation to each finding, then re-sorts by
 * exposure. It NEVER drops a finding and NEVER touches the exit code — the CLI
 * computes the exit code from raw severities before this ever runs.
 *
 * `@quantakrypto/agent` (the only networked package) is loaded via dynamic
 * `import()` so a plain scan never pulls in the network client.
 */
import { readFile as fsReadFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import {
  buildContext,
  compareFindings,
  fingerprintFinding,
  renderPreflight,
} from "@quantakrypto/core";
import type {
  ContextLevel,
  Finding,
  ScanResult,
  Severity,
  TriageVerdict,
} from "@quantakrypto/core";

import type { LlmProvider } from "./args.js";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Injectable triage function (default wraps `@quantakrypto/agent`). */
export type TriageFn = (findings: readonly Finding[]) => Promise<Map<string, TriageVerdict>>;

export interface RunTriageOptions {
  level: ContextLevel;
  floor?: Severity;
  dryRun?: boolean;
  provider?: LlmProvider;
  model?: string;
  cacheFile?: string;
  /** Base directory for resolving finding file paths (defaults to result.root). */
  root?: string;
  // --- injectables for testing ---
  triageFn?: TriageFn;
  resolveKey?: () => string | undefined;
  readFile?: (relPath: string) => Promise<string>;
  stderr?: (s: string) => void;
}

export interface RunTriageResult {
  /** When `--dry-run`, the preflight text to show instead of a normal report. */
  preflight?: string;
}

function envKey(provider: LlmProvider): string | undefined {
  return (
    process.env.QK_LLM_API_KEY ??
    (provider === "anthropic" ? process.env.ANTHROPIC_API_KEY : process.env.OPENAI_API_KEY)
  );
}

function defaultModel(provider: LlmProvider): string {
  return provider === "anthropic" ? "claude-sonnet-5" : "gpt-4o-mini";
}

/**
 * Annotate `result.findings` with triage verdicts (mutating `result`). Returns a
 * preflight string when `--dry-run` is set (no provider is contacted). Failures
 * degrade gracefully: the scan/report proceed without triage.
 */
export async function runTriage(
  result: ScanResult,
  opts: RunTriageOptions,
): Promise<RunTriageResult> {
  const level = opts.level;
  const floorRank = SEVERITY_RANK[opts.floor ?? "medium"];
  const targets = result.findings.filter((f) => SEVERITY_RANK[f.severity] <= floorRank);
  const stderr = opts.stderr ?? ((s: string) => void process.stderr.write(s));
  const root = opts.root ?? result.root ?? ".";
  const readFile = opts.readFile ?? ((rel: string) => fsReadFile(path.resolve(root, rel), "utf8"));

  // --dry-run: show exactly what would be sent; contact nothing.
  if (opts.dryRun) {
    const contexts = [];
    for (const f of targets) {
      const content = level === "metadata" ? "" : await readFile(f.location.file).catch(() => "");
      contexts.push(buildContext(f, level, content));
    }
    return {
      preflight: contexts.length
        ? renderPreflight(contexts)
        : "qscan --triage --dry-run: no findings at or above the triage floor.",
    };
  }

  const provider: LlmProvider = opts.provider ?? "anthropic";
  const key = opts.resolveKey ? opts.resolveKey() : envKey(provider);

  // No key and no injected triage function → graceful degrade (never fatal).
  if (!opts.triageFn && !key) {
    stderr(
      "qscan: --triage needs an API key (set QK_LLM_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY). Skipping triage.\n",
    );
    return {};
  }

  const model = opts.model ?? defaultModel(provider);
  const triageFn: TriageFn =
    opts.triageFn ??
    (async (findings) => {
      const agent = await import("@quantakrypto/agent");
      const client = agent.resolveClient({ provider, model, apiKey: key as string });
      return agent.triageFindings(findings, {
        client,
        level,
        readFile,
        fingerprint: fingerprintFinding,
        floor: opts.floor,
        cacheFile: opts.cacheFile,
        model,
      });
    });

  try {
    const verdicts = await triageFn(result.findings);
    for (const f of result.findings) {
      const v = verdicts.get(fingerprintFinding(f));
      if (v) {
        f.triage = { exposureScore: v.exposureScore, priority: v.priority, rationale: v.rationale };
      }
    }
    // Re-sort by exposure (desc), falling back to the stable finding order.
    result.findings = [...result.findings].sort((a, b) => {
      const ea = a.triage?.exposureScore ?? -1;
      const eb = b.triage?.exposureScore ?? -1;
      if (eb !== ea) return eb - ea;
      return compareFindings(a, b);
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    stderr(`qscan: triage failed (${msg}); showing findings without triage.\n`);
  }
  return {};
}
