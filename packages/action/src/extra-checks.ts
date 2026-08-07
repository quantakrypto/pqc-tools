import { runProbe } from "@quantakrypto/qprobe";
import { runSieve, type ParamSet } from "@quantakrypto/sieve";
import { normalizeProbeTarget } from "./checks.js";
import { conformanceResult, crashedResult, scoredResult } from "./platform.js";
import type { ResultPayload } from "./platform.js";

/**
 * The conformance and endpoint checks, driven in-process.
 *
 * Both tools were previously invoked as `npx` in a user's workflow, with their
 * stdout redirected to a file and picked apart by `jq`. Importing them instead
 * removes that whole layer: no shell quoting, no `> file.json`, no parsing a
 * report we already have as a typed object, and no `--format` flag to get wrong.
 *
 * Each returns a payload the platform can ingest, and neither throws: a check
 * that dies is a reportable outcome, not a crash of the run that contains it.
 * Otherwise one failing check would take its siblings down with it.
 */

type Result = Omit<ResultPayload, "auditRunId" | "token">;

/** qProbe against one host the workflow attests ownership of. */
export async function runProbeCheck(target: string): Promise<Result> {
  const host = normalizeProbeTarget(target);
  try {
    const { findings, inventory } = await runProbe({
      // A single host, always. qProbe refuses ranges and lists outright, and the
      // action must not be the thing that turns a scanner into a sweeper.
      targets: [{ host, port: 443 }],
      mode: "auto",
      attest: { iOwnThis: true },
    });
    return scoredResult("probe", "qProbe", inventory.readinessScore, findings);
  } catch (err) {
    // Ownership and target errors land here, and they are the operator's to fix.
    return crashedResult("qProbe", (err as Error).message);
  }
}

/** Sieve against the implementation the workflow names. */
export async function runConformanceCheck(
  impl: string,
  param: string,
  workflowPath: string,
): Promise<Result> {
  try {
    const report = await runSieve({
      // Split on whitespace: Sieve takes argv, and the input is a command line.
      command: impl.trim().split(/\s+/),
      param: param.trim() as ParamSet,
    });
    return conformanceResult(report, workflowPath);
  } catch (err) {
    // An unknown parameter set throws RangeError before anything spawns.
    return crashedResult("Sieve", (err as Error).message);
  }
}
