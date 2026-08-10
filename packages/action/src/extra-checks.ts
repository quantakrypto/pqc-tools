import { runProbe } from "@quantakrypto/qprobe";
import { parseTarget } from "@quantakrypto/qprobe";
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

/** Default port when the target names none. qProbe picks the mode from it. */
const DEFAULT_PROBE_PORT = 443;

/**
 * qProbe against one host the workflow attests ownership of.
 *
 * The target goes through qProbe's own `parseTarget`, which is the enforcement
 * point for "one host at a time, named explicitly": it refuses CIDR blocks, IP
 * ranges, wildcards, comma lists, URLs and embedded credentials, and the threat
 * model calls that control code-enforced.
 *
 * An earlier version of this file normalised the target itself and handed
 * `runProbe` a pre-built object, which skipped every one of those refusals.
 * `our-api.example.com@evil.test` would have been reduced to `evil.test` and
 * probed under a manufactured ownership claim, while a reviewer reading the
 * workflow saw `our-api.example.com`. Never parse a security-relevant input
 * twice; call the parser that owns the rule.
 *
 * `iOwnThis` is passed through from an explicit workflow input rather than
 * hardcoded. The CLI makes an operator type `--i-own-this`, and that affirmative
 * act is the whole control; the action must not manufacture it on their behalf.
 */
export async function runProbeCheck(target: string, iOwnThis: boolean): Promise<Result> {
  try {
    if (!iOwnThis) {
      throw new Error(
        'probing requires an ownership attestation: set i-own-this: "true" in the workflow, ' +
          "and only for an endpoint you are authorised to test.",
      );
    }
    // An explicitly-written URL is reduced to its host first, which is what
    // action.yml documents. It is a pure string-to-string step, not a second
    // parse: whatever comes out still goes through parseTarget below, and
    // anything that is not a plain scheme://host[:port] comes out unchanged so
    // parseTarget refuses it. See the note on normalizeProbeTarget.
    //
    // Throws TargetError with an actionable message on anything that is not a
    // single host (or host:port) named directly.
    const parsed = parseTarget(normalizeProbeTarget(target), DEFAULT_PROBE_PORT);
    const { findings, inventory } = await runProbe({
      targets: [parsed],
      mode: "auto",
      attest: { iOwnThis },
    });
    return scoredResult("qProbe", inventory.readinessScore, findings);
  } catch (err) {
    // Target and attestation errors land here, and they are the operator's to fix.
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
      // There is no shell anywhere on this path — runSieve spawns argv directly
      // — so this splits a command, it does not evaluate one.
      command: impl.trim().split(/\s+/),
      param: param.trim() as ParamSet,
    });
    return conformanceResult(report, workflowPath);
  } catch (err) {
    // An unknown parameter set throws RangeError before anything spawns.
    return crashedResult("Sieve", (err as Error).message);
  }
}
