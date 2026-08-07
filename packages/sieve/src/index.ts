/**
 * @quantakrypto/sieve — programmatic API.
 *
 * Sieve is a conformance battery for ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
 * implementations. It TESTS other people's implementations; it implements no
 * cryptography of its own and ships no Known-Answer-Test vectors. See README.md
 * and PROTOCOL.md.
 *
 * Typical use:
 * ```ts
 * import { runSieve } from "@quantakrypto/sieve";
 * const report = await runSieve({ command: ["node", "./my-impl.js"], param: "ml-kem-768" });
 * console.log(report.overall);
 * ```
 */

import { categoriesFor } from "./categories/index.js";
import type { CategoryResult } from "./categories/types.js";
import { loadVectors } from "./vectors.js";
import type { VectorFileProvenance } from "./vectors.js";
import { Runner, SutCrashError, TimeoutError, describeSutError } from "./runner.js";
import type { RequestInput } from "./protocol.js";
import { buildReport, HARNESS_CATEGORY, type SieveReport } from "./report.js";
import { isParamSet, sizesFor, type ParamSet, type Sizes } from "./sizes.js";

export type { SieveReport, CategoryCounts, Verdict } from "./report.js";
export type { CategoryResult, Check, Status, BugClass } from "./categories/types.js";
export type {
  ParamSet,
  Family,
  Sizes,
  KemSizes,
  DsaSizes,
  SlhDsaSizes,
  SignatureSizes,
} from "./sizes.js";
export type { Request, Response, SignatureFamily } from "./protocol.js";

export {
  PARAM_SETS,
  isParamSet,
  sizesFor,
  asKemSizes,
  asDsaSizes,
  asSlhDsaSizes,
  asSignatureSizes,
} from "./sizes.js";
export { CATEGORIES, categoriesFor } from "./categories/index.js";
export { buildReport, formatHuman, formatJson, overallVerdict, HARNESS_CATEGORY } from "./report.js";
export {
  encodeRequest,
  decodeResponse,
  ProtocolError,
  PROTOCOL_VERSION,
  toB64,
  fromB64,
} from "./protocol.js";
export {
  Runner,
  TimeoutError,
  SutCrashError,
  describeSutError,
  buildSutEnv,
  DEFAULT_ENV_ALLOWLIST,
} from "./runner.js";
export type { RunnerOptions } from "./runner.js";
export { loadVectors } from "./vectors.js";
export type { Vector, VectorSet } from "./vectors.js";

/** Options for {@link runSieve}. */
export interface RunSieveOptions {
  /** Argv of the SUT, e.g. ["node", "./impl.js"]. */
  command: readonly string[];
  /** Parameter set to test, e.g. "ml-kem-768". */
  param: ParamSet;
  /** Randomized iterations for applicable categories (default 32). */
  iterations?: number;
  /** Per-request timeout in milliseconds (default 10000). */
  timeoutMs?: number;
  /** Directory of official ACVP vectors for the kat category (optional). */
  vectorsDir?: string;
  /** Include the advisory timing category (default false). */
  timing?: boolean;
  /** Working directory for the SUT. */
  cwd?: string;
  /** Extra env for the SUT (layered over the scrubbed minimal env). */
  env?: Record<string, string>;
  /**
   * Inherit the full parent environment instead of the scrubbed minimal env.
   * Default `false` — the SUT is untrusted code. See security.md Q-17.
   */
  inheritEnv?: boolean;
  /** Extra env variable names to copy from the parent env into the SUT's env. */
  envAllowlist?: readonly string[];
  /**
   * Max concurrent in-flight requests per SUT process for categories that issue
   * many INDEPENDENT requests (correctness/determinism iterations). Default 16.
   * Set to 1 for strictly serial behavior. The id-correlated protocol keeps
   * dependent ops ordered; see docs/audits/performance.md §7.1.
   */
  pipelineDepth?: number;
  /** Restrict to these category names (default: all applicable). */
  only?: readonly string[];
}

/**
 * One keygen before the battery, to tell "this implementation is wrong" apart
 * from "I could not run this implementation".
 *
 * Without it, an `--impl` naming a file that does not exist makes every probe
 * fail with the same spawn error, and the report reads as dozens of independent
 * high-severity defects tagged with bug classes that were never exercised. That
 * is worse than useless: it is confidently wrong about code that never ran.
 *
 * Only a TRANSPORT failure counts as unusable, i.e. the process died or never
 * answered. A SUT that replies `{ok:false}` is alive and speaking the protocol,
 * which is a genuine conformance signal, so the battery runs as normal.
 *
 * Returns the harness category to report, or null when the SUT is usable.
 */
async function probeStartup(
  runner: Runner,
  family: Sizes["family"],
  param: ParamSet,
): Promise<CategoryResult | null> {
  try {
    await runner.send({ family, param, op: "keygen" } as RequestInput);
    return null;
  } catch (err) {
    if (!(err instanceof SutCrashError) && !(err instanceof TimeoutError)) return null;
    return {
      category: HARNESS_CATEGORY,
      status: "fail",
      checks: [
        {
          name: "sut-startup",
          status: "fail",
          detail: describeSutError(err),
        },
      ],
      summary: "the implementation under test could not be run, so no conformance checks were performed",
    };
  }
}

/**
 * Spawn the SUT, run the applicable categories, and return an aggregated
 * report. The SUT process is always torn down before returning, even on error.
 */
export async function runSieve(opts: RunSieveOptions): Promise<SieveReport> {
  if (!isParamSet(opts.param)) {
    throw new RangeError(`unknown parameter set: ${opts.param}`);
  }
  const sizes = sizesFor(opts.param);
  const iterations = opts.iterations ?? 32;
  const startedAt = new Date();
  const t0 = performance.now();

  const runner = new Runner({
    command: opts.command,
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.cwd ? { cwd: opts.cwd } : {}),
    ...(opts.env ? { env: opts.env } : {}),
    ...(opts.inheritEnv !== undefined ? { inheritEnv: opts.inheritEnv } : {}),
    ...(opts.envAllowlist ? { envAllowlist: opts.envAllowlist } : {}),
  });
  const pipelineDepth = opts.pipelineDepth ?? 16;

  const results: CategoryResult[] = [];
  try {
    let cats = categoriesFor(sizes.family, opts.timing ?? false);
    if (opts.only && opts.only.length > 0) {
      const want = new Set(opts.only);
      cats = cats.filter((c) => want.has(c.name));
    }
    const unusable = await probeStartup(runner, sizes.family, opts.param);
    if (unusable) {
      // The SUT cannot be spoken to, so every category below would fail with
      // this same error and the report would read as dozens of independent
      // conformance defects. Say the true thing once instead.
      results.push(unusable);
      cats = [];
    }
    for (const cat of cats) {
      try {
        const res = await cat.run({
          runner,
          sizes,
          iterations,
          pipelineDepth,
          ...(opts.vectorsDir ? { vectorsDir: opts.vectorsDir } : {}),
        });
        results.push(res);
      } catch (err) {
        // A category that throws (rather than recording a fail) is a harness
        // fault; surface it as a failing category so the report is complete.
        results.push({
          category: cat.name,
          status: "fail",
          checks: [
            {
              name: "category-error",
              status: "fail",
              detail: `category threw: ${(err as Error).message}`,
            },
          ],
          summary: "category aborted with an error",
        });
      }
    }
  } finally {
    await runner.close();
  }

  // Record vector-file provenance (raw-byte hashes + declared source) so a `kat`
  // PASS is traceable to authentic inputs. Best-effort: an invalid/empty vectors
  // dir is already surfaced by the kat category, so a load failure here is silent.
  let provenance: VectorFileProvenance[] | undefined;
  let provenanceDeclared: boolean | undefined;
  if (opts.vectorsDir) {
    try {
      const vs = loadVectors(opts.vectorsDir);
      provenance = vs.provenance;
      provenanceDeclared = vs.provenanceDeclared;
    } catch {
      /* invalid/empty vectors dir — the kat category reports it */
    }
  }

  return buildReport({
    param: opts.param,
    impl: [...opts.command],
    iterations,
    ...(opts.vectorsDir ? { vectorsDir: opts.vectorsDir } : {}),
    startedAt,
    durationMs: Math.round(performance.now() - t0),
    categories: results,
    ...(provenance ? { provenance, provenanceDeclared } : {}),
  });
}
