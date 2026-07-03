/**
 * Parallel scanning over a worker-thread pool (P2-1). The scan is embarrassingly
 * parallel: each file is read and regex-scanned independently, and the merge is
 * a concatenation + the existing deterministic sort. `Finding` is plain
 * structured-cloneable data, so it crosses the worker boundary cleanly.
 *
 * The merge and chunking logic are pure and exported for direct unit testing.
 * `scanParallel` falls back to the in-process serial path below the crossover
 * (small file counts / small total bytes) and whenever workers are unavailable.
 */
import { stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import type { Worker as NodeWorker } from "node:worker_threads";

import type { Finding, ParallelScanOptions, ScanResult } from "./types.js";
import { walkFiles } from "./walk.js";
import { isAnalyzableSource } from "./detect-utils.js";
import { buildInventory } from "./inventory.js";
import { compareFindings, filterExplicitFileList, scan } from "./scan.js";
import { AbortError, BudgetExceededError } from "./errors.js";
import { VERSION } from "./version.js";

/** One unit of work dispatched to a worker. */
export interface ScanChunk {
  files: string[];
}

/** What a worker returns for a chunk. */
export interface ChunkResult {
  findings: Finding[];
  filesScanned: number;
  /** Files that couldn't be read in this chunk (optional; older workers omit it). */
  unreadable?: number;
  /** Files skipped as minified in this chunk (optional; older workers omit it). */
  skippedMinified?: number;
}

const DEFAULT_PARALLEL_THRESHOLD_BYTES = 2 * 1024 * 1024;
const DEFAULT_PARALLEL_FILE_THRESHOLD = 200;
const DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024;

/** A file plus its byte size, used for byte-balanced chunking. */
export interface SizedFile {
  rel: string;
  size: number;
}

/**
 * Bucket files into chunks of roughly `chunkBytes` total bytes each, so one
 * large file doesn't starve a worker holding many tiny files. Pure +
 * deterministic: input order is preserved within and across chunks.
 */
export function chunkByBytes(files: readonly SizedFile[], chunkBytes: number): ScanChunk[] {
  const limit = Math.max(1, chunkBytes);
  const chunks: ScanChunk[] = [];
  let current: string[] = [];
  let currentBytes = 0;
  for (const f of files) {
    if (current.length > 0 && currentBytes + f.size > limit) {
      chunks.push({ files: current });
      current = [];
      currentBytes = 0;
    }
    current.push(f.rel);
    currentBytes += f.size;
  }
  if (current.length > 0) chunks.push({ files: current });
  return chunks;
}

/**
 * Merge per-chunk results into a single ordered finding set + total file count.
 * Pure: applies the SAME comparator as the serial scan, so the result is
 * byte-identical regardless of chunk completion order. Exported for unit tests.
 */
export function mergeChunkResults(results: readonly ChunkResult[]): ChunkResult {
  const findings: Finding[] = [];
  let filesScanned = 0;
  let unreadable = 0;
  let skippedMinified = 0;
  for (const r of results) {
    for (const f of r.findings) findings.push(f);
    filesScanned += r.filesScanned;
    unreadable += r.unreadable ?? 0;
    skippedMinified += r.skippedMinified ?? 0;
  }
  findings.sort(compareFindings);
  return { findings, filesScanned, unreadable, skippedMinified };
}

/** Resolve the worker count (>= 1). */
function resolveConcurrency(options: ParallelScanOptions): number {
  const raw = options.concurrency;
  if (typeof raw === "number" && raw >= 1) return Math.floor(raw);
  const avail =
    typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, avail);
}

/** Decide whether the workload is large enough to justify spawning workers. */
function shouldParallelize(options: ParallelScanOptions, files: SizedFile[]): boolean {
  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
  const byteFloor = options.parallelThresholdBytes ?? DEFAULT_PARALLEL_THRESHOLD_BYTES;
  const fileFloor = options.parallelFileThreshold ?? DEFAULT_PARALLEL_FILE_THRESHOLD;
  if (resolveConcurrency(options) <= 1) return false;
  return totalBytes >= byteFloor && files.length >= fileFloor;
}

/**
 * Enumerate the files to scan (relative POSIX paths + sizes), honouring an
 * explicit `files` list or the walker. Sizes power byte-balanced chunking.
 */
async function enumerateFiles(options: ParallelScanOptions, baseDir: string): Promise<SizedFile[]> {
  const rels: string[] = [];
  if (options.files) {
    // Apply the SAME include/exclude/binary filtering the serial path uses via
    // `filterExplicitFiles`, so `--parallel` is byte-for-byte identical to serial.
    for (const rel of filterExplicitFileList(options.files, options)) rels.push(rel);
  } else {
    for await (const rel of walkFiles(options.root, {
      include: options.include,
      exclude: options.exclude,
      noDefaultIgnores: options.noDefaultIgnores,
      maxFileSize: options.maxFileSize,
    })) {
      rels.push(rel);
    }
  }

  const sized: SizedFile[] = [];
  for (const rel of rels) {
    let size = 0;
    try {
      size = (await stat(path.join(baseDir, ...rel.split("/")))).size;
    } catch {
      // Unreadable now; keep with size 0 — worker read will skip if it's gone.
    }
    sized.push({ rel, size });
  }
  return sized;
}

/**
 * Resolve the worker entry next to this module. In a normal build it's
 * `dist/scan-worker.js`. When running from source under a TypeScript loader
 * (tsx) the built JS doesn't exist, so fall back to `scan-worker.ts` and tell
 * the worker to load tsx as well — so the parallel scanner works in dev/source
 * mode (and is exercisable by tests), not only after a build.
 */
function workerEntry(): { entry: string; execArgv?: string[] } {
  const here = fileURLToPath(import.meta.url);
  const dir = path.dirname(here);
  const js = path.join(dir, "scan-worker.js");
  if (existsSync(js)) return { entry: js };
  const ts = path.join(dir, "scan-worker.ts");
  if (existsSync(ts)) return { entry: ts, execArgv: ["--import", "tsx"] };
  return { entry: js }; // neither present: let Worker surface a clear ENOENT
}

/**
 * Scan in parallel across a worker-thread pool, falling back to the in-process
 * serial {@link scan} for small workloads or when workers can't be used. The
 * result is deterministic and identical to the serial path.
 */
export async function scanParallel(options: ParallelScanOptions): Promise<ScanResult> {
  const startedAt = new Date();

  const rootStat = await stat(options.root);
  const baseDir = rootStat.isFile() ? path.dirname(options.root) : options.root;

  // Single-file roots, the override-detectors path, and the scan cache always
  // run serially: detectors may not be structured-cloneable across the worker
  // boundary, and the cache read/write is owned by the in-process `scan()`.
  if (rootStat.isFile() || options.detectors || options.cacheFile) {
    return scan(options);
  }

  const files = await enumerateFiles(options, baseDir);

  // Budget + cancellation parity with the serial path. The parallel path
  // enumerates upfront, so budgets are enforced against the whole file set
  // before any worker is dispatched.
  if (options.signal?.aborted) throw new AbortError();
  if (typeof options.maxFiles === "number" && files.length > options.maxFiles) {
    throw new BudgetExceededError(`maxFiles budget exceeded (limit: ${options.maxFiles}).`);
  }
  if (typeof options.maxBytes === "number") {
    const totalBytes = files.reduce((n, f) => n + f.size, 0);
    if (totalBytes > options.maxBytes) {
      throw new BudgetExceededError(`maxBytes budget exceeded (limit: ${options.maxBytes}).`);
    }
  }

  if (!shouldParallelize(options, files)) {
    // In-process: reuse the exact serial path over the same file list.
    return scan({ ...options, files: files.map((f) => f.rel) });
  }

  let WorkerCtor: typeof import("node:worker_threads").Worker;
  try {
    ({ Worker: WorkerCtor } = await import("node:worker_threads"));
  } catch {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }

  const chunks = chunkByBytes(files, options.chunkBytes ?? DEFAULT_CHUNK_BYTES);
  const concurrency = Math.min(resolveConcurrency(options), chunks.length);
  const { entry, execArgv } = workerEntry();

  const toggles = {
    source: options.source !== false,
    config: options.config !== false,
    deps: options.dependencies !== false,
    scanMinified: options.scanMinified === true,
    // Plain string array — structured-cloneable, so it crosses the worker boundary.
    disabledRules: options.disabledRules,
  };

  let results: ChunkResult[];
  try {
    results = await runPool(
      WorkerCtor,
      entry,
      execArgv,
      baseDir,
      toggles,
      chunks,
      concurrency,
      options.onFile,
      options.signal,
    );
  } catch (err) {
    // Cancellation / budget overflow must propagate, not silently degrade.
    if (err instanceof AbortError || err instanceof BudgetExceededError) throw err;
    // Any other worker failure → safe fallback to the serial path.
    return scan({ ...options, files: files.map((f) => f.rel) });
  }

  const merged = mergeChunkResults(results);
  const inventory = buildInventory(merged.findings);
  const finishedAt = new Date();

  // Coverage: count analyzable-source files in the enumerated set. Computed from
  // the file list (not per-worker) to avoid worker-boundary plumbing; on the
  // parallel path this can include a minified analyzable file the workers
  // skipped, but that is vanishingly rare and never under-reports coverage.
  const analyzedFiles = files.reduce((n, f) => (isAnalyzableSource(f.rel) ? n + 1 : n), 0);

  return {
    root: options.root,
    findings: merged.findings,
    filesScanned: merged.filesScanned,
    analyzedFiles,
    diagnostics: {
      unreadable: merged.unreadable ?? 0,
      skippedMinified: merged.skippedMinified ?? 0,
    },
    inventory,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    toolVersion: VERSION,
  };
}

/** Worker-pool driver: at most `concurrency` workers, each pulls chunks. */
function runPool(
  WorkerCtor: typeof import("node:worker_threads").Worker,
  entry: string,
  execArgv: string[] | undefined,
  baseDir: string,
  toggles: {
    source: boolean;
    config: boolean;
    deps: boolean;
    scanMinified: boolean;
    disabledRules?: string[];
  },
  chunks: ScanChunk[],
  concurrency: number,
  onFile?: (file: string) => void,
  signal?: AbortSignal,
): Promise<ChunkResult[]> {
  return new Promise((resolve, reject) => {
    const results: ChunkResult[] = new Array(chunks.length);
    let next = 0;
    let done = 0;
    let failed = false;
    const workers: Array<NodeWorker> = [];

    const onAbort = (): void => {
      if (failed) return;
      failed = true;
      cleanup();
      reject(new AbortError());
    };

    const cleanup = () => {
      if (signal) signal.removeEventListener("abort", onAbort);
      for (const w of workers) void w.terminate();
    };

    // Cooperative cancellation: stop dispatching and tear down on abort.
    if (signal) {
      if (signal.aborted) {
        reject(new AbortError());
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
    }

    const dispatch = (w: NodeWorker): void => {
      if (failed) return;
      if (next >= chunks.length) {
        void w.terminate();
        return;
      }
      const idx = next++;
      w.postMessage({ index: idx, files: chunks[idx].files });
    };

    const spawn = (): NodeWorker => {
      const w = new WorkerCtor(entry, {
        workerData: { baseDir, toggles },
        ...(execArgv ? { execArgv } : {}),
      });
      w.on(
        "message",
        (msg: { index: number; result?: ChunkResult; files?: string[]; error?: string }) => {
          if (msg.error) {
            if (!failed) {
              failed = true;
              cleanup();
              reject(new Error(msg.error));
            }
            return;
          }
          if (msg.files && onFile) for (const f of msg.files) onFile(f);
          if (msg.result) {
            results[msg.index] = msg.result;
            done++;
            if (done === chunks.length) {
              cleanup();
              resolve(results);
              return;
            }
            dispatch(w);
          }
        },
      );
      w.on("error", (err) => {
        if (!failed) {
          failed = true;
          cleanup();
          reject(err);
        }
      });
      return w;
    };

    const n = Math.max(1, Math.min(concurrency, chunks.length));
    for (let i = 0; i < n; i++) {
      const w = spawn();
      workers.push(w);
      dispatch(w);
    }
  });
}
