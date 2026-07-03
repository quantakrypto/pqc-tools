/**
 * On-disk cache of validated LLM responses, so reruns are reproducible and
 * cheap (temperature is 0, so the same inputs deserve the same output without a
 * second paid call). Keyed by `(promptVersion, model, contextLevel,
 * findingFingerprint)` — a prompt or model change simply produces new keys and
 * misses, so there is no stale-response hazard.
 *
 * Mirrors `@quantakrypto/core`'s scan cache: atomic write (temp + rename),
 * tolerant load (missing/corrupt/wrong-version → empty). A cache is an
 * optimization, never a reason to fail.
 */
import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import * as path from "node:path";
import process from "node:process";

const CACHE_VERSION = 1;

interface CacheFileShape {
  version: number;
  entries: Record<string, unknown>;
}

/** Compose the cache key for one finding's request. */
export function cacheKey(parts: {
  promptVersion: string;
  model: string;
  contextLevel: string;
  fingerprint: string;
}): string {
  return `${parts.promptVersion}|${parts.model}|${parts.contextLevel}|${parts.fingerprint}`;
}

/** Load the response cache, or an empty map on any problem. */
export async function loadResponseCache(cacheFile: string): Promise<Map<string, unknown>> {
  let raw: string;
  try {
    raw = await readFile(cacheFile, "utf8");
  } catch {
    return new Map();
  }
  let parsed: CacheFileShape;
  try {
    parsed = JSON.parse(raw) as CacheFileShape;
  } catch {
    return new Map();
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    parsed.version !== CACHE_VERSION ||
    typeof parsed.entries !== "object" ||
    parsed.entries === null
  ) {
    return new Map();
  }
  return new Map(Object.entries(parsed.entries));
}

/** Write the response cache atomically. Errors are swallowed. */
export async function saveResponseCache(
  cacheFile: string,
  entries: Map<string, unknown>,
): Promise<void> {
  const doc: CacheFileShape = { version: CACHE_VERSION, entries: Object.fromEntries(entries) };
  try {
    await mkdir(path.dirname(cacheFile), { recursive: true });
    const tmp = `${cacheFile}.tmp-${process.pid}`;
    await writeFile(tmp, JSON.stringify(doc), "utf8");
    await rename(tmp, cacheFile);
  } catch {
    // best effort
  }
}
