/**
 * Optional on-disk scan cache. Keyed by file content hash so an unchanged file
 * reuses its previous findings instead of re-running every detector — the big
 * win on large monorepos where most files don't change between runs.
 *
 * Invalidation is conservative and whole-cache: the cache stores a RULESET
 * FINGERPRINT (tool version + the active detector ids + disabled rules). If any
 * of those differ from the current run, the entire cache is discarded and
 * rebuilt, so upgrading the tool or changing the rules never serves stale
 * results. Per file, a content-hash mismatch re-scans just that file.
 *
 * The cache is opt-in (`ScanOptions.cacheFile`); with no cache file, scans are
 * exactly as before. A corrupt / unreadable / wrong-version cache file is
 * ignored (treated as empty), never fatal.
 */
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import * as path from "node:path";

import type { Detector, Finding } from "./types.js";
import { VERSION } from "./version.js";

const CACHE_VERSION = 1;

/** One cached file: the content hash it was computed for, and its findings. */
export interface CacheEntry {
  hash: string;
  findings: Finding[];
}

interface CacheFileShape {
  version: number;
  ruleset: string;
  entries: Record<string, CacheEntry>;
}

/** sha256 of a file's content (hex). */
export function hashContent(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * Fingerprint of everything that changes what a scan produces: the tool version,
 * the active detector ids (sorted), and the disabled-rule set (sorted). A change
 * to any of these invalidates the whole cache.
 */
export function rulesetFingerprint(
  detectors: readonly Detector[],
  disabledRules: readonly string[] | undefined,
): string {
  const ids = detectors.map((d) => d.id).sort();
  const disabled = [...(disabledRules ?? [])].sort();
  return `v${VERSION}|d:${ids.join(",")}|x:${disabled.join(",")}`;
}

/**
 * Load the cache file into a `Map<relPath, CacheEntry>`. Returns an empty map
 * when the file is missing, unparseable, the wrong version, or was written for a
 * different ruleset (in which case its entries are stale and must not be reused).
 */
export async function loadCache(
  cacheFile: string,
  ruleset: string,
): Promise<Map<string, CacheEntry>> {
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
    parsed.ruleset !== ruleset ||
    typeof parsed.entries !== "object" ||
    parsed.entries === null
  ) {
    return new Map();
  }
  const map = new Map<string, CacheEntry>();
  for (const [file, entry] of Object.entries(parsed.entries)) {
    if (entry && typeof entry.hash === "string" && Array.isArray(entry.findings)) {
      map.set(file, entry);
    }
  }
  return map;
}

/**
 * Write the cache atomically (temp file + rename) so a concurrent reader never
 * sees a half-written file. Errors are swallowed — a cache is an optimization,
 * never a reason to fail a scan.
 */
export async function saveCache(
  cacheFile: string,
  ruleset: string,
  entries: Map<string, CacheEntry>,
): Promise<void> {
  const doc: CacheFileShape = {
    version: CACHE_VERSION,
    ruleset,
    entries: Object.fromEntries(entries),
  };
  try {
    await mkdir(path.dirname(cacheFile), { recursive: true });
    const tmp = `${cacheFile}.tmp-${process.pid}`;
    await writeFile(tmp, JSON.stringify(doc), "utf8");
    const { rename } = await import("node:fs/promises");
    await rename(tmp, cacheFile);
  } catch {
    // best effort
  }
}
