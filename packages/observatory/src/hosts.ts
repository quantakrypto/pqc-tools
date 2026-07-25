/**
 * Seed / opt-out list parsing. Pure file + string work over Node built-ins.
 *
 * `hosts.txt` is the committed seed list: one domain per line, `#` comments and
 * blank lines ignored. A host's rank is its 1-based position among the
 * non-comment lines (used only to bucket the rollup, not a traffic claim).
 * `optout.txt` has the same line format and names domains that must never be
 * probed (and are recorded with `opted_out_at`).
 */
import { existsSync, readFileSync } from "node:fs";

export interface SeedHost {
  domain: string;
  rank: number;
  rankSource: string;
}

/** Read a list file into its non-comment, non-blank, lower-cased domains (in order). */
export function parseHostFile(path: string): string[] {
  if (!existsSync(path)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    // Strip an inline `# comment`, then trim.
    const line = raw.replace(/#.*$/, "").trim().toLowerCase();
    if (line === "") continue;
    if (seen.has(line)) continue; // de-dup defensively
    seen.add(line);
    out.push(line);
  }
  return out;
}

/** Load the seed list, assigning each domain its 1-based line rank. */
export function loadSeedHosts(path: string, rankSource = "seed"): SeedHost[] {
  return parseHostFile(path).map((domain, i) => ({ domain, rank: i + 1, rankSource }));
}

/** Load the opt-out domains (empty when the file is absent). */
export function loadOptOut(path: string): string[] {
  return parseHostFile(path);
}
