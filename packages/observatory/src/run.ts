/**
 * Observatory run orchestration: resolve the month, load the seed + opt-out lists,
 * probe each host under the restrained policy, and persist results + the monthly
 * rollup. All wall-clock reads happen INSIDE `run` (never at module load), so the
 * default month is deterministic per invocation and easy to override in tests.
 */
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  computeRollup,
  ensureSchema,
  fetchHostRows,
  openDb,
  upsertHosts,
  upsertProbe,
} from "./db.js";
import { loadOptOut, loadSeedHosts, type SeedHost } from "./hosts.js";
import { measureHost } from "./probe.js";

const HERE = dirname(fileURLToPath(import.meta.url));
/** Package root (one level up from src/). */
const PKG_ROOT = resolve(HERE, "..");

export interface RunOptions {
  /** Explicit YYYY-MM. When omitted: OBS_MONTH env, else derived from `now`. */
  month?: string;
  /** Injected clock for the default-month path; defaults to `new Date()` inside run. */
  now?: Date;
  hostsFile?: string;
  optoutFile?: string;
  timeoutMs?: number;
  /** Minimum gap between successive host probes (politeness / restraint). */
  minIntervalMs?: number;
  /** Probe only; do not touch Postgres. */
  dryRun?: boolean;
  /** DATABASE_URL override; defaults to `process.env.DATABASE_URL`. */
  databaseUrl?: string;
  /** Sink for progress lines (defaults to stderr). */
  log?: (line: string) => void;
}

export interface RunSummary {
  runMonth: string;
  totalSeed: number;
  optedOut: number;
  probed: number;
  reachable: number;
  hybrid: number;
  pctHybridKex: number;
  dryRun: boolean;
}

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Validate/derive the run month as YYYY-MM. */
export function resolveMonth(opts: Pick<RunOptions, "month" | "now">): string {
  const explicit = opts.month ?? process.env.OBS_MONTH;
  if (explicit) {
    if (!/^\d{4}-\d{2}$/.test(explicit)) {
      throw new Error(`invalid --month "${explicit}": expected YYYY-MM`);
    }
    return explicit;
  }
  const d = opts.now ?? new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

/** Run the observatory for one month. Never throws on a single host's failure. */
export async function run(opts: RunOptions = {}): Promise<RunSummary> {
  const log = opts.log ?? ((line: string): void => void process.stderr.write(line + "\n"));
  const runMonth = resolveMonth(opts);
  const timeoutMs = opts.timeoutMs ?? 8000;
  const minIntervalMs = opts.minIntervalMs ?? 500;
  const dryRun = opts.dryRun ?? false;

  const hostsFile = opts.hostsFile ?? join(PKG_ROOT, "hosts.txt");
  const optoutFile = opts.optoutFile ?? join(PKG_ROOT, "optout.txt");

  const seeds: SeedHost[] = loadSeedHosts(hostsFile);
  const optout = new Set(loadOptOut(optoutFile));
  if (seeds.length === 0) throw new Error(`no seed hosts found in ${hostsFile}`);

  log(
    `observatory: month=${runMonth} seed=${seeds.length} opt-out=${optout.size} dryRun=${dryRun}`,
  );

  const databaseUrl = opts.databaseUrl ?? process.env.DATABASE_URL;
  if (!dryRun && !databaseUrl) {
    throw new Error("DATABASE_URL is not set (use --dry-run to probe without writing)");
  }

  const client = !dryRun && databaseUrl ? await openDb(databaseUrl) : null;
  let probed = 0;
  let reachable = 0;
  let hybrid = 0;

  try {
    if (client) {
      await ensureSchema(client);
      await upsertHosts(client, seeds, optout);
    }
    // Canonical ids + opt-out state come from the DB (which may include
    // website-marked opt-outs); in dry-run we fall back to the seed rank.
    const hostRows = client
      ? await fetchHostRows(
          client,
          seeds.map((s) => s.domain),
        )
      : new Map<string, { id: string; optedOut: boolean; rank: number | null }>();

    let first = true;
    for (const seed of seeds) {
      const row = hostRows.get(seed.domain);
      const optedOut = optout.has(seed.domain) || (row?.optedOut ?? false);
      if (optedOut) {
        log(`  skip ${seed.domain} (opted out)`);
        continue;
      }
      // Restraint: a minimum gap between successive hosts. No parallel fan-out.
      if (!first && minIntervalMs > 0) await delay(minIntervalMs);
      first = false;

      const m = await measureHost(seed.domain, { timeoutMs });
      probed += 1;
      if (m.reachable) {
        reachable += 1;
        if (m.kexHybrid) hybrid += 1;
      }
      const status = m.reachable
        ? `${m.tlsVersion ?? "?"} kex=${m.kexGroup ?? "?"} hybrid=${m.kexHybrid} sig=${m.certSigAlg ?? "?"}`
        : `unreachable (${m.error ?? "unknown"})`;
      log(`  ${seed.domain}: ${status}`);

      if (client) {
        const hostId = row?.id ?? seed.domain;
        await upsertProbe(client, hostId, runMonth, m);
      }
    }

    let pctHybridKex = reachable > 0 ? Math.round((hybrid / reachable) * 10000) / 100 : 0;
    if (client) {
      const rollup = await computeRollup(client, runMonth);
      pctHybridKex = rollup.pctHybridKex;
      log(
        `observatory: rollup ${rollup.runMonth} hosts=${rollup.hostsProbed} ` +
          `reachable=${rollup.reachable} hybrid=${rollup.hybrid} pct=${rollup.pctHybridKex}%`,
      );
    }

    return {
      runMonth,
      totalSeed: seeds.length,
      optedOut: seeds.filter((s) => optout.has(s.domain) || hostRows.get(s.domain)?.optedOut)
        .length,
      probed,
      reachable,
      hybrid,
      pctHybridKex,
      dryRun,
    };
  } finally {
    if (client) await client.end();
  }
}
