/**
 * Postgres persistence for the observatory.
 *
 * The three tables are OWNED by the website's migration; this worker only ever
 * CREATE TABLE IF NOT EXISTS them (defensively, so it can run standalone) and
 * upserts rows. It never drops or alters them, so a run against a DB the website
 * already migrated is a no-op on the schema and a plain upsert on the data.
 *
 * `pg` is the observatory's ONLY third-party dependency, and it is a devDependency
 * of this private package alone; the published qProbe / qScan / core packages stay
 * zero-dependency (ADR-0001).
 */
import { Client } from "pg";

import type { SeedHost } from "./hosts.js";
import type { HostMeasurement } from "./probe.js";

/** Exact schema from the website migration, guarded with IF NOT EXISTS. */
export const SCHEMA_DDL = `
CREATE TABLE IF NOT EXISTS observatory_host (
  id text PRIMARY KEY, domain text UNIQUE NOT NULL, rank_source text,
  rank int, added_at timestamptz NOT NULL DEFAULT now(), opted_out_at timestamptz);
CREATE TABLE IF NOT EXISTS observatory_probe (
  id text PRIMARY KEY, host_id text NOT NULL REFERENCES observatory_host(id) ON DELETE CASCADE,
  run_month text NOT NULL, reachable boolean NOT NULL DEFAULT false,
  kex_hybrid boolean NOT NULL DEFAULT false, kex_group text, tls_version text,
  cert_sig_alg text, cert_expiry timestamptz, probed_at timestamptz NOT NULL DEFAULT now(),
  raw jsonb NOT NULL DEFAULT '{}'::jsonb, UNIQUE (host_id, run_month));
CREATE TABLE IF NOT EXISTS observatory_rollup (
  run_month text PRIMARY KEY, hosts_probed int NOT NULL, pct_hybrid_kex numeric NOT NULL,
  by_rank_bucket jsonb NOT NULL DEFAULT '{}'::jsonb, generated_at timestamptz NOT NULL DEFAULT now());
`;

export interface HostRow {
  id: string;
  optedOut: boolean;
  rank: number | null;
}

export interface RollupBucket {
  hosts_probed: number;
  reachable: number;
  hybrid: number;
  pct_hybrid_kex: number;
}

export interface RollupResult {
  runMonth: string;
  hostsProbed: number;
  reachable: number;
  hybrid: number;
  pctHybridKex: number;
  byRankBucket: Record<string, RollupBucket>;
}

/** Open a client from `DATABASE_URL` (or an explicit override) and connect. */
export async function openDb(databaseUrl: string): Promise<Client> {
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  return client;
}

/** Create the three tables if they do not already exist. Never alters existing tables. */
export async function ensureSchema(client: Client): Promise<void> {
  await client.query(SCHEMA_DDL);
}

/**
 * Upsert the seed hosts. New rows are inserted (ON CONFLICT (domain) DO NOTHING so
 * we never clobber a website-owned row). Opt-out is then applied by a separate
 * UPDATE so a host that already existed still gets `opted_out_at` set within this
 * run. Opt-out is sticky: we never clear `opted_out_at` for a host dropped from the
 * opt-out list (removing a host from probing is intentional and stays until an
 * operator clears it in the DB).
 */
export async function upsertHosts(
  client: Client,
  seeds: SeedHost[],
  optout: Set<string>,
): Promise<void> {
  for (const s of seeds) {
    const optedOutAt = optout.has(s.domain) ? new Date().toISOString() : null;
    await client.query(
      `INSERT INTO observatory_host (id, domain, rank_source, rank, opted_out_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (domain) DO NOTHING`,
      [s.domain, s.domain, s.rankSource, s.rank, optedOutAt],
    );
  }
  // Any opt-out domain (seed or already present) that is not yet marked: mark it now.
  const optoutList = [...optout];
  if (optoutList.length > 0) {
    await client.query(
      `UPDATE observatory_host SET opted_out_at = now()
       WHERE domain = ANY($1::text[]) AND opted_out_at IS NULL`,
      [optoutList],
    );
  }
}

/** Read the canonical id / opt-out state / rank for each domain. */
export async function fetchHostRows(
  client: Client,
  domains: string[],
): Promise<Map<string, HostRow>> {
  const map = new Map<string, HostRow>();
  if (domains.length === 0) return map;
  const res = await client.query(
    `SELECT id, domain, rank, opted_out_at FROM observatory_host WHERE domain = ANY($1::text[])`,
    [domains],
  );
  for (const r of res.rows as Array<{
    id: string;
    domain: string;
    rank: number | null;
    opted_out_at: Date | null;
  }>) {
    map.set(r.domain, { id: r.id, optedOut: r.opted_out_at !== null, rank: r.rank });
  }
  return map;
}

/** Insert or update the probe row for (host, month). Idempotent per month. */
export async function upsertProbe(
  client: Client,
  hostId: string,
  runMonth: string,
  m: HostMeasurement,
): Promise<void> {
  await client.query(
    `INSERT INTO observatory_probe
       (id, host_id, run_month, reachable, kex_hybrid, kex_group, tls_version,
        cert_sig_alg, cert_expiry, probed_at, raw)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10::jsonb)
     ON CONFLICT (host_id, run_month) DO UPDATE SET
       reachable = EXCLUDED.reachable,
       kex_hybrid = EXCLUDED.kex_hybrid,
       kex_group = EXCLUDED.kex_group,
       tls_version = EXCLUDED.tls_version,
       cert_sig_alg = EXCLUDED.cert_sig_alg,
       cert_expiry = EXCLUDED.cert_expiry,
       probed_at = now(),
       raw = EXCLUDED.raw`,
    [
      `${hostId}:${runMonth}`,
      hostId,
      runMonth,
      m.reachable,
      m.kexHybrid,
      m.kexGroup ?? null,
      m.tlsVersion ?? null,
      m.certSigAlg ?? null,
      m.certExpiry ?? null,
      JSON.stringify(m.raw),
    ],
  );
}

/** Rank -> bucket label. Buckets are coarse on purpose (small seed list). */
function rankBucket(rank: number | null): string {
  if (rank === null) return "unranked";
  if (rank <= 25) return "1-25";
  if (rank <= 50) return "26-50";
  return "51+";
}

/**
 * Recompute the month's rollup from `observatory_probe` joined to host rank, then
 * upsert `observatory_rollup`. `pct_hybrid_kex` is the share of REACHABLE hosts that
 * selected the hybrid group (unreachable hosts are excluded from the denominator).
 */
export async function computeRollup(client: Client, runMonth: string): Promise<RollupResult> {
  const res = await client.query(
    `SELECT h.rank AS rank, p.reachable AS reachable, p.kex_hybrid AS kex_hybrid
       FROM observatory_probe p
       JOIN observatory_host h ON h.id = p.host_id
      WHERE p.run_month = $1`,
    [runMonth],
  );
  const rows = res.rows as Array<{ rank: number | null; reachable: boolean; kex_hybrid: boolean }>;

  const buckets: Record<string, RollupBucket> = {};
  let hostsProbed = 0;
  let reachable = 0;
  let hybrid = 0;
  for (const row of rows) {
    hostsProbed += 1;
    const label = rankBucket(row.rank);
    const b = (buckets[label] ??= { hosts_probed: 0, reachable: 0, hybrid: 0, pct_hybrid_kex: 0 });
    b.hosts_probed += 1;
    if (row.reachable) {
      reachable += 1;
      b.reachable += 1;
      if (row.kex_hybrid) {
        hybrid += 1;
        b.hybrid += 1;
      }
    }
  }
  const pct = (n: number, d: number): number => (d > 0 ? Math.round((n / d) * 10000) / 100 : 0);
  for (const b of Object.values(buckets)) b.pct_hybrid_kex = pct(b.hybrid, b.reachable);
  const pctHybridKex = pct(hybrid, reachable);

  await client.query(
    `INSERT INTO observatory_rollup (run_month, hosts_probed, pct_hybrid_kex, by_rank_bucket, generated_at)
     VALUES ($1, $2, $3, $4::jsonb, now())
     ON CONFLICT (run_month) DO UPDATE SET
       hosts_probed = EXCLUDED.hosts_probed,
       pct_hybrid_kex = EXCLUDED.pct_hybrid_kex,
       by_rank_bucket = EXCLUDED.by_rank_bucket,
       generated_at = now()`,
    [runMonth, hostsProbed, pctHybridKex, JSON.stringify(buckets)],
  );

  return { runMonth, hostsProbed, reachable, hybrid, pctHybridKex, byRankBucket: buckets };
}
