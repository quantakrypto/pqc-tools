#!/usr/bin/env node
/**
 * Observatory CLI. Thin shell over `run` in `./run.ts`: parse argv, print, exit.
 *
 *   observatory run [--month YYYY-MM] [--hosts PATH] [--optout PATH]
 *                   [--timeout MS] [--interval MS] [--dry-run]
 *
 * When --month is omitted the month is OBS_MONTH, else the current UTC month
 * (computed inside `run`, never at module load). DATABASE_URL is read from the
 * environment; --dry-run probes without writing to Postgres.
 */
import process from "node:process";

import { run } from "./run.js";

const HELP = `observatory - internal PQC readiness prober (not a published tool)

Usage:
  observatory run [options]

Options:
  --month YYYY-MM    Run month (default: OBS_MONTH env, else current UTC month)
  --hosts PATH       Seed host list (default: packages/observatory/hosts.txt)
  --optout PATH      Opt-out list  (default: packages/observatory/optout.txt)
  --timeout MS       Per-connection hard timeout (default: 8000)
  --interval MS      Minimum gap between hosts (default: 500)
  --dry-run          Probe only; do not connect to or write Postgres
  -h, --help         Show this help

Environment:
  DATABASE_URL       Postgres connection string (required unless --dry-run)
  OBS_MONTH          Fallback run month when --month is not given
`;

interface Parsed {
  help: boolean;
  month?: string;
  hostsFile?: string;
  optoutFile?: string;
  timeoutMs?: number;
  minIntervalMs?: number;
  dryRun: boolean;
}

function parseInteger(flag: string, value: string | undefined): number {
  if (value === undefined) throw new Error(`${flag} requires a value`);
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) throw new Error(`${flag} must be a non-negative number`);
  return n;
}

function parseArgs(argv: readonly string[]): Parsed {
  const out: Parsed = { help: false, dryRun: false };
  // First non-flag token is the subcommand; only `run` is supported.
  const args = [...argv];
  const sub = args.find((a) => !a.startsWith("-"));
  if (sub && sub !== "run") throw new Error(`unknown command "${sub}" (only "run")`);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case "run":
        break;
      case "-h":
      case "--help":
        out.help = true;
        break;
      case "--dry-run":
        out.dryRun = true;
        break;
      case "--month":
        out.month = args[++i];
        break;
      case "--hosts":
        out.hostsFile = args[++i];
        break;
      case "--optout":
        out.optoutFile = args[++i];
        break;
      case "--timeout":
        out.timeoutMs = parseInteger("--timeout", args[++i]);
        break;
      case "--interval":
        out.minIntervalMs = parseInteger("--interval", args[++i]);
        break;
      default:
        if (a.startsWith("-")) throw new Error(`unknown option "${a}"`);
    }
  }
  return out;
}

async function main(argv: readonly string[]): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`observatory: ${(err as Error).message}\n`);
    process.stderr.write(`Run "observatory --help" for usage.\n`);
    return 2;
  }
  if (parsed.help || argv.length === 0) {
    process.stdout.write(HELP);
    return 0;
  }
  try {
    const summary = await run({
      month: parsed.month,
      hostsFile: parsed.hostsFile,
      optoutFile: parsed.optoutFile,
      timeoutMs: parsed.timeoutMs,
      minIntervalMs: parsed.minIntervalMs,
      dryRun: parsed.dryRun,
    });
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
    return 0;
  } catch (err) {
    process.stderr.write(`observatory: ${(err as Error).message}\n`);
    return 1;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`observatory: fatal ${String(err)}\n`);
    process.exit(1);
  },
);
