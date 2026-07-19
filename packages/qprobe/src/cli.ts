#!/usr/bin/env node
/**
 * qprobe CLI — a thin shell over the programmatic API: parse argv, authorize,
 * probe, print, and set an exit code. It never throws to the top level.
 * Exit codes mirror qScan: 0 OK, 1 findings, 2 error/usage.
 */
import { readFileSync } from "node:fs";
import { parseArgs, HELP } from "./args.js";
import { parseTarget, TargetError } from "./target.js";
import { parseOwnedHosts, AttestationError } from "./attest.js";
import { runProbe, type RunResult, type EndpointReport } from "./index.js";
import { toJsonReport, toSarifReport, toCbomReport } from "./report.js";
import { VERSION } from "./version.js";

const EXIT = { OK: 0, FINDINGS: 1, ERROR: 2 } as const;

function endpointLine(r: EndpointReport): string {
  const t = `${r.target.host}:${r.target.port}`;
  const lines: string[] = [`\n${t}  [${r.mode}]`];
  if (r.mode !== "ssh" && r.tls) {
    if (r.tls.error) lines.push(`  ${r.mode}: ${r.tls.error}`);
    else
      lines.push(
        `  ${r.tls.protocol ?? "?"} · ${r.tls.cipher ?? "?"} · KEX ${r.tls.kexGroup ?? "?"} · cert ${
          r.tls.certKeyType ?? "?"
        }${r.tls.certKeyBits ? `-${r.tls.certKeyBits}` : ""}${
          r.tls.certSigFamily ? ` (sig ${r.tls.certSigFamily})` : ""
        }`,
      );
    if (r.hybrid && !r.hybrid.error)
      lines.push(
        `  PQC-hybrid (X25519MLKEM768): ${r.hybrid.hybridSelected ? "SUPPORTED ✓" : "not negotiated"}`,
      );
  }
  if (r.mode === "ssh" && r.ssh) {
    if (r.ssh.error) lines.push(`  ssh: ${r.ssh.error}`);
    else
      lines.push(`  ${r.ssh.banner ?? ""} · PQC KEX: ${r.ssh.pqKexOffered ? "offered ✓" : "none"}`);
  }
  for (const p of r.positives) lines.push(`  ✓ ${p}`);
  for (const f of r.findings) lines.push(`  [${f.severity}] ${f.title} — ${f.message}`);
  return lines.join("\n");
}

function formatHuman(result: RunResult): string {
  const out: string[] = [`qProbe — live post-quantum readiness · qprobe v${VERSION}`];
  for (const r of result.reports) out.push(endpointLine(r));
  const f = result.findings;
  out.push(
    `\n${f.length} finding${f.length === 1 ? "" : "s"} · ${result.inventory.hndlCount} HNDL-exposed · readiness ${
      result.inventory.readinessScore
    }/100`,
  );
  return out.join("\n") + "\n";
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return EXIT.OK;
  }
  if (args.targets.length === 0) {
    console.error(HELP);
    return EXIT.ERROR;
  }

  const DEFAULT_PORTS: Record<string, number> = {
    ssh: 22,
    smtp: 587,
    imap: 143,
    pop3: 110,
    postgres: 5432,
  };
  const defaultPort = DEFAULT_PORTS[args.mode] ?? 443;
  let targets;
  try {
    targets = args.targets.map((t) => parseTarget(t, defaultPort));
  } catch (e) {
    if (e instanceof TargetError) {
      console.error(`qprobe: ${e.message}`);
      return EXIT.ERROR;
    }
    throw e;
  }

  let ownedHosts: string[] | undefined;
  if (args.ownedHostsFile) {
    try {
      ownedHosts = parseOwnedHosts(readFileSync(args.ownedHostsFile, "utf8"));
    } catch {
      console.error(`qprobe: cannot read ownership manifest ${args.ownedHostsFile}`);
      return EXIT.ERROR;
    }
  }

  const startedAt = new Date().toISOString();
  let result: RunResult;
  try {
    result = await runProbe({
      targets,
      mode: args.mode,
      attest: { iOwnThis: args.iOwnThis, ownedHosts },
      servername: args.servername,
      timeoutMs: args.timeoutMs,
    });
  } catch (e) {
    if (e instanceof AttestationError) {
      console.error(`qprobe: ${e.message}`);
      return EXIT.ERROR;
    }
    throw e;
  }
  const finishedAt = new Date().toISOString();

  switch (args.format) {
    case "json":
      console.log(JSON.stringify(toJsonReport(result, startedAt, finishedAt), null, 2));
      break;
    case "sarif":
      console.log(JSON.stringify(toSarifReport(result, startedAt, finishedAt), null, 2));
      break;
    case "cbom":
      console.log(JSON.stringify(toCbomReport(result, startedAt, finishedAt), null, 2));
      break;
    default:
      process.stdout.write(formatHuman(result));
  }

  return result.findings.length > 0 ? EXIT.FINDINGS : EXIT.OK;
}

main()
  .then((code) => process.exit(code))
  .catch((e: unknown) => {
    console.error(`qprobe: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(EXIT.ERROR);
  });
