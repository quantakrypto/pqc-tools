/**
 * Reporting: turn a qProbe {@link RunResult} into `@quantakrypto/core`'s shared
 * output formats, so live-endpoint findings emit the SAME SARIF 2.1.0 and
 * CycloneDX 1.6 CBOM as qScan (code) and the infra detectors (config). This is
 * what lets the three planes compose into one post-quantum posture: a qScan CBOM
 * and a qProbe CBOM are both CycloneDX 1.6 documents and merge cleanly.
 *
 * The core reporters are findings-based (they derive SARIF `rules[]` and CBOM
 * crypto-assets from the findings themselves), so no registry entry is needed for
 * the `qprobe-*` rules.
 */
import type { ScanResult, SarifLog, CycloneDxBom } from "@quantakrypto/core";
import { toSarif, toJson, toCbom } from "@quantakrypto/core";
import type { RunResult } from "./index.js";
import { VERSION } from "./version.js";

/**
 * Adapt a {@link RunResult} to a {@link ScanResult}. `filesScanned` is the number
 * of endpoints probed; `root` is the probed target list.
 */
export function toScanResult(run: RunResult, startedAt: string, finishedAt: string): ScanResult {
  return {
    root: run.reports.map((r) => `${r.target.host}:${r.target.port}`).join(", ") || "(no targets)",
    findings: run.findings,
    filesScanned: run.reports.length,
    inventory: run.inventory,
    startedAt,
    finishedAt,
    toolVersion: `qprobe ${VERSION}`,
  };
}

export function toSarifReport(run: RunResult, startedAt: string, finishedAt: string): SarifLog {
  return toSarif(toScanResult(run, startedAt, finishedAt));
}

export function toCbomReport(run: RunResult, startedAt: string, finishedAt: string): CycloneDxBom {
  const bom = toCbom(toScanResult(run, startedAt, finishedAt));
  // core's toCbom labels the producing tool "qScan"; correct it for qProbe so a
  // merged code+endpoints CBOM attributes each plane to the right tool.
  const tools = (bom.metadata as { tools?: { components?: { name?: string }[] } }).tools
    ?.components;
  if (Array.isArray(tools)) for (const t of tools) if (t.name === "qScan") t.name = "qProbe";
  return bom;
}

export function toJsonReport(
  run: RunResult,
  startedAt: string,
  finishedAt: string,
): Record<string, unknown> {
  // Core's structured JSON (findings + inventory), augmented with the per-endpoint
  // probe detail qProbe uniquely carries (negotiated params, hybrid result).
  const base = toJson(toScanResult(run, startedAt, finishedAt));
  return {
    ...base,
    endpoints: run.reports.map((r) => ({
      target: `${r.target.host}:${r.target.port}`,
      mode: r.mode,
      positives: r.positives,
      tls: r.tls,
      hybrid: r.hybrid,
      ssh: r.ssh
        ? { banner: r.ssh.banner, pqKexOffered: r.ssh.pqKexOffered, error: r.ssh.error }
        : undefined,
    })),
  };
}
