/**
 * Dependency-advisory scanning (opt-in, wired to `qscan --audit`).
 *
 * Unlike the built-in {@link vulnerableDependencies} database — which flags
 * packages whose *purpose* is quantum-vulnerable classical crypto — this module
 * surfaces KNOWN SECURITY ADVISORIES (CVE / RUSTSEC / GHSA / PYSEC) against the
 * pinned versions in a project's lockfiles, by shelling out to each ecosystem's
 * own audit tool:
 *   - Rust  (`Cargo.toml` / `Cargo.lock`)          → `cargo audit --json`
 *   - Python(`requirements*.txt` / `pyproject.toml`)→ `pip-audit --format json`
 *   - npm   (`package-lock.json`)                   → `npm audit --json`
 *
 * DESIGN (mirrors `changed.ts` / `sign.ts`, the blessed shell-out pattern):
 *  - `execFile` (never a shell), a timeout, and a bounded `maxBuffer`, all inside
 *    a try/catch. A missing tool (`ENOENT`) or any other failure NEVER throws —
 *    it degrades to a diagnostic string ("cargo audit not available, skipped").
 *  - The audit tools exit NON-ZERO when they find advisories, so their JSON
 *    arrives on the error's `stdout`; that is the normal, expected path.
 *  - Zero runtime dependencies (ADR-0001): only `node:child_process` /
 *    `node:util` / `node:fs` — the same built-ins `changed.ts` already uses.
 *
 * Findings are `category: "dependency"`, `ruleId: "dep-advisory"`, located at the
 * project's manifest file. They are produced by this scanner, not a registered
 * {@link Detector}, so — exactly like `DEP_VULNERABLE_RULE` — the generic
 * {@link DEP_ADVISORY_RULE} catalog entry is merged into the SARIF `rules[]` by
 * the reporter (see qscan `report.ts`).
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readdir } from "node:fs/promises";
import * as path from "node:path";

import type { Finding, RuleMeta, Severity } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * Generic catalog entry for the `dep-advisory` rule. The per-advisory specifics
 * (title / severity / patched version) live on each individual finding; this is
 * the shared, package-agnostic description SARIF advertises for the rule.
 */
export const DEP_ADVISORY_RULE: RuleMeta = {
  id: "dep-advisory",
  title: "Dependency with a known security advisory",
  category: "dependency",
  // Representative default; each finding carries its own advisory severity.
  severity: "high",
  confidence: "high",
  hndl: false,
  message:
    "A pinned dependency has a published security advisory (CVE / RUSTSEC / GHSA / PYSEC). Upgrade to a patched version.",
  remediation: "Upgrade the affected package to the advisory's patched release.",
  description:
    "Flags dependencies with a known security advisory, via the ecosystem's own audit tool (cargo audit / pip-audit / npm audit). Opt-in with `qscan --audit`.",
};

/** Options for {@link scanAdvisories}. */
export interface ScanAdvisoriesOptions {
  /** Per-tool timeout in milliseconds. Default: 120_000. */
  timeoutMs?: number;
  /** Max stdout buffer per tool, in bytes. Default: 32 MiB. */
  maxBuffer?: number;
  /**
   * Injectable command runner (for tests). Resolves with the tool's stdout, or
   * rejects with an error carrying `code` (e.g. `"ENOENT"`) and, for a non-zero
   * exit, the captured `stdout`. Defaults to a promisified `execFile`.
   */
  exec?: ExecFn;
  /** Injectable directory lister (for tests). Defaults to `fs.readdir`. */
  listDir?: (dir: string) => Promise<string[]>;
}

/** Shape of an injectable command runner and of the errors it may reject with. */
export type ExecFn = (
  command: string,
  args: readonly string[],
  options: { cwd: string; timeout: number; maxBuffer: number },
) => Promise<{ stdout: string; stderr: string }>;

interface ExecError {
  code?: string;
  killed?: boolean;
  signal?: string;
  stdout?: string;
  stderr?: string;
  message?: string;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_BUFFER = 32 * 1024 * 1024;

/** One audit tool and how to detect + parse it. */
interface AuditTool {
  /** Human label used in diagnostics (e.g. "cargo audit"). */
  label: string;
  /** Program to run. */
  command: string;
  /** Arguments (must request JSON output). */
  args: string[];
  /**
   * Given the project's top-level entry names, return the manifest file the
   * advisories should be located at, or null when this ecosystem is absent.
   */
  manifest: (entries: readonly string[]) => string | null;
  /** Parse the tool's JSON stdout into normalized advisory records. */
  parse: (json: unknown) => AdvisoryRecord[];
}

/** A normalized advisory, ecosystem-independent. */
interface AdvisoryRecord {
  /** Advisory id (CVE-…, RUSTSEC-…, GHSA-…, PYSEC-…). */
  id: string;
  package: string;
  version: string;
  summary: string;
  severity: Severity;
  /** Patched version(s), when the tool reports them. */
  patched?: string;
}

/** Map an ecosystem-reported severity token to our {@link Severity}. */
function toSeverity(raw: unknown): Severity {
  const s = String(raw ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "moderate" || s === "medium") return "medium";
  if (s === "low") return "low";
  if (s === "info" || s === "informational" || s === "none" || s === "negligible") return "info";
  // An advisory with no usable severity is treated as high (conservative — a
  // known-vulnerable pinned dependency should not silently pass a scan).
  return "high";
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" ? (v as Record<string, unknown>) : null;
}
function str(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : String(v);
}
function firstString(v: unknown): string | undefined {
  if (typeof v === "string" && v) return v;
  if (Array.isArray(v)) {
    const s = v.find((x) => typeof x === "string" && x);
    return typeof s === "string" ? s : undefined;
  }
  return undefined;
}

/** cargo audit --json → advisories. */
function parseCargoAudit(json: unknown): AdvisoryRecord[] {
  const root = asRecord(json);
  const vulns = asRecord(root?.vulnerabilities);
  const list = Array.isArray(vulns?.list) ? vulns.list : [];
  const out: AdvisoryRecord[] = [];
  for (const item of list) {
    const rec = asRecord(item);
    const advisory = asRecord(rec?.advisory);
    const pkg = asRecord(rec?.package);
    const versions = asRecord(rec?.versions);
    if (!advisory) continue;
    out.push({
      id: str(advisory.id) || "RUSTSEC-UNKNOWN",
      package: str(pkg?.name) || str(advisory.package),
      version: str(pkg?.version),
      summary: str(advisory.title) || "security advisory",
      severity: toSeverity(advisory.severity),
      patched: firstString(versions?.patched),
    });
  }
  return out;
}

/** pip-audit --format json → advisories. Handles the object + legacy-array forms. */
function parsePipAudit(json: unknown): AdvisoryRecord[] {
  const root = asRecord(json);
  const deps = Array.isArray(json)
    ? json
    : Array.isArray(root?.dependencies)
      ? root.dependencies
      : [];
  const out: AdvisoryRecord[] = [];
  for (const item of deps) {
    const dep = asRecord(item);
    if (!dep) continue;
    const name = str(dep.name);
    const version = str(dep.version);
    const vulns = Array.isArray(dep.vulns) ? dep.vulns : [];
    for (const v of vulns) {
      const vuln = asRecord(v);
      if (!vuln) continue;
      out.push({
        id: str(vuln.id) || firstString(vuln.aliases) || "PYSEC-UNKNOWN",
        package: name,
        version,
        summary: str(vuln.description) || "security advisory",
        // pip-audit's base JSON does not grade severity; treat as high.
        severity: toSeverity(vuln.severity),
        patched: firstString(vuln.fix_versions),
      });
    }
  }
  return out;
}

/** Extract a GHSA id from an advisory URL when present. */
function ghsaFrom(url: string): string | undefined {
  const m = /GHSA-[\w-]+/.exec(url);
  return m ? m[0] : undefined;
}

/** npm audit --json (npm v7+) → advisories. */
function parseNpmAudit(json: unknown): AdvisoryRecord[] {
  const root = asRecord(json);
  const vulns = asRecord(root?.vulnerabilities);
  if (!vulns) return [];
  const out: AdvisoryRecord[] = [];
  for (const [name, entry] of Object.entries(vulns)) {
    const rec = asRecord(entry);
    if (!rec) continue;
    const range = str(rec.range);
    const fix = asRecord(rec.fixAvailable);
    const patched = fix ? str(fix.version) : undefined;
    const via = Array.isArray(rec.via) ? rec.via : [];
    for (const v of via) {
      const adv = asRecord(v);
      if (!adv) continue; // string `via` = transitive; the source entry carries the detail.
      const url = str(adv.url);
      const id =
        ghsaFrom(url) ||
        (adv.source !== undefined ? `npm-advisory-${str(adv.source)}` : url) ||
        "npm-advisory";
      out.push({
        id,
        package: str(adv.name) || name,
        version: range,
        summary: str(adv.title) || "security advisory",
        severity: toSeverity(adv.severity ?? rec.severity),
        patched: patched || undefined,
      });
    }
  }
  return out;
}

/** Match `requirements*.txt` (requirements.txt, requirements-dev.txt, …). */
function isRequirements(name: string): boolean {
  return /^requirements[\w.-]*\.txt$/i.test(name);
}

/** The audit tools, in a deterministic order. */
const AUDIT_TOOLS: readonly AuditTool[] = [
  {
    label: "cargo audit",
    command: "cargo",
    args: ["audit", "--json"],
    manifest: (e) =>
      e.includes("Cargo.lock") ? "Cargo.lock" : e.includes("Cargo.toml") ? "Cargo.toml" : null,
    parse: parseCargoAudit,
  },
  {
    label: "pip-audit",
    command: "pip-audit",
    args: ["--format", "json"],
    manifest: (e) => {
      const req = e.find(isRequirements);
      if (req) return req;
      return e.includes("pyproject.toml") ? "pyproject.toml" : null;
    },
    parse: parsePipAudit,
  },
  {
    label: "npm audit",
    command: "npm",
    args: ["audit", "--json"],
    manifest: (e) => (e.includes("package-lock.json") ? "package-lock.json" : null),
    parse: parseNpmAudit,
  },
];

/** Build a {@link Finding} from a normalized advisory record. */
function advisoryFinding(rec: AdvisoryRecord, manifest: string): Finding {
  const pkgVer = rec.version ? `${rec.package}@${rec.version}` : rec.package;
  const finding: Finding = {
    ruleId: "dep-advisory",
    title: rec.id,
    category: "dependency",
    severity: rec.severity,
    confidence: "high",
    hndl: false,
    message: `${pkgVer}: ${rec.summary} (${rec.id})`,
    location: { file: manifest, line: 1 },
  };
  if (rec.patched) finding.remediation = `Upgrade ${rec.package} to ${rec.patched}`;
  return finding;
}

/**
 * Scan `root` for dependency security advisories by shelling out to each present
 * ecosystem's audit tool. Never throws: a missing tool or a tool error becomes a
 * diagnostic string. Returns the merged findings plus the diagnostics.
 */
export async function scanAdvisories(
  root: string,
  opts: ScanAdvisoriesOptions = {},
): Promise<{ findings: Finding[]; diagnostics: string[] }> {
  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;
  const list = opts.listDir ?? ((dir: string) => readdir(dir));
  const exec: ExecFn =
    opts.exec ??
    ((command, args, options) =>
      execFileAsync(command, args as string[], { ...options, windowsHide: true }));

  const findings: Finding[] = [];
  const diagnostics: string[] = [];

  let entries: string[];
  try {
    entries = await list(root);
  } catch {
    return { findings, diagnostics }; // unreadable root — nothing to audit.
  }

  for (const tool of AUDIT_TOOLS) {
    const manifest = tool.manifest(entries);
    if (manifest === null) continue; // this ecosystem isn't present.

    let stdout: string;
    try {
      const res = await exec(tool.command, tool.args, { cwd: root, timeout, maxBuffer });
      stdout = res.stdout;
    } catch (err) {
      const e = err as ExecError;
      if (e.code === "ENOENT") {
        diagnostics.push(`${tool.label} not available, skipped`);
        continue;
      }
      if (e.killed || e.signal === "SIGTERM") {
        diagnostics.push(`${tool.label} timed out, skipped`);
        continue;
      }
      // A non-zero exit is EXPECTED when advisories are found: the JSON is on
      // the error's stdout. Only when there is no parseable stdout is it a real
      // failure we skip over.
      if (typeof e.stdout === "string" && e.stdout.trim()) {
        stdout = e.stdout;
      } else {
        const detail = (e.stderr || e.message || "").trim().slice(0, 160);
        diagnostics.push(`${tool.label} failed, skipped${detail ? `: ${detail}` : ""}`);
        continue;
      }
    }

    let json: unknown;
    try {
      json = JSON.parse(stdout);
    } catch {
      diagnostics.push(`${tool.label} produced unparseable output, skipped`);
      continue;
    }

    let records: AdvisoryRecord[];
    try {
      records = tool.parse(json);
    } catch {
      diagnostics.push(`${tool.label} output could not be interpreted, skipped`);
      continue;
    }

    // Dedupe by advisory id + package (npm lists the same advisory under both a
    // direct and a transitive path).
    const seen = new Set<string>();
    for (const rec of records) {
      const key = `${rec.id}|${rec.package}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(advisoryFinding(rec, path.posix.basename(manifest)));
    }
  }

  return { findings, diagnostics };
}
