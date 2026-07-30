/**
 * Provenance / declared-source-repository check (wired to `qscan --audit`).
 *
 * A package that declares no source repository, or one whose declared repository
 * does not resolve, cannot have its published artifacts verified against source —
 * a supply-chain gap. This reads the ROOT manifest's repository URL and emits:
 *
 *   - `provenance-repo-missing`   (info)    — the manifest declares no repository.
 *   - `provenance-repo-unresolved`(medium)  — the declared repository 404s / does
 *                                             not resolve (network mode only).
 *
 * OFFLINE BOUNDARY (ADR-0005). `@quantakrypto/core` must stay strictly offline: it
 * may NOT import `node:https` or make outbound calls. So this module does the
 * pure work — parse the manifest, decide what to check — and delegates the actual
 * HEAD request to an INJECTED {@link RepoHeadRequester} that the caller (qScan,
 * which is allowed to be networked) supplies. In the default (static) mode no
 * network hook is used at all, so a scan without `--audit` never reaches for one.
 */
import { readFile } from "node:fs/promises";
import * as path from "node:path";

import type { Finding } from "./types.js";

/** Outcome of a HEAD request to a declared repository URL. */
export type RepoHeadOutcome =
  | { kind: "status"; status: number } // an HTTP response was received.
  | { kind: "unresolved" } // DNS / host-not-found — the repository does not exist.
  | { kind: "error"; message: string }; // transient network error — verification skipped.

/**
 * Injected HEAD requester. Implemented by the (networked) caller — qScan supplies
 * a `node:https`-backed one — so core never imports an outbound network module.
 * MUST resolve (never reject); map its own failures onto {@link RepoHeadOutcome}.
 */
export type RepoHeadRequester = (url: string, timeoutMs: number) => Promise<RepoHeadOutcome>;

/** Options for {@link checkProvenance}. */
export interface ProvenanceOptions {
  /**
   * Verify the declared repository over the network via {@link head}. When false
   * (or when no `head` is supplied) only the static `repo-missing` check runs.
   */
  network?: boolean;
  /** HEAD-request timeout in milliseconds. Default: 5000. */
  timeoutMs?: number;
  /** Injected HEAD requester (required for the network check to do anything). */
  head?: RepoHeadRequester;
  /** Injected file reader (for tests). Defaults to `fs.readFile`. */
  readManifest?: (file: string) => Promise<string>;
}

const DEFAULT_TIMEOUT_MS = 5000;

/** The root manifests we understand, in precedence order. */
const MANIFESTS = ["package.json", "Cargo.toml", "pyproject.toml"] as const;

/** What a root manifest told us about its declared repository. */
interface ManifestRepo {
  /** The manifest filename that was read. */
  file: string;
  /** The declared repository URL, or null when the manifest declares none. */
  url: string | null;
}

/**
 * Normalize a declared repository reference to an https(s) URL, or null when it
 * cannot be turned into one we can HEAD. Handles `git+https://…`, `git://…`,
 * `git@github.com:owner/repo(.git)`, the `owner/repo` and `github:owner/repo`
 * shorthands, and strips a trailing `.git`.
 */
export function normalizeRepoUrl(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  s = s.replace(/^git\+/, "");
  // scp-style `git@host:owner/repo`
  const scp = /^[\w.-]+@([\w.-]+):(.+)$/.exec(s);
  if (scp) s = `https://${scp[1]}/${scp[2]}`;
  if (s.startsWith("git://")) s = `https://${s.slice("git://".length)}`;
  if (s.startsWith("ssh://")) s = `https://${s.slice("ssh://".length)}`;
  // `github:owner/repo` / `gitlab:owner/repo` / `bitbucket:owner/repo`
  const hosted = /^(github|gitlab|bitbucket):(.+)$/.exec(s);
  if (hosted) {
    const host = hosted[1] === "github" ? "github.com" : `${hosted[1]}.org`;
    s = `https://${host}/${hosted[2]}`;
  }
  // bare `owner/repo` shorthand → GitHub
  if (/^[\w.-]+\/[\w.-]+$/.test(s)) s = `https://github.com/${s}`;
  if (!/^https?:\/\//i.test(s)) return null;
  return s.replace(/\.git$/, "");
}

/** package.json `repository` (string or `{ url }`). */
function repoFromPackageJson(content: string): string | null {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return null;
  }
  if (json === null || typeof json !== "object") return null;
  const repo = (json as Record<string, unknown>).repository;
  if (typeof repo === "string") return normalizeRepoUrl(repo);
  if (repo !== null && typeof repo === "object") {
    const url = (repo as Record<string, unknown>).url;
    if (typeof url === "string") return normalizeRepoUrl(url);
  }
  return null;
}

/** Cargo.toml `[package] repository = "…"`. */
function repoFromCargoToml(content: string): string | null {
  const m = /^\s*repository\s*=\s*"([^"]+)"/m.exec(content);
  return m ? normalizeRepoUrl(m[1]) : null;
}

/**
 * pyproject.toml — `[project.urls]` `Repository`/`Source`/`Homepage`, or the
 * legacy `[tool.poetry]` `repository = "…"`. Generous line scan (any of those
 * keys → url), which is enough to know a repository was declared.
 */
function repoFromPyproject(content: string): string | null {
  const m = /^\s*(?:repository|source|homepage)\s*=\s*"([^"]+)"/im.exec(content);
  return m ? normalizeRepoUrl(m[1]) : null;
}

const PARSERS: Record<(typeof MANIFESTS)[number], (content: string) => string | null> = {
  "package.json": repoFromPackageJson,
  "Cargo.toml": repoFromCargoToml,
  "pyproject.toml": repoFromPyproject,
};

/**
 * Read the first present root manifest and extract its declared repository URL.
 * Returns null when NO root manifest exists (there is no package to assess).
 */
async function readManifestRepo(
  root: string,
  read: (file: string) => Promise<string>,
): Promise<ManifestRepo | null> {
  for (const file of MANIFESTS) {
    let content: string;
    try {
      content = await read(path.join(root, file));
    } catch {
      continue; // manifest absent / unreadable — try the next.
    }
    return { file, url: PARSERS[file](content) };
  }
  return null;
}

/**
 * Check a project's declared-source-repository provenance.
 *
 * Static (always): a present root manifest that declares NO repository yields a
 * `provenance-repo-missing` info finding. Network (`network: true` + a `head`
 * requester): a declared repository that 404s or does not resolve yields a
 * `provenance-repo-unresolved` (medium) finding; transient network errors are
 * skipped silently (recorded as a diagnostic). Never throws.
 */
export async function checkProvenance(
  root: string,
  opts: ProvenanceOptions = {},
): Promise<{ findings: Finding[]; diagnostics: string[] }> {
  const read = opts.readManifest ?? ((file: string) => readFile(file, "utf8"));
  const findings: Finding[] = [];
  const diagnostics: string[] = [];

  const manifest = await readManifestRepo(root, read);
  if (manifest === null) return { findings, diagnostics }; // no manifest → nothing to assess.

  if (manifest.url === null) {
    findings.push({
      ruleId: "provenance-repo-missing",
      title: "Package declares no source repository",
      category: "dependency",
      severity: "info",
      confidence: "medium",
      hndl: false,
      message: "Package declares no source repository; builds cannot be verified against source.",
      remediation:
        "Declare a source repository in the manifest (package.json `repository`, Cargo.toml `repository`, or pyproject.toml `[project.urls]`).",
      location: { file: path.posix.basename(manifest.file), line: 1 },
    });
    return { findings, diagnostics };
  }

  // Network verification is opt-in and needs an injected requester.
  if (!opts.network || !opts.head) return { findings, diagnostics };

  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let outcome: RepoHeadOutcome;
  try {
    outcome = await opts.head(manifest.url, timeout);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    diagnostics.push(`provenance: could not verify ${manifest.url} (${message}), skipped`);
    return { findings, diagnostics };
  }

  const unresolved =
    outcome.kind === "unresolved" ||
    (outcome.kind === "status" && (outcome.status === 404 || outcome.status === 410));

  if (unresolved) {
    findings.push({
      ruleId: "provenance-repo-unresolved",
      title: "Declared source repository does not resolve",
      category: "dependency",
      severity: "medium",
      confidence: "medium",
      hndl: false,
      message: `Declared source repository ${manifest.url} does not resolve.`,
      remediation:
        "Fix the manifest's repository URL to point at the real, reachable source repository.",
      location: { file: path.posix.basename(manifest.file), line: 1 },
    });
  } else if (outcome.kind === "error") {
    diagnostics.push(`provenance: could not verify ${manifest.url} (${outcome.message}), skipped`);
  }

  return { findings, diagnostics };
}

/** The two rule ids this module can emit, for SARIF catalog registration. */
export const PROVENANCE_RULES: import("./types.js").RuleMeta[] = [
  {
    id: "provenance-repo-missing",
    title: "Package declares no source repository",
    category: "dependency",
    severity: "info",
    confidence: "medium",
    hndl: false,
    message: "Package declares no source repository; builds cannot be verified against source.",
    description: "The root manifest declares no source repository (opt-in with `qscan --audit`).",
  },
  {
    id: "provenance-repo-unresolved",
    title: "Declared source repository does not resolve",
    category: "dependency",
    severity: "medium",
    confidence: "medium",
    hndl: false,
    message: "The declared source repository does not resolve (404 / DNS failure).",
    description:
      "The manifest's declared source repository 404s or does not resolve (opt-in with `qscan --audit`).",
  },
];
