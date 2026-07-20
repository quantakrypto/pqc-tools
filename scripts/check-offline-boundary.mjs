#!/usr/bin/env node
// Enforce ADR-0005 (docs/adr/0005-byok-agent-two-planes.md): the BYOK/LLM plane
// is fenced off from the deterministic engine. This is the CI gate the ADR calls
// for ("this gate does not exist yet"). It asserts, by source scan:
//
//   1. Agent plane. Only `@quantakrypto/agent` is the networked/keyed LLM plane.
//      `core`, `mcp`, `sieve`, `action`, `qprobe` must NOT import it at all;
//      `qscan` may reach it ONLY via a dynamic `import()` (so an offline run never
//      loads networked code) — a STATIC import is a violation.
//   2. Offline trio. `core`, `mcp`, `sieve` stay strictly offline + key-free: no
//      outbound `fetch(` / WebSocket / XHR / sendBeacon, and no LLM API-key reads.
//      (The `action` talks to the GitHub API and `qprobe` is a live prober, so
//      they are legitimately networked and are exempt from the outbound-call rule;
//      neither may read an LLM key, though.)
//   3. No auto-merge, ever. No `gh pr merge` / `--admin` in any package or workflow.
//
// Zero-dependency: a masked line scan (comments + string literals are blanked so a
// token that only appears inside a regex/string/comment — e.g. core's redaction
// patterns that MATCH `fetch(` — is not mistaken for a real call). Import checks
// run on the raw text because the module specifier is itself a string literal.
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Packages that must be strictly offline and never read an LLM key. */
const OFFLINE_PKGS = new Set(["core", "mcp", "sieve"]);
/** Packages allowed to touch the agent plane (agent IS it; qscan via dynamic import). */
const AGENT_ALLOWED = new Set(["agent", "qscan"]);
/** Packages allowed to read an LLM API key (agent uses it; qscan injects it for BYOK). */
const KEY_ALLOWED = new Set(["agent", "qscan"]);

const RE_AGENT_STATIC = /import\s[\s\S]*?from\s*['"]@quantakrypto\/agent['"]/;
const RE_AGENT_DYNAMIC = /(?:import|require)\s*\(\s*['"]@quantakrypto\/agent['"]\s*\)/;
const RE_OUTBOUND = /\bfetch\s*\(|\bnew\s+WebSocket\b|\bXMLHttpRequest\b|\bnavigator\.sendBeacon\b/;
const RE_LLM_KEY = /process\.env\.(?:QK_LLM_API_KEY|[A-Z0-9_]*_API_KEY)\b/;
// Auto-merge lives in shell strings (`exec("gh pr merge …")`) or REST calls, so it
// is matched on RAW text — masking would blank the very string we want to catch.
const RE_AUTOMERGE = /gh\s+pr\s+merge\b|gh\b[^\n]*--admin\b|\/pulls\/[^/\s]+\/merge\b/;

/** Blank out line + block comments and string/template literals (length preserved). */
export function maskCode(text) {
  let out = text
    // Block comments (incl. multi-line).
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    // Line comments.
    .replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length));
  // String + template literals (same-line, tolerant of escapes).
  out = out.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g, (m) =>
    m.replace(/[^\n]/g, " "),
  );
  return out;
}

/**
 * Scan one source file's text for ADR-0005 violations. `pkg` is the workspace
 * name (e.g. "core"). Returns `{ rule, line, snippet }[]` — empty when clean.
 * Exported so the guard tests can drive it with known-bad fixtures.
 */
export function scanFileForViolations(pkg, relFile, text) {
  const violations = [];
  const masked = maskCode(text);
  const rawLines = text.split("\n");
  const maskedLines = masked.split("\n");
  const flag = (rule, i, lineText) =>
    violations.push({
      rule,
      pkg,
      file: relFile,
      line: i + 1,
      snippet: lineText.trim().slice(0, 120),
    });

  // (1) Agent-plane import + (3) auto-merge — checked on RAW text (both live in
  // string literals: the module specifier and the shell command respectively).
  rawLines.forEach((line, i) => {
    if (RE_AGENT_STATIC.test(line) && !AGENT_ALLOWED.has(pkg)) {
      flag("agent-import", i, line);
    } else if (RE_AGENT_STATIC.test(line) && pkg === "qscan") {
      flag("agent-static-import", i, line); // qscan must use dynamic import()
    }
    if (RE_AGENT_DYNAMIC.test(line) && !AGENT_ALLOWED.has(pkg)) {
      flag("agent-import", i, line);
    }
    if (RE_AUTOMERGE.test(line)) flag("auto-merge", i, line);
  });

  // (2) Outbound calls / LLM-key reads — checked on MASKED text so a token that
  // only appears inside a comment/regex/string is not mistaken for a real call.
  maskedLines.forEach((line, i) => {
    if (OFFLINE_PKGS.has(pkg) && RE_OUTBOUND.test(line)) flag("outbound-network", i, rawLines[i]);
    if (!KEY_ALLOWED.has(pkg) && RE_LLM_KEY.test(line)) flag("llm-key-read", i, rawLines[i]);
  });

  return violations;
}

/** Recursively list `.ts` / `.mjs` / `.js` source files under `dir`. */
function sourceFiles(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) {
      if (name === "node_modules" || name === "dist") continue;
      out.push(...sourceFiles(abs));
    } else if (/\.(ts|mjs|js)$/.test(name) && !/\.test\.ts$/.test(name)) {
      out.push(abs);
    }
  }
  return out;
}

/** Walk every workspace's `src/` and return all violations. */
export function findOfflineBoundaryViolations(root = ROOT) {
  const pkgsDir = join(root, "packages");
  const violations = [];
  if (!existsSync(pkgsDir)) return violations;
  for (const pkg of readdirSync(pkgsDir)) {
    const src = join(pkgsDir, pkg, "src");
    for (const file of sourceFiles(src)) {
      const rel = relative(root, file);
      violations.push(...scanFileForViolations(pkg, rel, readFileSync(file, "utf8")));
    }
  }
  return violations;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const violations = findOfflineBoundaryViolations();
  if (violations.length > 0) {
    console.error("✗ ADR-0005 offline-boundary violated:");
    for (const v of violations) {
      console.error(`  - [${v.rule}] ${v.file}:${v.line}  ${v.snippet}`);
    }
    console.error(
      "\nThe LLM/agent plane must stay fenced off: only @quantakrypto/agent is networked+keyed " +
        "(qscan reaches it via dynamic import), core/mcp/sieve stay offline+key-free, and nothing auto-merges.",
    );
    process.exit(1);
  }
  console.log(
    "✓ ADR-0005 offline boundary holds: the agent plane is fenced off, core/mcp/sieve are offline+key-free, no auto-merge.",
  );
}
