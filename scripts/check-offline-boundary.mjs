#!/usr/bin/env node
// Enforce ADR-0005 (docs/adr/0005-byok-agent-two-planes.md): the BYOK/LLM plane
// is fenced off from the deterministic engine. This is the CI gate the ADR calls
// for. It asserts, by source scan:
//
//   1. Agent plane. Only `@quantakrypto/agent` is the networked/keyed LLM plane.
//      `core`, `mcp`, `sieve`, `action`, `qprobe` must NOT reference it in ANY
//      import/export/require form; `qscan` may reach it ONLY via a dynamic
//      `import()` (so an offline run never loads networked code) — a static /
//      side-effect / re-export import is a violation.
//   2. Offline trio. `core`, `mcp`, `sieve` stay strictly offline + key-free: no
//      outbound `fetch(`/WebSocket/XHR/sendBeacon, no import of an outbound Node
//      network module (node:https/http2/dgram, undici), and no LLM API-key read
//      (dot, bracket, or destructured `process.env`). `action` (GitHub API) and
//      `qprobe` (live prober) are legitimately networked and exempt from the
//      outbound rule; neither may read an LLM key.
//   3. No auto-merge, ever. No `gh pr merge` / `gh … --admin` in any package or
//      workflow.
//
// Zero-dependency. Robustness (the previous line-by-line + sequential-regex
// version was bypassable by Prettier-formatted multi-line imports and by tokens
// after a `//`-containing URL string): a single-pass lexer classifies every
// character as code / string / comment (recursing into template `${…}` as code),
// and detection runs over the WHOLE file with index→line mapping. Import and
// key-read checks run on raw text (their evidence lives in a string literal or a
// property name); outbound-call checks run on code-only text (so a `fetch(` token
// inside a regex/string/comment is not a real call); auto-merge runs on
// comment-stripped text (so `exec("gh pr merge")` is caught but a `// gh pr merge`
// note is not).
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

// Agent-plane references (matched on RAW text — the specifier is a string literal).
const RE_AGENT_STATIC =
  /(?:^|[\n;{}])\s*(?:import|export)\s[^;]*?['"]@quantakrypto\/agent['"]|(?:^|[\n;{}])\s*import\s*['"]@quantakrypto\/agent['"]/g;
const RE_AGENT_DYNAMIC = /(?:import|require)\s*\(\s*['"]@quantakrypto\/agent['"]\s*\)/g;
// Outbound network CALLS (matched on CODE-only text).
const RE_OUTBOUND_CALL =
  /\bfetch\s*\(|\bnew\s+WebSocket\b|\bXMLHttpRequest\b|\bnavigator\.sendBeacon\b/g;
// Outbound Node network MODULE imports (matched on RAW text). node:http / node:net
// are allowed — the MCP serves a local HTTP endpoint; these have no server use.
const RE_OUTBOUND_MODULE =
  /(?:from|import|require)\s*\(?\s*['"](?:node:)?(?:https|http2|dgram)['"]|['"]undici['"]/g;
// LLM API-key reads (matched on RAW text — the bracket/destructure forms hide the
// key name inside a string that masking would erase).
const RE_KEY_DOT = /process\.env\.(?:QK_LLM_API_KEY|[A-Z0-9_]*_API_KEY)\b/g;
const RE_KEY_BRACKET = /process\.env\[\s*['"](?:QK_LLM_API_KEY|[A-Z0-9_]*_API_KEY)['"]\s*\]/g;
const RE_KEY_DESTRUCTURE =
  /\{[^}]*\b(?:QK_LLM_API_KEY|[A-Z0-9_]*_API_KEY)\b[^}]*\}\s*=\s*process\.env\b/g;
// Auto-merge (matched on COMMENT-stripped text — strings kept, comments removed).
const RE_AUTOMERGE = /\bgh\b[^\n]*\bpr\s+merge\b|\bgh\b[^\n]*--admin\b|\/pulls\/[^/\s]+\/merge\b/g;

/**
 * Classify every character of `text` as "code" | "string" | "comment" with a
 * single left-to-right pass. Template literals are strings; their `${…}`
 * interpolations are code (recursively). Handles escapes and nested braces.
 */
function classify(text) {
  const n = text.length;
  const cls = new Array(n).fill("code");
  const tmpl = []; // stack of { depth } — depth 0 means "in the template string part"
  let i = 0;
  while (i < n) {
    const inTemplateString = tmpl.length > 0 && tmpl[tmpl.length - 1].depth === 0;
    const c = text[i];
    const d = text[i + 1];
    if (inTemplateString) {
      if (c === "\\") {
        cls[i] = "string";
        if (i + 1 < n) cls[i + 1] = "string";
        i += 2;
        continue;
      }
      if (c === "`") {
        cls[i] = "string";
        tmpl.pop();
        i++;
        continue;
      }
      if (c === "$" && d === "{") {
        cls[i] = "code";
        cls[i + 1] = "code";
        tmpl[tmpl.length - 1].depth = 1;
        i += 2;
        continue;
      }
      cls[i] = "string";
      i++;
      continue;
    }
    // Line comment.
    if (c === "/" && d === "/") {
      let j = i;
      while (j < n && text[j] !== "\n") cls[j++] = "comment";
      i = j;
      continue;
    }
    // Block comment.
    if (c === "/" && d === "*") {
      cls[i] = "comment";
      cls[i + 1] = "comment";
      let j = i + 2;
      while (j < n && !(text[j] === "*" && text[j + 1] === "/")) cls[j++] = "comment";
      if (j < n) {
        cls[j] = "comment";
        cls[j + 1] = "comment";
        j += 2;
      }
      i = j;
      continue;
    }
    // Single/double-quoted string.
    if (c === "'" || c === '"') {
      const q = c;
      cls[i] = "string";
      let j = i + 1;
      while (j < n) {
        if (text[j] === "\\") {
          cls[j] = "string";
          if (j + 1 < n) cls[j + 1] = "string";
          j += 2;
          continue;
        }
        if (text[j] === q || text[j] === "\n") {
          if (text[j] === q) cls[j++] = "string";
          break;
        }
        cls[j++] = "string";
      }
      i = j;
      continue;
    }
    // Template literal start.
    if (c === "`") {
      cls[i] = "string";
      tmpl.push({ depth: 0 });
      i++;
      continue;
    }
    // Brace tracking while inside an interpolation.
    if (tmpl.length > 0) {
      const top = tmpl[tmpl.length - 1];
      if (c === "{") top.depth++;
      else if (c === "}") top.depth = Math.max(0, top.depth - 1);
    }
    cls[i] = "code";
    i++;
  }
  return cls;
}

/** Build a variant of `text` keeping only the requested classes (others → spaces). */
function project(text, cls, keep) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    out += keep.has(cls[i]) || text[i] === "\n" ? text[i] : " ";
  }
  return out;
}

/** Comments + string literals blanked (code kept). Exported for the guard tests. */
export function maskCode(text) {
  return project(text, classify(text), new Set(["code"]));
}

/** 1-indexed line number of a character offset. */
function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === "\n") line++;
  return line;
}

/**
 * Scan one source file's text for ADR-0005 violations. `pkg` is the workspace
 * name (e.g. "core"). Returns `{ rule, line, snippet }[]` — empty when clean.
 * Exported so the guard tests can drive it with known-bad fixtures.
 */
export function scanFileForViolations(pkg, relFile, text) {
  const cls = classify(text);
  const codeOnly = project(text, cls, new Set(["code"]));
  const noComments = project(text, cls, new Set(["code", "string"]));
  const lines = text.split("\n");
  const violations = [];
  const flag = (rule, index) => {
    const line = lineOf(text, index);
    violations.push({
      rule,
      pkg,
      file: relFile,
      line,
      snippet: (lines[line - 1] ?? "").trim().slice(0, 120),
    });
  };
  const scan = (re, src, rule) => {
    re.lastIndex = 0;
    for (let m = re.exec(src); m; m = re.exec(src)) flag(rule, m.index);
  };

  // (1) Agent plane — RAW whole-file text.
  if (!AGENT_ALLOWED.has(pkg)) {
    scan(RE_AGENT_STATIC, text, "agent-import");
    scan(RE_AGENT_DYNAMIC, text, "agent-import");
  } else if (pkg === "qscan") {
    scan(RE_AGENT_STATIC, text, "agent-static-import");
  }

  // (2) Offline trio — outbound calls (code-only), outbound modules + key reads (raw).
  if (OFFLINE_PKGS.has(pkg)) {
    scan(RE_OUTBOUND_CALL, codeOnly, "outbound-network");
    scan(RE_OUTBOUND_MODULE, text, "outbound-network");
  }
  if (!KEY_ALLOWED.has(pkg)) {
    scan(RE_KEY_DOT, text, "llm-key-read");
    scan(RE_KEY_BRACKET, text, "llm-key-read");
    scan(RE_KEY_DESTRUCTURE, text, "llm-key-read");
  }

  // (3) Auto-merge — comment-stripped text (strings kept).
  scan(RE_AUTOMERGE, noComments, "auto-merge");

  return violations;
}

/** Scan a workflow file for the auto-merge rule (ADR-0005 covers CI too). */
export function scanWorkflowForAutoMerge(relFile, text) {
  const cls = classify(text);
  const noComments = project(text, cls, new Set(["code", "string"]));
  const lines = text.split("\n");
  const violations = [];
  RE_AUTOMERGE.lastIndex = 0;
  for (let m = RE_AUTOMERGE.exec(noComments); m; m = RE_AUTOMERGE.exec(noComments)) {
    const line = lineOf(text, m.index);
    violations.push({
      rule: "auto-merge",
      pkg: "workflow",
      file: relFile,
      line,
      snippet: (lines[line - 1] ?? "").trim().slice(0, 120),
    });
  }
  return violations;
}

/** Recursively list `.ts` / `.mjs` / `.js` source files under `dir` (excluding tests). */
function sourceFiles(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) {
      if (name === "node_modules" || name === "dist") continue;
      out.push(...sourceFiles(abs));
    } else if (/\.(ts|mjs|js)$/.test(name) && !/\.(test|spec)\.(ts|mjs|js)$/.test(name)) {
      out.push(abs);
    }
  }
  return out;
}

/** Walk every workspace's `src/` plus the CI workflows and return all violations. */
export function findOfflineBoundaryViolations(root = ROOT) {
  const violations = [];
  const pkgsDir = join(root, "packages");
  if (existsSync(pkgsDir)) {
    for (const pkg of readdirSync(pkgsDir)) {
      const src = join(pkgsDir, pkg, "src");
      for (const file of sourceFiles(src)) {
        const rel = relative(root, file);
        violations.push(...scanFileForViolations(pkg, rel, readFileSync(file, "utf8")));
      }
    }
  }
  const wfDir = join(root, ".github", "workflows");
  if (existsSync(wfDir)) {
    for (const name of readdirSync(wfDir)) {
      if (!/\.ya?ml$/.test(name)) continue;
      const rel = relative(root, join(wfDir, name));
      violations.push(...scanWorkflowForAutoMerge(rel, readFileSync(join(wfDir, name), "utf8")));
    }
  }
  return violations;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const violations = findOfflineBoundaryViolations();
  if (violations.length > 0) {
    console.error("✗ ADR-0005 offline-boundary violated:");
    for (const v of violations) console.error(`  - [${v.rule}] ${v.file}:${v.line}  ${v.snippet}`);
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
