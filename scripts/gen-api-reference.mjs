#!/usr/bin/env node
/**
 * Generate the public API reference (docs/API.md) and the frozen public-surface
 * snapshot (docs/api-surface.json) from each package's public entry point.
 *
 * This operationalises the VERSIONING.md 1.0 gate ("a documented, frozen public API
 * surface + a generated API reference"): the JSON snapshot is the CONTRACT — a test /
 * CI check (`--check`) fails if a package's real exports drift from it, so any
 * addition or removal of a public symbol is a deliberate, reviewed change, not an
 * accident. Zero dependencies — a lightweight, comment/string-aware line scanner over
 * the entry `index.ts` (following a single `export * from "./mod.js"` re-export hop),
 * NOT a full TypeScript parse; it enumerates the exported NAMES + their kind and
 * one-line doc summary, which is exactly what freezing the surface needs.
 *
 * Usage:
 *   node scripts/gen-api-reference.mjs           # regenerate docs/API.md + snapshot
 *   node scripts/gen-api-reference.mjs --check   # fail (exit 1) if either is stale
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Packages with a public API surface, in the order the reference lists them. */
const PACKAGES = [
  { name: "@quantakrypto/core", entry: "packages/core/src/index.ts" },
  { name: "@quantakrypto/qscan", entry: "packages/qscan/src/index.ts" },
  { name: "@quantakrypto/mcp", entry: "packages/mcp/src/index.ts" },
  { name: "@quantakrypto/sieve", entry: "packages/sieve/src/index.ts" },
  { name: "@quantakrypto/agent", entry: "packages/agent/src/index.ts" },
  { name: "@quantakrypto/qprobe", entry: "packages/qprobe/src/index.ts" },
];

/** Strip block and line comments so a `export`-looking word in a comment is ignored. */
function stripComments(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  let inStr = null;
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\") {
        out += c2 ?? "";
        i += 2;
        continue;
      }
      if (c === inStr) inStr = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      inStr = c;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && c2 === "/") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && c2 === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** The exported name of a `{ orig as alias }` / `orig` clause (alias wins). */
function exportedName(clause) {
  const m = clause.trim().match(/^(?:type\s+)?[\w$]+(?:\s+as\s+([\w$]+))?$/);
  if (!m) return null;
  const asMatch = clause.match(/\bas\s+([\w$]+)/);
  return asMatch ? asMatch[1] : clause.trim().replace(/^type\s+/, "");
}

/** Best-effort one-line doc summary for `name` declared in `src` (from its doc block). */
function docFor(src, name) {
  const pattern =
    String.raw`\/\*\*([\s\S]*?)\*\/\s*export\s+(?:(?:declare|async|abstract)\s+)*` +
    String.raw`(?:const|function|class|interface|type|enum)\s+` +
    name +
    String.raw`\b`;
  const m = src.match(new RegExp(pattern));
  if (!m) return "";
  const first = m[1]
    .split("\n")
    .map((l) => l.replace(/^\s*\*?\s?/, "").trim())
    .find((l) => l.length > 0);
  return (first || "").replace(/\s+/g, " ").slice(0, 140);
}

/**
 * Collect the public export names of `entryRel`, following a single `export * from`
 * hop into a sibling module. Returns a Map(name -> {kind, doc}).
 */
function collectExports(entryRel) {
  const entryAbs = resolve(ROOT, entryRel);
  const raw = readFileSync(entryAbs, "utf8");
  const src = stripComments(raw);
  const out = new Map();

  // `export * from "./mod.js"` — pull in the re-exported module's own named exports.
  for (const m of src.matchAll(/export\s+\*\s+from\s+["']([^"']+)["']/g)) {
    const modPath = resolve(dirname(entryAbs), m[1].replace(/\.js$/, ".ts"));
    let modRaw;
    try {
      modRaw = readFileSync(modPath, "utf8");
    } catch {
      continue;
    }
    const modSrc = stripComments(modRaw);
    for (const d of modSrc.matchAll(
      /export\s+(?:(?:declare|async|abstract)\s+)*(const|function|class|interface|type|enum)\s+([\w$]+)/g,
    )) {
      out.set(d[2], { kind: d[1] === "function" ? "function" : d[1], doc: docFor(modRaw, d[2]) });
    }
  }

  // `export { a, b as c } from "…"` and `export type { … } from "…"` (may span lines).
  for (const m of src.matchAll(/export\s+(type\s+)?\{([\s\S]*?)\}\s*from\s+["'][^"']+["']/g)) {
    const isType = Boolean(m[1]);
    for (const clause of m[2].split(",")) {
      const name = exportedName(clause);
      if (name) out.set(name, { kind: isType ? "type" : "value", doc: "" });
    }
  }

  // Direct declarations: `export const|function|class|interface|type|enum NAME`.
  for (const d of src.matchAll(
    /export\s+(?:(?:declare|async|abstract)\s+)*(const|function|class|interface|type|enum)\s+([\w$]+)/g,
  )) {
    out.set(d[2], { kind: d[1] === "function" ? "function" : d[1], doc: docFor(raw, d[2]) });
  }

  return out;
}

function buildSurface() {
  const surface = {};
  const details = {};
  for (const pkg of PACKAGES) {
    const map = collectExports(pkg.entry);
    surface[pkg.name] = [...map.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    details[pkg.name] = map;
  }
  return { surface, details };
}

function renderMarkdown(details) {
  const lines = [
    "# Public API reference",
    "",
    "> **Generated** by `scripts/gen-api-reference.mjs` — do not edit by hand. Run",
    "> `npm run api:docs` to regenerate; `npm run api:check` fails CI if it drifts.",
    "",
    "Only the symbols listed here are covered by the SemVer contract",
    "([VERSIONING.md](VERSIONING.md)). Anything not re-exported from a package's entry",
    "point is internal and may change in a patch. The machine-readable frozen surface is",
    "[`api-surface.json`](api-surface.json).",
    "",
  ];
  for (const pkg of PACKAGES) {
    const map = details[pkg.name];
    lines.push(`## ${pkg.name}`, "");
    lines.push(`Public entry: \`${pkg.entry}\` — ${map.size} exported symbols.`, "");
    lines.push("| Symbol | Kind | Summary |", "| --- | --- | --- |");
    for (const name of [...map.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      const { kind, doc } = map.get(name);
      lines.push(`| \`${name}\` | ${kind} | ${doc.replace(/\|/g, "\\|")} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

const SNAPSHOT_PATH = resolve(ROOT, "docs/api-surface.json");
const MD_PATH = resolve(ROOT, "docs/API.md");

const { surface, details } = buildSurface();
const snapshotText = JSON.stringify(surface, null, 2) + "\n";
const mdText = renderMarkdown(details);

if (process.argv.includes("--check")) {
  let stale = false;
  for (const [path, fresh] of [
    [SNAPSHOT_PATH, snapshotText],
    [MD_PATH, mdText],
  ]) {
    let current = "";
    try {
      current = readFileSync(path, "utf8");
    } catch {
      /* missing → stale */
    }
    if (current !== fresh) {
      stale = true;
      console.error(`api:check — ${path.replace(ROOT + "/", "")} is stale.`);
    }
  }
  if (stale) {
    console.error("Public API surface drifted. Run `npm run api:docs` and review the diff.");
    process.exit(1);
  }
  console.log("api:check — public API surface matches the frozen snapshot.");
  process.exit(0);
}

writeFileSync(SNAPSHOT_PATH, snapshotText);
writeFileSync(MD_PATH, mdText);
const total = Object.values(surface).reduce((n, a) => n + a.length, 0);
console.log(
  `Wrote docs/API.md + docs/api-surface.json — ${total} public symbols across ${PACKAGES.length} packages.`,
);
