#!/usr/bin/env node
/**
 * The action ships two metadata files and nothing was checking they agree.
 *
 *   action.yml                 repository root, so the Marketplace can list it
 *   packages/action/action.yml the canonical path, `uses: …/packages/action@v1`
 *
 * They must declare the SAME inputs and outputs, because both entrypoints run
 * the same bundle. A drifting pair is silent and nasty: an input added to one
 * file works via one `uses:` coordinate and is ignored via the other, so the
 * check simply does not do what the workflow says.
 *
 * Deliberately compared on the input/output NAMES and defaults rather than the
 * whole file: `name`, `description` and `runs.main` differ by design.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const ROOT_ACTION = "action.yml";
export const PACKAGE_ACTION = "packages/action/action.yml";

/**
 * Pull the input/output names and their defaults out of an action.yml.
 *
 * A hand-rolled reader rather than a YAML dependency: this repo ships zero
 * runtime dependencies (ADR-0001) and adding a parser to a supply-chain gate
 * would be its own irony. Only the shape action.yml actually uses is handled —
 * two-space top-level keys, four-space entry keys.
 */
export function parseActionMeta(text) {
  const inputs = new Map();
  const outputs = new Set();
  let section = null;
  let current = null;

  for (const line of text.split("\n")) {
    if (/^[a-z]/i.test(line)) {
      section = line.startsWith("inputs:")
        ? "inputs"
        : line.startsWith("outputs:")
          ? "outputs"
          : null;
      current = null;
      continue;
    }
    if (!section) continue;

    const entry = line.match(/^ {2}([a-z0-9-]+):\s*$/i);
    if (entry?.[1]) {
      current = entry[1];
      if (section === "inputs") inputs.set(current, { default: null });
      else outputs.add(current);
      continue;
    }
    if (section === "inputs" && current) {
      const def = line.match(/^ {4}default:\s*(.*)$/);
      if (def) {
        const raw = (def[1] ?? "").trim();
        inputs.get(current).default = raw.replace(/^["']|["']$/g, "");
      }
    }
  }
  return { inputs, outputs };
}

/** Differences that matter. Empty means the two files agree. */
export function diffActionMeta(rootMeta, pkgMeta) {
  const problems = [];
  const rootNames = [...rootMeta.inputs.keys()];
  const pkgNames = [...pkgMeta.inputs.keys()];

  for (const name of pkgNames) {
    if (!rootMeta.inputs.has(name)) problems.push(`input "${name}" is missing from ${ROOT_ACTION}`);
  }
  for (const name of rootNames) {
    if (!pkgMeta.inputs.has(name))
      problems.push(`input "${name}" is missing from ${PACKAGE_ACTION}`);
  }
  for (const name of pkgNames) {
    if (!rootMeta.inputs.has(name)) continue;
    const a = rootMeta.inputs.get(name).default;
    const b = pkgMeta.inputs.get(name).default;
    if (a !== b) {
      problems.push(
        `input "${name}" default differs: ${ROOT_ACTION}=${a} vs ${PACKAGE_ACTION}=${b}`,
      );
    }
  }
  for (const name of pkgMeta.outputs) {
    if (!rootMeta.outputs.has(name))
      problems.push(`output "${name}" is missing from ${ROOT_ACTION}`);
  }
  for (const name of rootMeta.outputs) {
    if (!pkgMeta.outputs.has(name))
      problems.push(`output "${name}" is missing from ${PACKAGE_ACTION}`);
  }
  return problems;
}

function main() {
  const rootMeta = parseActionMeta(readFileSync(resolve(ROOT, ROOT_ACTION), "utf8"));
  const pkgMeta = parseActionMeta(readFileSync(resolve(ROOT, PACKAGE_ACTION), "utf8"));

  // A parser that silently reads nothing would make this gate always pass.
  if (pkgMeta.inputs.size === 0 || pkgMeta.outputs.size === 0) {
    console.error(`✗ read no inputs/outputs from ${PACKAGE_ACTION} — the check itself is broken.`);
    process.exit(1);
  }

  const problems = diffActionMeta(rootMeta, pkgMeta);
  if (problems.length > 0) {
    console.error(`✗ ${ROOT_ACTION} and ${PACKAGE_ACTION} have drifted:`);
    for (const p of problems) console.error(`  - ${p}`);
    console.error("\nBoth entrypoints run the same bundle; their inputs and outputs must match.");
    process.exit(1);
  }
  console.log(
    `✓ action metadata in sync: ${pkgMeta.inputs.size} input(s), ${pkgMeta.outputs.size} output(s).`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
