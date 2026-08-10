#!/usr/bin/env node
/**
 * The example workflows are copy-paste product, and nothing was checking them.
 *
 * `packages/action/examples/*.yml` is what the READMEs tell people to drop into
 * `.github/workflows/`. Unlike our own workflows, GitHub never parses these, so a
 * broken one ships silently. One did: an edit merged a step name into the key
 * below it, leaving `continue-on-error: true to code scanning`. That is *valid
 * YAML* — the value is just a string — so neither prettier nor any YAML parser
 * would have caught it. Only a workflow-aware check does.
 *
 * This is deliberately narrow rather than a workflow schema:
 *
 *   1. keys whose value must be a boolean actually hold one;
 *   2. `uses:` is a single well-formed ref;
 *   3. a `uses:` of OUR action pins a bare moving major (`@vN`), never a semver
 *      tag or a branch. An example pinning `@v1.2.3` or `@main` would freeze or
 *      float every repository that copied it.
 *
 * Hand-rolled, no YAML dependency: this repo ships zero runtime dependencies
 * (ADR-0001) and the same reasoning applies to its supply-chain gates.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const EXAMPLE_DIR = "packages/action/examples";

/** Workflow keys GitHub requires to be a boolean. */
const BOOLEAN_KEYS = new Set([
  "continue-on-error",
  "fail-fast",
  "cancel-in-progress",
  "submodules",
]);

/** Our own action, in either of its two `uses:` coordinates. */
const OWN_ACTION = /^quantakrypto\/pqc-tools(\/packages\/action)?@(.+)$/;

/** A value GitHub will evaluate rather than read literally. */
const isExpression = (v) => v.startsWith("${{");

/**
 * Problems in one workflow file. Empty array means it is fine.
 *
 * Line-oriented on purpose. A step's keys are `key: value` at a fixed indent, so
 * the mangling this exists to catch (prose spilling into the next key) shows up
 * as a scalar that does not fit its key, which is exactly what we test.
 */
export function checkWorkflow(text) {
  const problems = [];
  const lines = text.split("\n");

  lines.forEach((line, i) => {
    const n = i + 1;
    if (/^\s*#/.test(line)) return;

    const m = line.match(/^\s*-?\s*([a-z][a-z0-9-]*):\s*(.*?)\s*(?:#.*)?$/i);
    if (!m) return;
    const [, key, rawValue] = m;
    const value = (rawValue ?? "").replace(/^["']|["']$/g, "");
    if (!value) return;

    if (BOOLEAN_KEYS.has(key) && !isExpression(value) && value !== "true" && value !== "false") {
      problems.push(`${n}: ${key} must be true or false, got "${value}"`);
      return;
    }

    if (key !== "uses") return;

    if (/\s/.test(value)) {
      problems.push(`${n}: uses must be a single ref, got "${value}"`);
      return;
    }
    if (!value.includes("@") && !value.startsWith("./")) {
      problems.push(`${n}: uses is unpinned: "${value}"`);
      return;
    }
    const own = value.match(OWN_ACTION);
    if (own && !/^v\d+$/.test(own[2])) {
      problems.push(
        `${n}: our action must be pinned to a moving major (@v1), got "@${own[2]}". ` +
          `A copied example lives for years; a semver tag or branch freezes or floats it.`,
      );
    }
  });

  return problems;
}

function main() {
  const dir = resolve(ROOT, EXAMPLE_DIR);
  const files = readdirSync(dir).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));

  // A glob that matched nothing would make this gate pass forever.
  if (files.length === 0) {
    console.error(`✗ no example workflows found in ${EXAMPLE_DIR} — the check itself is broken.`);
    process.exit(1);
  }

  let failed = false;
  for (const file of files) {
    const problems = checkWorkflow(readFileSync(join(dir, file), "utf8"));
    if (problems.length === 0) continue;
    failed = true;
    console.error(`✗ ${EXAMPLE_DIR}/${file}`);
    for (const p of problems) console.error(`  - ${p}`);
  }
  if (failed) {
    console.error("\nThese files are copy-paste product. A broken one ships to every reader.");
    process.exit(1);
  }
  console.log(`✓ ${files.length} example workflow(s) well-formed and pinned to a moving major.`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
