#!/usr/bin/env node
// Enforce that every third-party GitHub Action is pinned to a full commit SHA,
// not a mutable tag (`@v4`) or branch (`@main`). A tag can be moved to point at
// new code after review, so an unpinned `uses:` is a live supply-chain hole —
// this is the OpenSSF Scorecard "Pinned-Dependencies" criterion, enforced here
// as a hard gate so a new workflow can't regress it silently.
//
// Zero-dependency: a line scan of the workflow YAML (a real YAML parser would
// pull in a dependency, which ADR-0001 forbids). Workflow `uses:` lines are
// simple enough that a regex is sufficient and honest.
//
// Exempt: local actions (`./…`, `../…`) and Docker refs (`docker://…`).
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW_DIR = join(ROOT, ".github", "workflows");
const SHA_RE = /^[0-9a-f]{40}$/;
const USES_RE = /^\s*-?\s*uses:\s*(['"]?)([^'"#\s]+)\1/;

/** Collect { file, line, uses } for every unpinned third-party action. */
export function findUnpinnedActions(workflowDir) {
  const violations = [];
  if (!existsSync(workflowDir)) return violations;
  const files = readdirSync(workflowDir)
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
    .sort();

  for (const file of files) {
    const text = readFileSync(join(workflowDir, file), "utf8");
    text.split("\n").forEach((rawLine, i) => {
      const m = USES_RE.exec(rawLine);
      if (!m) return;
      const ref = m[2];
      // Local composite/action references and Docker images are not tag-pinnable
      // GitHub Actions — skip them.
      if (ref.startsWith("./") || ref.startsWith("../") || ref.startsWith("docker://")) return;
      const at = ref.lastIndexOf("@");
      const pin = at === -1 ? "" : ref.slice(at + 1);
      if (!SHA_RE.test(pin)) {
        violations.push({ file, line: i + 1, uses: ref });
      }
    });
  }
  return violations;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const violations = findUnpinnedActions(WORKFLOW_DIR);
  if (violations.length > 0) {
    for (const v of violations) {
      console.error(
        `::error file=.github/workflows/${v.file},line=${v.line}::action not pinned to a SHA: ${v.uses}`,
      );
    }
    console.error(
      `\n${violations.length} unpinned action(s). Pin each to a full 40-char commit SHA ` +
        `(keep the human tag as a trailing comment, e.g. \`uses: owner/repo@<sha> # v1.2.3\`).`,
    );
    process.exit(1);
  }
  console.log("check-action-pins: all GitHub Actions are pinned to a commit SHA.");
}
