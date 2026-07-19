#!/usr/bin/env node
// Pin the file mode of every workspace `bin` target to 0644 so the packed npm
// tarball is byte-for-byte reproducible regardless of the working tree's prior
// on-disk state.
//
// Why this exists
// ---------------
// `tsc -b` overwrites a file's *contents* but preserves its existing *mode*. A
// `dist/cli.js` that once picked up an exec bit (0755) during local dev keeps
// that bit on every rebuild, whereas a fresh CI checkout creates the same file
// at 0644. `npm pack` records the on-disk mode verbatim in the tar header, so
// the identical source packs to two different tarballs (different SHA-512
// integrity) — the classic reproducible-build trap. Pinning the mode removes
// that variance.
//
// Why 0644 (not 0755): npm re-creates the exec bit on the installed `bin` shim
// from the `bin` field at install time, so the mode inside the tarball is
// irrelevant to whether the CLI runs — 0644 is exactly how the 0.4.x releases
// already ship. We pin explicitly (not "whatever a fresh tsc emits") so the
// result is umask-independent too.
//
// Run automatically as the root `postbuild`; also invoked by repro-build.mjs.
import { readdirSync, readFileSync, existsSync, statSync, chmodSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const MODE = 0o644;

/**
 * Normalize every workspace bin target under `<root>/packages/*` to MODE.
 * Returns { checked, changed, entries } — entries lists what was touched.
 */
export function normalizeBinModes(root) {
  const pkgsDir = join(root, "packages");
  const entries = [];
  let checked = 0;
  let changed = 0;
  if (!existsSync(pkgsDir)) return { checked, changed, entries };

  for (const name of readdirSync(pkgsDir).sort()) {
    const manifestPath = join(pkgsDir, name, "package.json");
    if (!existsSync(manifestPath)) continue;
    const { bin } = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (!bin) continue;
    const targets = typeof bin === "string" ? [bin] : Object.values(bin);
    for (const rel of targets) {
      const file = join(pkgsDir, name, rel);
      if (!existsSync(file)) continue; // not built yet — nothing to pin
      checked++;
      const before = statSync(file).mode & 0o777;
      if (before !== MODE) {
        chmodSync(file, MODE);
        changed++;
        entries.push({ pkg: name, rel, before, after: MODE });
      }
    }
  }
  return { checked, changed, entries };
}

// Run as a script (postbuild): normalize the repo this file lives in.
if (import.meta.url === `file://${process.argv[1]}`) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const { checked, changed, entries } = normalizeBinModes(root);
  for (const e of entries) {
    console.log(
      `  normalized ${e.pkg}/${e.rel}  ${e.before.toString(8)} -> ${e.after.toString(8)}`,
    );
  }
  console.log(`normalize-bin-modes: ${checked} bin file(s) checked, ${changed} normalized`);
}
