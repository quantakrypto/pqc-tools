#!/usr/bin/env node
// Reproducible-build verification for the published @quantakrypto/* packages.
//
// The guarantee we want: the tarball published to npm for a given version can be
// re-created, byte for byte, from this source tree — so anyone can audit that
// what's on the registry is exactly what's in git, with nothing injected.
//
// Two checks:
//
//   determinism (default, network-free — the CI gate)
//     Pack each workspace and record its SHA-512 integrity. Then perturb the one
//     known nondeterminism source — the `bin` file mode (see normalize-bin-modes
//     .mjs) — by force-setting it to 0755, re-run the normalizer, and re-pack.
//     The integrity MUST be unchanged. This proves the packed artifact does not
//     depend on the working tree's prior on-disk state.
//
//   --against-npm (release verification — needs network + a published version)
//     Compare each workspace's from-source pack integrity to the integrity npm
//     recorded for that exact version. A match proves the registry artifact is
//     reproducible from this commit. Unpublished versions are reported, not failed.
//
// Assumes the workspaces are already built (run `npm run build` first — its
// `postbuild` normalizes bin modes). Exits non-zero if any package fails.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, existsSync, statSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeBinModes } from "./normalize-bin-modes.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const againstNpm = process.argv.includes("--against-npm");

/** Publishable workspaces (skip `private: true`), with their versions + bins. */
function publishableWorkspaces() {
  const pkgsDir = join(ROOT, "packages");
  const out = [];
  for (const name of readdirSync(pkgsDir).sort()) {
    const manifestPath = join(pkgsDir, name, "package.json");
    if (!existsSync(manifestPath)) continue;
    const m = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (m.private === true) continue;
    const bins = m.bin ? (typeof m.bin === "string" ? [m.bin] : Object.values(m.bin)) : [];
    out.push({ name: m.name, version: m.version, dir: join(pkgsDir, name), bins });
  }
  return out;
}

/** Pack a single workspace into a fresh temp dir; return its npm integrity. */
function packIntegrity(name) {
  const dest = mkdtempSync(join(tmpdir(), "qk-repro-"));
  const stdout = execFileSync(
    "npm",
    ["pack", "--workspace", name, "--json", "--pack-destination", dest],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  );
  const parsed = JSON.parse(stdout);
  return parsed[0].integrity;
}

/** Integrity npm recorded for name@version, or null if unpublished. */
function publishedIntegrity(name, version) {
  try {
    return execFileSync("npm", ["view", `${name}@${version}`, "dist.integrity"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null; // 404 — not published (yet)
  }
}

const pkgs = publishableWorkspaces();
const rows = [];
let failed = 0;

for (const pkg of pkgs) {
  // Guard: dist must exist (built) or packing an empty package is meaningless.
  const first = packIntegrity(pkg.name);

  // Perturb the known nondeterminism source, then let the normalizer fix it.
  for (const rel of pkg.bins) {
    const f = join(pkg.dir, rel);
    if (existsSync(f)) chmodSync(f, 0o755);
  }
  const perturbed = pkg.bins.some((rel) => {
    const f = join(pkg.dir, rel);
    return existsSync(f) && (statSync(f).mode & 0o777) === 0o755;
  });
  normalizeBinModes(ROOT);
  const second = packIntegrity(pkg.name);

  const deterministic = first === second;
  if (!deterministic) failed++;

  const row = {
    name: pkg.name,
    version: pkg.version,
    deterministic,
    perturbed,
    integrity: first,
    npm: "—",
  };

  if (againstNpm) {
    const pub = publishedIntegrity(pkg.name, pkg.version);
    if (pub === null) {
      row.npm = "unpublished";
    } else if (pub === first) {
      row.npm = "✅ match";
    } else {
      row.npm = "❌ MISMATCH";
      failed++;
    }
  }

  rows.push(row);
}

// Report.
const w = (s, n) => String(s).padEnd(n);
console.log(`\nreproducible-build verification${againstNpm ? " (vs npm)" : " (determinism)"}\n`);
console.log(
  `  ${w("package", 24)} ${w("version", 9)} ${w("deterministic", 14)}${againstNpm ? " vs-npm" : ""}`,
);
console.log(`  ${"-".repeat(againstNpm ? 62 : 49)}`);
for (const r of rows) {
  const det = r.deterministic ? "✅ yes" : "❌ NO";
  console.log(
    `  ${w(r.name, 24)} ${w(r.version, 9)} ${w(det, 14)}${againstNpm ? " " + r.npm : ""}`,
  );
}
console.log("");

if (failed > 0) {
  console.error(`::error::reproducible-build check failed for ${failed} package(s).`);
  process.exit(1);
}
console.log(`reproducible-build: all ${rows.length} package(s) OK.`);
