// Enforce ADR-0001 (docs/adr/0001-zero-runtime-dependencies.md): no workspace
// package may declare a third-party RUNTIME dependency — only internal
// `@quantakrypto/*` packages are permitted — and none may carry an install
// lifecycle script. This keeps the "runtime deps: 0" invariant from eroding
// silently by review-only enforcement.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const PKGS = "packages";
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "prepublishOnly"];
const violations = [];

for (const name of readdirSync(PKGS)) {
  const manifest = join(PKGS, name, "package.json");
  if (!existsSync(manifest)) continue;
  const pkg = JSON.parse(readFileSync(manifest, "utf8"));
  for (const dep of Object.keys(pkg.dependencies ?? {})) {
    if (!dep.startsWith("@quantakrypto/")) {
      violations.push(
        `${manifest}: runtime dependency "${dep}" — only @quantakrypto/* is allowed (ADR-0001).`,
      );
    }
  }
  for (const s of LIFECYCLE) {
    if (pkg.scripts?.[s]) {
      violations.push(
        `${manifest}: install lifecycle script "${s}" is not allowed (supply-chain surface).`,
      );
    }
  }
}

if (violations.length) {
  console.error("✗ zero-runtime-dependency invariant violated (ADR-0001):");
  for (const v of violations) console.error("  - " + v);
  process.exit(1);
}
console.log(
  "✓ zero-runtime-dependency invariant holds: every workspace dependency is @quantakrypto/*, no install lifecycle scripts.",
);
