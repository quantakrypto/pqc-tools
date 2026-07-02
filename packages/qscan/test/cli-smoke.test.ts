/**
 * Regression guard for the npx / global-install no-op: the CLI MUST run when
 * launched through a SYMLINK. npm's `node_modules/.bin/qscan` is a symlink, and
 * macOS's `/tmp -> /private/tmp` is another — the old `import.meta.url ===
 * pathToFileURL(argv[1])` guard failed both, so `npx @quantakrypto/qscan`
 * printed nothing and exited 0. Runs the BUILT cli.js; skips cleanly if the
 * build is absent (a bare `npm test` without a prior `npm run build`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, symlinkSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const distCli = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "cli.js");
const skip = existsSync(distCli) ? false : "dist not built (run `npm run build` first)";

test("the CLI runs when launched through a symlink (npx / .bin shim)", { skip }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "qk-cli-smoke-"));
  try {
    writeFileSync(
      path.join(dir, "sample.js"),
      "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
    );
    // Stand-in for node_modules/.bin/qscan (a symlink to the real entry).
    const link = path.join(dir, "qscan-shim.js");
    symlinkSync(distCli, link);

    let out = "";
    try {
      out = execFileSync(process.execPath, [link, dir, "--format", "json"], { encoding: "utf8" });
    } catch (err) {
      // qscan exits non-zero when findings are present; the report is on stdout.
      out = String((err as { stdout?: unknown }).stdout ?? "");
    }
    assert.ok(
      out.trim().length > 0,
      "CLI produced NO output when launched via a symlink — the npx no-op regression is back",
    );
    assert.ok(out.includes('"ruleId"'), "expected a JSON report with findings");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
