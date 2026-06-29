/**
 * Exercises the REAL worker-spawning path of `scanParallel` — the part that
 * `parallel.test.ts` deliberately leaves out (it only covers the in-process
 * serial fall-back). Now that `workerEntry()` falls back to the `.ts` worker
 * under tsx, this runs against the instrumented src and spawns genuine worker
 * threads, so the dispatch/merge path is both verified and covered.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { scan, scanParallel } from "../src/index.js";

// Short lines so files are NOT treated as minified (a single 40 KB line would
// be), repeated for byte volume so chunkByBytes splits into multiple chunks.
const pad = "// padding line to add byte volume for multi-chunk worker dispatch\n".repeat(800);

// Force the worker path on a small fixture: thresholds at 1 trip
// shouldParallelize, and a small chunkBytes spreads the files across chunks.
const FORCE = {
  concurrency: 4,
  parallelFileThreshold: 1,
  parallelThresholdBytes: 1,
  chunkBytes: 50_000,
};

test("scanParallel spawns workers and matches serial scan() exactly", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "qk-par-worker-"));
  try {
    await mkdir(path.join(dir, "src"), { recursive: true });
    const files: Record<string, string> = {
      "src/a.ts": "const e = crypto.createECDH('prime256v1');\n" + pad,
      "src/b.ts": "jwt.sign(payload, key, { algorithm: 'RS256' });\n" + pad,
      "src/c.ts": "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n" + pad,
      "src/d.ts": "const dh = crypto.createDiffieHellman(2048);\n" + pad,
      "src/e.ts": "crypto.sign('sha256', data, ecdsaKey);\n" + pad,
      "src/f.ts": "const s = crypto.createECDH('secp256k1');\n" + pad,
    };
    for (const [rel, content] of Object.entries(files)) {
      await writeFile(path.join(dir, rel), content);
    }

    const serial = await scan({ root: dir });
    const parallel = await scanParallel({ root: dir, ...FORCE });

    const key = (f: (typeof serial.findings)[number]) =>
      `${f.location.file}:${f.location.line}:${f.ruleId}`;
    assert.deepEqual(
      [...parallel.findings].map(key).sort(),
      [...serial.findings].map(key).sort(),
      "worker-path findings must equal serial findings",
    );
    assert.equal(parallel.filesScanned, serial.filesScanned);
    assert.ok(parallel.findings.length >= 5, "fixture should yield several findings");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanParallel (worker path) tolerates an unreadable file mid-scan", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "qk-par-worker-"));
  const blocked = path.join(dir, "blocked.ts");
  try {
    await writeFile(path.join(dir, "good.ts"), "crypto.createECDH('prime256v1');\n" + pad);
    await writeFile(path.join(dir, "more.ts"), "jwt.sign(p, k, { algorithm: 'RS256' });\n" + pad);
    await writeFile(blocked, "crypto.createDiffieHellman(2048);\n" + pad);
    // Unreadable for a non-root process, so the worker's per-file read catch is
    // exercised. (Run as root it's just read like any other — the assertion holds
    // either way: the scan must complete without throwing.)
    await chmod(blocked, 0o000);

    const result = await scanParallel({ root: dir, ...FORCE });
    assert.ok(result.findings.length >= 2);
    assert.ok(result.filesScanned >= 2);
  } finally {
    await chmod(blocked, 0o644).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  }
});
