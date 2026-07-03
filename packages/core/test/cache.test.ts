/**
 * Tests for the optional content-hash scan cache: round-trip + invalidation of
 * the cache module, and end-to-end behaviour through `scan({ cacheFile })` —
 * unchanged files reuse prior findings, a content change re-scans, and a ruleset
 * change discards the whole cache.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scan, detectors } from "../src/index.js";
import { loadCache, saveCache, hashContent, rulesetFingerprint } from "../src/cache.js";
import type { CacheEntry } from "../src/cache.js";
import type { Finding } from "../src/index.js";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "quantakrypto-cache-"));
}

test("hashContent + rulesetFingerprint are deterministic and change with inputs", () => {
  assert.equal(hashContent("abc"), hashContent("abc"));
  assert.notEqual(hashContent("abc"), hashContent("abd"));
  const base = rulesetFingerprint(detectors, undefined);
  assert.equal(base, rulesetFingerprint(detectors, []));
  assert.notEqual(base, rulesetFingerprint(detectors, ["node-crypto-ecdh"]));
});

test("saveCache/loadCache round-trip; a ruleset mismatch or corrupt file loads empty", async () => {
  const dir = await tmp();
  try {
    const file = join(dir, ".cache.json");
    const entries = new Map<string, CacheEntry>([["a.ts", { hash: "h", findings: [] }]]);
    await saveCache(file, "ruleset-A", entries);

    assert.equal((await loadCache(file, "ruleset-A")).size, 1);
    assert.equal((await loadCache(file, "ruleset-B")).size, 0, "wrong ruleset → empty");

    await writeFile(file, "{ not json", "utf8");
    assert.equal((await loadCache(file, "ruleset-A")).size, 0, "corrupt → empty");
    assert.equal((await loadCache(join(dir, "nope.json"), "ruleset-A")).size, 0, "missing → empty");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan with a cacheFile produces identical findings to no cache, and writes the cache", async () => {
  const dir = await tmp();
  try {
    await writeFile(join(dir, "a.ts"), "const e = crypto.createECDH('p256');\n");
    const cacheFile = join(dir, ".cache.json");

    const plain = await scan({ root: dir });
    const cached = await scan({ root: dir, cacheFile });
    assert.deepEqual(
      cached.findings.map((f) => f.ruleId),
      plain.findings.map((f) => f.ruleId),
    );
    // The cache file now exists and holds the file's entry.
    const onDisk = JSON.parse(await readFile(cacheFile, "utf8")) as {
      entries: Record<string, unknown>;
    };
    assert.ok(onDisk.entries["a.ts"], "a.ts is cached");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an unchanged file REUSES the cached findings (proven with a sentinel)", async () => {
  const dir = await tmp();
  try {
    const src = join(dir, "a.ts");
    await writeFile(src, "const e = crypto.createECDH('p256');\n");
    const cacheFile = join(dir, ".cache.json");

    // Populate the cache.
    await scan({ root: dir, cacheFile });

    // Tamper the cache: keep the SAME hash but swap the findings for a sentinel.
    const doc = JSON.parse(await readFile(cacheFile, "utf8")) as {
      version: number;
      ruleset: string;
      entries: Record<string, CacheEntry>;
    };
    const sentinel: Finding = {
      ruleId: "SENTINEL-CACHED",
      title: "s",
      category: "signature",
      severity: "low",
      confidence: "low",
      hndl: false,
      message: "from cache",
      location: { file: "a.ts", line: 1 },
    };
    doc.entries["a.ts"].findings = [sentinel];
    await writeFile(cacheFile, JSON.stringify(doc), "utf8");

    // File is unchanged → cache hit → the sentinel comes back (not a re-scan).
    const reused = await scan({ root: dir, cacheFile });
    assert.ok(
      reused.findings.some((f) => f.ruleId === "SENTINEL-CACHED"),
      "unchanged file served cached findings",
    );
    assert.ok(!reused.findings.some((f) => f.ruleId === "node-crypto-ecdh"), "did not re-detect");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a content change re-scans; a ruleset change discards the cache", async () => {
  const dir = await tmp();
  try {
    const src = join(dir, "a.ts");
    await writeFile(src, "const e = crypto.createECDH('p256');\n");
    const cacheFile = join(dir, ".cache.json");

    await scan({ root: dir, cacheFile });
    // Change the content → the old hash no longer matches → re-scan picks up RSA.
    await writeFile(src, "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    const changed = await scan({ root: dir, cacheFile });
    assert.ok(changed.findings.some((f) => f.ruleId === "node-crypto-keygen"));
    assert.ok(!changed.findings.some((f) => f.ruleId === "node-crypto-ecdh"), "stale ecdh gone");

    // A disabledRules change alters the ruleset → the cache is rebuilt, honouring it.
    const disabled = await scan({ root: dir, cacheFile, disabledRules: ["node-crypto-keygen"] });
    assert.ok(!disabled.findings.some((f) => f.ruleId === "node-crypto-keygen"), "rule disabled");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an incremental scan (files list) preserves cache entries for unvisited files (audit: arch #4)", async () => {
  const dir = await tmp();
  try {
    await writeFile(join(dir, "a.ts"), "const e = crypto.createECDH('p256');\n");
    await writeFile(
      join(dir, "b.ts"),
      "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
    );
    const cacheFile = join(dir, ".cache.json");
    await scan({ root: dir, cacheFile });
    let doc = JSON.parse(await readFile(cacheFile, "utf8")) as { entries: Record<string, unknown> };
    assert.ok(doc.entries["a.ts"] && doc.entries["b.ts"], "both cached after full scan");
    // Incremental run over only a.ts must NOT evict b.ts.
    await scan({ root: dir, cacheFile, files: ["a.ts"] });
    doc = JSON.parse(await readFile(cacheFile, "utf8")) as { entries: Record<string, unknown> };
    assert.ok(doc.entries["a.ts"], "a.ts still cached");
    assert.ok(doc.entries["b.ts"], "b.ts entry preserved across the incremental run");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
