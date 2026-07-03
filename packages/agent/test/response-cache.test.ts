import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { cacheKey, loadResponseCache, saveResponseCache } from "../src/response-cache.js";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "quantakrypto-agent-cache-"));
}

test("cacheKey changes with any component", () => {
  const base = { promptVersion: "1", model: "m", contextLevel: "snippet", fingerprint: "fp" };
  assert.equal(cacheKey(base), cacheKey({ ...base }));
  assert.notEqual(cacheKey(base), cacheKey({ ...base, model: "m2" }));
  assert.notEqual(cacheKey(base), cacheKey({ ...base, fingerprint: "fp2" }));
});

test("round-trips entries; a corrupt file loads empty", async () => {
  const dir = await tmp();
  try {
    const file = join(dir, ".cache.json");
    const map = new Map<string, unknown>([["k", { exposureScore: 42 }]]);
    await saveResponseCache(file, map);
    const loaded = await loadResponseCache(file);
    assert.deepEqual(loaded.get("k"), { exposureScore: 42 });

    await writeFile(file, "{ not json", "utf8");
    assert.equal((await loadResponseCache(file)).size, 0);
    assert.equal((await loadResponseCache(join(dir, "nope.json"))).size, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
