/**
 * scanParallel must honor the same cancellation + work budgets as the serial
 * path (previously they were silently dropped on the parallel route).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scanParallel, AbortError, BudgetExceededError } from "../src/index.js";

async function fixture(n = 3): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "quantakrypto-par-"));
  for (let i = 0; i < n; i++) {
    await writeFile(join(dir, `f${i}.ts`), "const e = crypto.createECDH('p256');\n", "utf8");
  }
  return dir;
}

test("scanParallel enforces maxFiles", async () => {
  const dir = await fixture(3);
  try {
    await assert.rejects(() => scanParallel({ root: dir, maxFiles: 1 }), BudgetExceededError);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanParallel enforces maxBytes", async () => {
  const dir = await fixture(3);
  try {
    await assert.rejects(() => scanParallel({ root: dir, maxBytes: 1 }), BudgetExceededError);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanParallel honors an already-aborted signal", async () => {
  const dir = await fixture(3);
  try {
    const ctrl = new AbortController();
    ctrl.abort();
    await assert.rejects(() => scanParallel({ root: dir, signal: ctrl.signal }), AbortError);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanParallel completes normally within budget", async () => {
  const dir = await fixture(3);
  try {
    const result = await scanParallel({ root: dir, maxFiles: 100, maxBytes: 1_000_000 });
    assert.ok(result.findings.length >= 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
