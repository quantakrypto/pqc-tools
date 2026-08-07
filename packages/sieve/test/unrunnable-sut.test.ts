import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runSieve } from "../src/index.js";
import { describeSutError, SutCrashError, TimeoutError } from "../src/runner.js";
import { HARNESS_CATEGORY, overallVerdict } from "../src/report.js";
import type { CategoryResult } from "../src/categories/types.js";

/**
 * An implementation that cannot be run is not a failing implementation.
 *
 * Before this, pointing --impl at a file that did not exist produced a FAIL
 * report with ~35 high-severity checks, each tagged with a bug class that was
 * never exercised: a confident verdict about code that never executed. These
 * tests pin the three properties that stop that happening.
 */

const dir = mkdtempSync(join(tmpdir(), "sieve-unrunnable-"));

test("a SUT that cannot start yields ERROR and one harness check, not a battery of failures", async () => {
  const report = await runSieve({
    command: ["node", join(dir, "does-not-exist.js")],
    param: "ml-kem-768",
    iterations: 2,
  });

  assert.equal(report.overall, "ERROR", "must not claim a FAIL verdict on code that never ran");
  assert.equal(report.categories.length, 1);
  assert.equal(report.categories[0]?.category, HARNESS_CATEGORY);
  assert.equal(report.counts.pass, 0);
  assert.equal(report.counts.fail, 1, "one true statement, not one per skipped probe");

  // No bug classes: none were tested, so none may be implied.
  const tagged = report.categories.flatMap((c) => c.checks).filter((k) => k.bugClass !== undefined);
  assert.deepEqual(tagged, []);
});

test("the harness check names the actual cause, not just the exit code", async () => {
  const report = await runSieve({
    command: ["node", join(dir, "does-not-exist.js")],
    param: "ml-kem-768",
    iterations: 2,
  });

  const detail = report.categories[0]?.checks[0]?.detail ?? "";
  // "SUT exited with code 1" alone is unactionable; the missing path is the fix.
  assert.match(detail, /Cannot find module/);
  assert.match(detail, /does-not-exist\.js/);
});

test("a SUT that starts and answers is judged normally, however wrong its answers", async () => {
  // Speaks the protocol but refuses every op. That IS a conformance signal, so
  // the battery must run rather than being short-circuited as unrunnable.
  const impl = join(dir, "always-error.js");
  writeFileSync(
    impl,
    `const rl = require("node:readline").createInterface({ input: process.stdin });
     rl.on("line", (line) => {
       let id = 0;
       try { id = JSON.parse(line).id ?? 0; } catch {}
       process.stdout.write(JSON.stringify({ id, ok: false, code: "unsupported", message: "not implemented" }) + "\\n");
     });`,
  );

  const report = await runSieve({ command: ["node", impl], param: "ml-kem-768", iterations: 2 });

  assert.notEqual(report.overall, "ERROR", "a live SUT is a conformance question, not a harness fault");
  assert.equal(report.overall, "FAIL");
  assert.ok(
    report.categories.every((c) => c.category !== HARNESS_CATEGORY),
    "no harness category when the SUT is reachable",
  );
});

test("a SUT that starts but never answers is reported as unrunnable, and said so exactly", async () => {
  // Spawns and reads, never writes. There is no crash and no stderr, so there is
  // no diagnosis to quote — the report must say that plainly rather than dress
  // up silence as one. Tiny timeout/iterations to keep this test quick.
  const impl = join(dir, "hangs.js");
  writeFileSync(impl, `require("node:readline").createInterface({ input: process.stdin }).on("line", () => {});`);

  const report = await runSieve({
    command: ["node", impl],
    param: "ml-kem-768",
    iterations: 1,
    timeoutMs: 50,
  });

  assert.equal(report.overall, "ERROR");
  assert.equal(report.categories.length, 1);
  assert.match(report.categories[0]?.checks[0]?.detail ?? "", /never returned a protocol response/);
});

test("the unusable check costs no requests: a run that needs none sends none", async () => {
  // The guard reads a counter the runner keeps anyway. Nothing may probe the SUT
  // speculatively to find out whether it is alive: `kat` without --vectors skips
  // without issuing a request, so a healthy SUT must see exactly zero.
  const log = join(dir, "requests.log");
  const impl = join(dir, "counting.js");
  writeFileSync(
    impl,
    `const fs = require("node:fs");
     fs.writeFileSync(${JSON.stringify(log)}, "");
     require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {
       fs.appendFileSync(${JSON.stringify(log)}, line + "\\n");
     });`,
  );

  await runSieve({ command: ["node", impl], param: "ml-kem-768", iterations: 1, only: ["kat"] });

  const sent = readFileSync(log, "utf8").split("\n").filter(Boolean);
  assert.deepEqual(sent, [], "no speculative probe may be issued");
});

test("overallVerdict: ERROR outranks FAIL", () => {
  const harness: CategoryResult = {
    category: HARNESS_CATEGORY,
    status: "fail",
    checks: [{ name: "sut-startup", status: "fail", detail: "boom" }],
    summary: "unusable",
  };
  const broken: CategoryResult = {
    category: "correctness",
    status: "fail",
    checks: [{ name: "roundtrip", status: "fail", detail: "bad" }],
    summary: "failed",
  };
  assert.equal(overallVerdict([harness, broken]), "ERROR");
  assert.equal(overallVerdict([broken]), "FAIL");
});

test("describeSutError quotes the diagnostic line from either end of a dump", () => {
  // Node buries the useful line in the middle: internal frame first, version last.
  const node = new SutCrashError(
    "SUT exited with code 1",
    [
      "node:internal/modules/cjs/loader:1215",
      "  throw err;",
      "  ^",
      "Error: Cannot find module '/x/my-impl.js'",
      "    at Function._resolveFilename (node:internal/modules/cjs/loader:1207:15)",
      "Node.js v20.19.6",
    ].join("\n"),
  );
  const nodeText = describeSutError(node);
  assert.match(nodeText, /Cannot find module/);
  assert.doesNotMatch(nodeText, /Node\.js v20/, "the version banner is not a diagnosis");

  // Python is the mirror image: the exception is the LAST line.
  const python = new SutCrashError(
    "SUT exited with code 1",
    [
      "Traceback (most recent call last):",
      '  File "/x/kem.py", line 2, in <module>',
      "RuntimeError: boom in my kem",
    ].join("\n"),
  );
  assert.match(describeSutError(python), /RuntimeError: boom in my kem/);
});

test("describeSutError degrades honestly with no stderr and passes other errors through", () => {
  assert.match(describeSutError(new SutCrashError("failed to spawn SUT: ENOENT", "")), /\(no stderr\)/);
  // A timeout carries no stderr channel; its own message is already the answer.
  const timeout = new TimeoutError({ id: 1, family: "ml-kem", param: "ml-kem-768", op: "keygen" }, 10);
  assert.equal(describeSutError(timeout), timeout.message);
});
