/**
 * Runner resilience against a misbehaving SUT, exercised with tiny spawned
 * probe processes:
 *   - S2: a stray, non-protocol stdout line (banner, log, progress noise) or an
 *     oversize unterminated line is sidelined, not made fatal — previously any
 *     undecodable line triggered `failAll` and stdout had no per-line cap.
 *   - crash/timeout: a SUT that never answers rejects with TimeoutError; a SUT
 *     that exits (or fails to spawn) rejects the in-flight send with a
 *     SutCrashError carrying the exit reason + stderr, and poisons later sends.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

import { Runner, SutCrashError, TimeoutError } from "../src/runner.js";
import type { RequestInput } from "../src/protocol.js";

/** A canonical, cheap verify request used to drive the runner in these tests. */
const VERIFY: RequestInput = {
  family: "ml-dsa",
  param: "ml-dsa-65",
  op: "verify",
  pk: "",
  msg: "",
  sig: "",
};

/** Write a probe .mjs SUT to a temp dir and return its path. */
function writeProbe(body: string): string {
  const probe = join(mkdtempSync(join(tmpdir(), "sieve-runner-")), "probe.mjs");
  writeFileSync(probe, body);
  return probe;
}

test("a banner line on stdout does not kill an otherwise-valid run", async () => {
  // The SUT prints a human banner BEFORE answering, then replies with a valid
  // protocol line. A conformant-but-chatty SUT must still be drivable.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      // Noise to stdout before any request arrives.
      "process.stdout.write('quantakrypto SUT v1.2.3 — starting up\\n');",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  if (!line.trim()) return;",
      "  const r = JSON.parse(line);",
      // More noise interleaved with the real answer.
      "  process.stdout.write('debug: handling request ' + r.id + '\\n');",
      "  process.stdout.write(JSON.stringify({ id: r.id, ok: true, valid: true }) + '\\n');",
      "});",
    ].join("\n"),
  );

  const notes: string[] = [];
  const runner = new Runner({
    command: [process.execPath, probe],
    timeoutMs: 10_000,
    onStderr: (l) => notes.push(l),
  });
  try {
    const resp = await runner.send({
      family: "ml-dsa",
      param: "ml-dsa-65",
      op: "verify",
      pk: "",
      msg: "",
      sig: "",
    });
    assert.equal(resp.ok, true);
    assert.ok("valid" in resp && resp.valid === true, "the real protocol response still arrived");
    // A second request must also succeed — the runner was not poisoned.
    const resp2 = await runner.send({
      family: "ml-dsa",
      param: "ml-dsa-65",
      op: "verify",
      pk: "",
      msg: "",
      sig: "",
    });
    assert.ok("valid" in resp2 && resp2.valid === true);
  } finally {
    await runner.close();
  }
  // The banner/debug lines were sidelined to the stderr sink, not made fatal.
  assert.ok(
    notes.some((n) => /ignored non-protocol stdout line/.test(n)),
    "non-protocol stdout lines should be surfaced via onStderr",
  );
});

test("an oversized stdout line is sidelined, not buffered or made fatal", async () => {
  // The SUT emits one enormous non-protocol line (no newline for a long time),
  // then a valid response. The giant line must be capped/ignored, not buffered
  // without bound nor treated as a protocol violation that aborts the run.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  if (!line.trim()) return;",
      "  const r = JSON.parse(line);",
      // ~512 KiB of junk on a single stdout line, then the real answer.
      "  process.stdout.write('x'.repeat(512 * 1024) + '\\n');",
      "  process.stdout.write(JSON.stringify({ id: r.id, ok: true, valid: false }) + '\\n');",
      "});",
    ].join("\n"),
  );

  const runner = new Runner({ command: [process.execPath, probe], timeoutMs: 10_000 });
  try {
    const resp = await runner.send({
      family: "ml-dsa",
      param: "ml-dsa-65",
      op: "verify",
      pk: "",
      msg: "",
      sig: "",
    });
    assert.equal(resp.ok, true);
    assert.ok("valid" in resp && resp.valid === false, "valid response survives the oversize line");
  } finally {
    await runner.close();
  }
});

/* --------------------------- crash / timeout ------------------------------ */

test("a request to a SUT that never answers rejects with TimeoutError", async () => {
  // The SUT reads a line but deliberately never replies. With a short timeout,
  // send() must reject with a TimeoutError carrying the request + timeout.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', () => { /* swallow the request, never respond */ });",
    ].join("\n"),
  );
  const runner = new Runner({ command: [process.execPath, probe], timeoutMs: 150 });
  try {
    await assert.rejects(
      () => runner.send(VERIFY),
      (err: unknown) => {
        assert.ok(err instanceof TimeoutError, "rejects with TimeoutError");
        assert.equal(err.timeoutMs, 150);
        assert.equal(err.request.op, "verify");
        assert.match(err.message, /within 150ms/);
        return true;
      },
    );
  } finally {
    await runner.close();
  }
});

test("a SUT that exits mid-request rejects the in-flight send with SutCrashError", async () => {
  // The SUT prints a diagnostic to stderr, then exits non-zero on the first
  // request without answering. The in-flight send() must reject with a
  // SutCrashError that captures the exit reason and the SUT's stderr.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', () => {",
      "  process.stderr.write('fatal: unsupported parameter set\\n');",
      "  process.exit(3);",
      "});",
    ].join("\n"),
  );
  const runner = new Runner({ command: [process.execPath, probe], timeoutMs: 10_000 });
  try {
    await assert.rejects(
      () => runner.send(VERIFY),
      (err: unknown) => {
        assert.ok(err instanceof SutCrashError, "rejects with SutCrashError");
        assert.match(err.message, /exited with code 3|exited via signal/);
        assert.match(err.stderr, /unsupported parameter set/, "SUT stderr is attached");
        return true;
      },
    );
  } finally {
    await runner.close();
  }
});

test("spawning a nonexistent SUT binary rejects with SutCrashError", async () => {
  const runner = new Runner({
    command: ["/nonexistent/quantakrypto-sut-does-not-exist", "--stdio"],
    timeoutMs: 10_000,
  });
  try {
    await assert.rejects(
      () => runner.send(VERIFY),
      (err: unknown) => {
        assert.ok(err instanceof SutCrashError, "spawn failure surfaces as SutCrashError");
        assert.match(err.message, /failed to spawn SUT|exited/);
        return true;
      },
    );
  } finally {
    await runner.close();
  }
});

test("once a SUT has crashed, every later send rejects with the same fatal error", async () => {
  // After the first crash, the runner is poisoned: subsequent sends fail fast
  // with the stored fatal error rather than hanging until timeout.
  const probe = writeProbe(
    [
      "import { createInterface } from 'node:readline';",
      "const rl = createInterface({ input: process.stdin });",
      "rl.on('line', () => process.exit(1));",
    ].join("\n"),
  );
  const runner = new Runner({ command: [process.execPath, probe], timeoutMs: 10_000 });
  try {
    await assert.rejects(() => runner.send(VERIFY), SutCrashError);
    // The process is gone; a follow-up send must reject promptly (fail-fast),
    // again as a SutCrashError — not hang or throw a generic error.
    await assert.rejects(() => runner.send(VERIFY), SutCrashError);
  } finally {
    await runner.close();
  }
});
