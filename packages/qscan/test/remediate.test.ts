/**
 * qremediate CLI tests: diff mode shows a verified fix and writes nothing;
 * apply mode writes the fix and a re-scan is clean; pr mode is gated; arg
 * parsing validates modes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scan } from "@quantakrypto/core";
import { runRemediate, parseRemediateArgs, unifiedDiff } from "../src/index.js";

const LEGACY = "export const opts = { minVersion: 'TLSv1.1' };\n";

async function fixture(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "qremediate-"));
  await writeFile(join(dir, "server.ts"), LEGACY, "utf8");
  return dir;
}

test("diff mode shows a verified TLS fix and writes nothing", async () => {
  const dir = await fixture();
  try {
    const run = await runRemediate({ path: dir, mode: "diff", llm: false });
    assert.equal(run.exitCode, 0);
    assert.equal(run.written.length, 0);
    assert.match(run.output, /-.*TLSv1\.1/);
    assert.match(run.output, /\+.*TLSv1\.3/);
    // file is untouched
    assert.equal(await readFile(join(dir, "server.ts"), "utf8"), LEGACY);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("apply mode writes the fix and a re-scan is clean of the finding", async () => {
  const dir = await fixture();
  try {
    const run = await runRemediate({ path: dir, mode: "apply", llm: false });
    assert.equal(run.exitCode, 0);
    assert.deepEqual(run.written, ["server.ts"]);
    const after = await readFile(join(dir, "server.ts"), "utf8");
    assert.match(after, /TLSv1\.3/);
    const rescan = await scan({ root: dir });
    assert.ok(!rescan.findings.some((f) => f.ruleId === "tls-legacy-version"), "finding gone");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("pr mode opens a DRAFT PR via the injected backend and never writes the tree", async () => {
  const dir = await fixture();
  try {
    let seen: { branch: string; patches: unknown[]; body: string } | null = null;
    const run = await runRemediate(
      { path: dir, mode: "pr", llm: false },
      {
        branchSuffix: "test",
        openDraftPr: async (plan) => {
          seen = plan;
          return { url: "https://example/pr/1" };
        },
      },
    );
    assert.equal(run.exitCode, 0);
    assert.ok(seen, "the draft-PR backend was called");
    assert.equal(seen.branch, "quantakrypto/remediate-test");
    assert.equal(seen.patches.length, 1);
    assert.match(seen.body, /draft/i);
    assert.match(run.output, /DRAFT PR/);
    // The working tree is NOT mutated in pr mode (the backend isolates it).
    assert.equal(await readFile(join(dir, "server.ts"), "utf8"), LEGACY);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--llm proposes a fix for a finding no codemod covers, gated by verify", async () => {
  const dir = await mkdtemp(join(tmpdir(), "qremediate-llm-"));
  try {
    await writeFile(
      join(dir, "keys.ts"),
      "export const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
      "utf8",
    );
    const run = await runRemediate(
      { path: dir, mode: "diff", llm: true },
      {
        // Simulate the LLM returning PQC code that clears the finding.
        llmPatchSource: async (finding) => ({
          path: finding.location.file,
          newContent: "export const k = mlkem768.keygen();\n",
          ruleId: finding.ruleId,
          source: "llm",
        }),
      },
    );
    assert.match(run.output, /mlkem768/);
    assert.match(run.output, /1 verified fix/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("parseRemediateArgs validates the mode and captures flags", () => {
  const ok = parseRemediateArgs(["src", "--mode", "apply", "--llm"]);
  assert.equal(ok.kind, "run");
  if (ok.kind === "run") {
    assert.equal(ok.options.path, "src");
    assert.equal(ok.options.mode, "apply");
    assert.equal(ok.options.llm, true);
  }
  assert.equal(parseRemediateArgs(["--mode", "bogus"]).kind, "error");
  assert.equal(parseRemediateArgs(["--help"]).kind, "help");
});

test("unifiedDiff produces a hunk for a localized change", () => {
  const d = unifiedDiff("a.ts", "line1\nline2\nline3\n", "line1\nCHANGED\nline3\n");
  assert.match(d, /^--- a\/a\.ts/m);
  assert.match(d, /-line2/);
  assert.match(d, /\+CHANGED/);
});
