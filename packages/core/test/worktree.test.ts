/**
 * Tests for the ephemeral worktree runner. Skipped gracefully when `git` is not
 * on PATH (it always is in CI and dev).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { withWorktree } from "../src/worktree.js";

function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}
const HAS_GIT = gitAvailable();

async function makeRepo(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "quantakrypto-repo-"));
  const g = (args: string[]) => execFileSync("git", args, { cwd: repo, stdio: "pipe" });
  g(["init"]);
  g(["config", "user.email", "t@t"]);
  g(["config", "user.name", "t"]);
  await writeFile(join(repo, "f.txt"), "hi");
  g(["add", "."]);
  g(["commit", "-m", "init"]);
  return repo;
}

test("withWorktree yields a checkout of HEAD and cleans it up", { skip: !HAS_GIT }, async () => {
  const repo = await makeRepo();
  try {
    let seenDir = "";
    const contentSeen = await withWorktree(repo, async (dir) => {
      seenDir = dir;
      const s = await stat(join(dir, "f.txt"));
      assert.ok(s.isFile(), "the committed file is present in the worktree");
      return "ok";
    });
    assert.equal(contentSeen, "ok");
    assert.equal(existsSync(seenDir), false, "the worktree is removed afterwards");
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("withWorktree cleans up even when the callback throws", { skip: !HAS_GIT }, async () => {
  const repo = await makeRepo();
  let seenDir = "";
  try {
    await assert.rejects(() =>
      withWorktree(repo, async (dir) => {
        seenDir = dir;
        throw new Error("boom");
      }),
    );
    assert.equal(existsSync(seenDir), false);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("withWorktree throws on a non-repo directory", { skip: !HAS_GIT }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "quantakrypto-norepo-"));
  try {
    await assert.rejects(() => withWorktree(dir, async () => "x"), /not a git repository/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
