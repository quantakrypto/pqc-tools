/**
 * Symlink-escape hardening for the FS root confinement (audit: mcp #1): a
 * symlink inside an allowed root must not read outside it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { realpathInsideRoots } from "../src/fsconfig.js";

test("a symlink inside a root that points OUTSIDE is rejected by realpath containment", async () => {
  const base = await mkdtemp(join(tmpdir(), "quantakrypto-fscfg-"));
  try {
    const root = join(base, "root");
    const outside = join(base, "outside");
    await mkdir(root);
    await mkdir(outside);
    await writeFile(join(outside, "secret.txt"), "s");
    await writeFile(join(root, "ok.txt"), "ok");
    await symlink(outside, join(root, "escape")); // <root>/escape -> <base>/outside

    const config = { roots: [root], maxFiles: 0, maxBytes: 0 };
    // A real file inside the root is allowed.
    assert.equal(await realpathInsideRoots(join(root, "ok.txt"), config), true);
    // The symlink target resolves outside the root → rejected.
    assert.equal(await realpathInsideRoots(join(root, "escape"), config), false);
    assert.equal(await realpathInsideRoots(join(root, "escape", "secret.txt"), config), false);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
