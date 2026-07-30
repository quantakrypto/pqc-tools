/**
 * Tests for the provenance / declared-source-repository check (`--audit`). Uses
 * an injected manifest reader and HEAD requester so it is fully offline and
 * deterministic — exercising the static `repo-missing` path, the networked
 * `repo-unresolved` path (404 + DNS-fail), the resolves-fine and skip-silently
 * paths, and the URL normalization.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { checkProvenance, normalizeRepoUrl } from "../src/provenance.js";
import type { RepoHeadOutcome } from "../src/provenance.js";

/** A manifest reader that serves `files[name]`, else throws ENOENT. */
function readerFrom(files: Record<string, string>) {
  return async (file: string) => {
    const base = file.split("/").pop() ?? file;
    if (base in files) return files[base];
    throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
  };
}

test("package.json with no repository → provenance-repo-missing (info)", async () => {
  const { findings } = await checkProvenance("/repo", {
    readManifest: readerFrom({ "package.json": JSON.stringify({ name: "x", version: "1.0.0" }) }),
  });
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.ruleId, "provenance-repo-missing");
  assert.equal(f.category, "dependency");
  assert.equal(f.severity, "info");
  assert.match(f.message, /declares no source repository/);
  assert.equal(f.location.file, "package.json");
});

test("no root manifest at all → no finding (nothing to assess)", async () => {
  const { findings, diagnostics } = await checkProvenance("/repo", {
    readManifest: readerFrom({}),
  });
  assert.deepEqual(findings, []);
  assert.deepEqual(diagnostics, []);
});

test("static mode never makes a network call even when a repo is declared", async () => {
  let called = false;
  const { findings } = await checkProvenance("/repo", {
    readManifest: readerFrom({
      "package.json": JSON.stringify({ repository: "https://github.com/a/b" }),
    }),
    head: async () => {
      called = true;
      return { kind: "status", status: 200 };
    },
    // network omitted → false
  });
  assert.equal(called, false, "no HEAD request in static mode");
  assert.deepEqual(findings, []);
});

test("network mode: a 404 on the declared repo → provenance-repo-unresolved (medium)", async () => {
  const { findings } = await checkProvenance("/repo", {
    network: true,
    readManifest: readerFrom({
      "package.json": JSON.stringify({ repository: { url: "git+https://github.com/a/gone.git" } }),
    }),
    head: async (): Promise<RepoHeadOutcome> => ({ kind: "status", status: 404 }),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "provenance-repo-unresolved");
  assert.equal(findings[0].severity, "medium");
  assert.match(findings[0].message, /https:\/\/github\.com\/a\/gone does not resolve/);
});

test("network mode: a DNS failure → unresolved; a transient error → skipped silently", async () => {
  const dns = await checkProvenance("/repo", {
    network: true,
    readManifest: readerFrom({ "Cargo.toml": '[package]\nrepository = "https://nope.invalid/x"' }),
    head: async (): Promise<RepoHeadOutcome> => ({ kind: "unresolved" }),
  });
  assert.equal(dns.findings.length, 1);
  assert.equal(dns.findings[0].ruleId, "provenance-repo-unresolved");
  assert.equal(dns.findings[0].location.file, "Cargo.toml");

  const transient = await checkProvenance("/repo", {
    network: true,
    readManifest: readerFrom({ "Cargo.toml": '[package]\nrepository = "https://ok.example/x"' }),
    head: async (): Promise<RepoHeadOutcome> => ({ kind: "error", message: "timeout" }),
  });
  assert.deepEqual(transient.findings, []);
  assert.equal(transient.diagnostics.length, 1);
  assert.match(transient.diagnostics[0], /could not verify .* skipped/);
});

test("network mode: a 200 (repo resolves) yields no finding", async () => {
  const { findings } = await checkProvenance("/repo", {
    network: true,
    readManifest: readerFrom({
      "package.json": JSON.stringify({ repository: "github:a/b" }),
    }),
    head: async (): Promise<RepoHeadOutcome> => ({ kind: "status", status: 200 }),
  });
  assert.deepEqual(findings, []);
});

test("normalizeRepoUrl handles git+/scp/shorthand forms and strips .git", () => {
  assert.equal(normalizeRepoUrl("git+https://github.com/a/b.git"), "https://github.com/a/b");
  assert.equal(normalizeRepoUrl("git@github.com:a/b.git"), "https://github.com/a/b");
  assert.equal(normalizeRepoUrl("github:a/b"), "https://github.com/a/b");
  assert.equal(normalizeRepoUrl("a/b"), "https://github.com/a/b");
  assert.equal(normalizeRepoUrl("git://gitlab.com/a/b.git"), "https://gitlab.com/a/b");
  assert.equal(normalizeRepoUrl("not a url"), null);
});
