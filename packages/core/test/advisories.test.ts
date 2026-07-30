/**
 * Tests for the dependency-advisory scanner (`--audit`). Drives it with an
 * injected `exec` and `listDir` so no real cargo/pip/npm audit tool — or network
 * — is needed: the ecosystem detection, JSON parsing, severity mapping, and the
 * graceful-degradation (ENOENT / non-zero-exit-with-stdout) paths are all
 * exercised deterministically.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { scanAdvisories } from "../src/advisories.js";
import type { ExecFn } from "../src/advisories.js";

/** Build an exec stub from a map of `command` → stdout (or an error to throw). */
function execFrom(map: Record<string, string | Error>): ExecFn {
  return async (command) => {
    const v = map[command];
    if (v === undefined) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    if (v instanceof Error) throw v;
    return { stdout: v, stderr: "" };
  };
}

test("npm audit advisories become dependency findings (severity mapped, patched → remediation)", async () => {
  const npm = JSON.stringify({
    vulnerabilities: {
      lodash: {
        name: "lodash",
        severity: "high",
        range: "<4.17.21",
        fixAvailable: { name: "lodash", version: "4.17.21" },
        via: [
          {
            source: 1065,
            name: "lodash",
            title: "Prototype pollution",
            url: "https://github.com/advisories/GHSA-jf85-cpcp-j695",
            severity: "high",
          },
        ],
      },
    },
  });
  const { findings, diagnostics } = await scanAdvisories("/repo", {
    listDir: async () => ["package-lock.json"],
    exec: execFrom({ npm }),
  });
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.ruleId, "dep-advisory");
  assert.equal(f.category, "dependency");
  assert.equal(f.severity, "high");
  assert.equal(f.title, "GHSA-jf85-cpcp-j695");
  assert.match(f.message, /lodash@<4\.17\.21: Prototype pollution \(GHSA-jf85-cpcp-j695\)/);
  assert.equal(f.location.file, "package-lock.json");
  assert.match(f.remediation ?? "", /Upgrade lodash to 4\.17\.21/);
  assert.deepEqual(diagnostics, []);
});

test("a non-zero exit carrying JSON on stdout is parsed, not treated as failure", async () => {
  // npm/cargo/pip audit all exit non-zero when advisories exist.
  const cargo = JSON.stringify({
    vulnerabilities: {
      count: 1,
      list: [
        {
          advisory: { id: "RUSTSEC-2023-0001", title: "flaw", severity: "medium" },
          package: { name: "time", version: "0.1.0" },
          versions: { patched: [">=0.2.23"] },
        },
      ],
    },
  });
  const err = Object.assign(new Error("exit 1"), { code: undefined, stdout: cargo, stderr: "" });
  const { findings, diagnostics } = await scanAdvisories("/repo", {
    listDir: async () => ["Cargo.lock"],
    exec: execFrom({ cargo: err }),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "RUSTSEC-2023-0001");
  assert.equal(findings[0].severity, "medium");
  assert.equal(findings[0].location.file, "Cargo.lock");
  assert.deepEqual(diagnostics, []);
});

test("a missing tool (ENOENT) degrades to a diagnostic, never throws", async () => {
  const { findings, diagnostics } = await scanAdvisories("/repo", {
    listDir: async () => ["Cargo.toml"],
    exec: execFrom({}), // every command → ENOENT
  });
  assert.deepEqual(findings, []);
  assert.deepEqual(diagnostics, ["cargo audit not available, skipped"]);
});

test("pip-audit object form is parsed; absent ecosystems are not probed", async () => {
  const pip = JSON.stringify({
    dependencies: [
      {
        name: "requests",
        version: "2.19.0",
        vulns: [{ id: "PYSEC-2018-28", description: "CRLF", fix_versions: ["2.20.0"] }],
      },
    ],
  });
  const { findings } = await scanAdvisories("/repo", {
    listDir: async () => ["requirements.txt"],
    exec: execFrom({ "pip-audit": pip }),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "PYSEC-2018-28");
  assert.equal(findings[0].severity, "high", "pip-audit has no severity → conservative high");
  assert.match(findings[0].remediation ?? "", /Upgrade requests to 2\.20\.0/);
});

test("no manifests present → no findings, no diagnostics", async () => {
  const { findings, diagnostics } = await scanAdvisories("/repo", {
    listDir: async () => ["src", "README.md"],
    exec: execFrom({}),
  });
  assert.deepEqual(findings, []);
  assert.deepEqual(diagnostics, []);
});
