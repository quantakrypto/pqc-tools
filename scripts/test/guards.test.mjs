/**
 * Known-bad-fixture tests for the CI GUARD scripts themselves.
 *
 * These scripts are the repo's hard supply-chain / output gates (zero runtime
 * deps, SHA-pinned actions, structurally-valid SARIF). They run as their own CI
 * steps, so nothing else proves their FAILURE path works — a guard whose reject
 * logic silently broke would leave CI green while the invariant eroded. Each
 * test below feeds a deliberately-bad fixture and asserts the guard rejects it,
 * plus a good fixture to confirm it still passes.
 *
 * Run via `npm run test:scripts` (node:test, ESM, zero deps).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { validateSarif } from "../validate-sarif.mjs";
import { findUnpinnedActions } from "../check-action-pins.mjs";
import { scanFileForViolations, maskCode } from "../check-offline-boundary.mjs";

const SCRIPTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** A minimal, structurally-valid SARIF 2.1.0 document. */
function goodSarif() {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "qScan", rules: [{ id: "rsa-keygen" }] } },
        results: [
          {
            ruleId: "rsa-keygen",
            level: "error",
            message: { text: "RSA is classical" },
            locations: [{ physicalLocation: { artifactLocation: { uri: "a.ts" } } }],
          },
        ],
      },
    ],
  };
}

/* ------------------------------ validate-sarif ---------------------------- */

test("validateSarif ACCEPTS a well-formed SARIF 2.1.0 document", () => {
  assert.equal(validateSarif(goodSarif()).ok, true);
});

test("validateSarif REJECTS the wrong version", () => {
  const bad = goodSarif();
  bad.version = "2.0.0";
  const v = validateSarif(bad);
  assert.equal(v.ok, false);
  assert.ok(
    v.errors.some((e) => e.includes("$.version")),
    "the version violation is reported",
  );
});

test("validateSarif REJECTS missing runs[] and a non-object top level", () => {
  const noRuns = goodSarif();
  delete noRuns.runs;
  assert.equal(validateSarif(noRuns).ok, false);
  assert.equal(validateSarif(null).ok, false);
  assert.equal(validateSarif("not-an-object").ok, false);
});

test("validateSarif REJECTS a result missing its ruleId / message / locations", () => {
  const bad = goodSarif();
  bad.runs[0].results[0] = { level: "error" }; // no ruleId, message, or locations
  const v = validateSarif(bad);
  assert.equal(v.ok, false);
  assert.ok(v.errors.length >= 1, "the malformed result is flagged");
});

/* ---------------------------- check-action-pins --------------------------- */

/** Write workflow YAML files into a fresh temp workflow dir; return the dir. */
function makeWorkflows(files) {
  const dir = mkdtempSync(join(tmpdir(), "qk-wf-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

test("findUnpinnedActions FLAGS a tag- or branch-pinned action", () => {
  const dir = makeWorkflows({
    "ci.yml": [
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4", // tag — unpinned
      "      - uses: actions/setup-node@main", // branch — unpinned
    ].join("\n"),
  });
  try {
    const violations = findUnpinnedActions(dir);
    assert.equal(violations.length, 2, "both the tag and the branch ref are flagged");
    assert.ok(violations.every((v) => v.file === "ci.yml"));
    assert.ok(violations.some((v) => v.uses.includes("actions/checkout@v4")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("findUnpinnedActions PASSES SHA-pinned, local, and docker refs", () => {
  const sha = "a".repeat(40);
  const dir = makeWorkflows({
    "ci.yml": [
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/checkout@${sha} # v4.1.1`, // SHA-pinned (+ human tag comment)
      "      - uses: ./.github/actions/local", // local composite — exempt
      "      - uses: docker://alpine:3.20", // docker image — exempt
    ].join("\n"),
  });
  try {
    assert.deepEqual(findUnpinnedActions(dir), [], "no violations for pinned/exempt refs");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ----------------------------- check-zero-deps ---------------------------- */

/**
 * Drive the real `check-zero-deps.mjs` (which scans `packages/` relative to its
 * cwd) against a temp fixture so its process exit code is what we assert.
 */
function runZeroDeps(packages) {
  const root = mkdtempSync(join(tmpdir(), "qk-deps-"));
  for (const [name, manifest] of Object.entries(packages)) {
    mkdirSync(join(root, "packages", name), { recursive: true });
    writeFileSync(join(root, "packages", name, "package.json"), JSON.stringify(manifest, null, 2));
  }
  const res = spawnSync(process.execPath, [join(SCRIPTS_DIR, "check-zero-deps.mjs")], {
    cwd: root,
    encoding: "utf8",
  });
  rmSync(root, { recursive: true, force: true });
  return res;
}

test("check-zero-deps FAILS (exit 1) on a third-party runtime dependency", () => {
  const res = runZeroDeps({
    bad: { name: "@quantakrypto/bad", dependencies: { "node-forge": "^1.3.1" } },
  });
  assert.equal(res.status, 1, "a non-@quantakrypto runtime dep must fail the gate");
  assert.match(res.stderr, /node-forge/);
  assert.match(res.stderr, /ADR-0001/);
});

test("check-zero-deps FAILS (exit 1) on an install lifecycle script", () => {
  const res = runZeroDeps({
    sneaky: { name: "@quantakrypto/sneaky", scripts: { postinstall: "node ./steal.js" } },
  });
  assert.equal(res.status, 1, "an install lifecycle script must fail the gate");
  assert.match(res.stderr, /lifecycle script/i);
});

test("check-zero-deps PASSES when only @quantakrypto/* deps and no lifecycle scripts exist", () => {
  const res = runZeroDeps({
    ok: {
      name: "@quantakrypto/ok",
      dependencies: { "@quantakrypto/core": "*" },
      scripts: { build: "tsc -b", test: "node --test" },
    },
  });
  assert.equal(res.status, 0, `clean workspace should pass; stderr=${res.stderr}`);
});

/* ------------------------- check-offline-boundary (ADR-0005) -------------- */

const rules = (vs) => vs.map((v) => v.rule).sort();

test("offline-boundary FLAGS core importing the agent plane", () => {
  const bad = 'import { proposeFix } from "@quantakrypto/agent";\nexport const x = 1;\n';
  assert.deepEqual(rules(scanFileForViolations("core", "packages/core/src/x.ts", bad)), [
    "agent-import",
  ]);
});

test("offline-boundary FLAGS an outbound fetch() and an LLM key read in the offline trio", () => {
  const net = "export async function f() { return fetch('https://evil'); }\n";
  assert.ok(
    scanFileForViolations("mcp", "packages/mcp/src/x.ts", net).some(
      (v) => v.rule === "outbound-network",
    ),
  );
  const key = "const k = process.env.ANTHROPIC_API_KEY;\n";
  assert.ok(
    scanFileForViolations("sieve", "packages/sieve/src/x.ts", key).some(
      (v) => v.rule === "llm-key-read",
    ),
  );
});

test("offline-boundary requires qscan to reach the agent via DYNAMIC import only", () => {
  const staticImp = 'import { proposeFix } from "@quantakrypto/agent";\n';
  assert.deepEqual(rules(scanFileForViolations("qscan", "packages/qscan/src/x.ts", staticImp)), [
    "agent-static-import",
  ]);
  const dynImp = 'const agent = await import("@quantakrypto/agent");\n';
  assert.deepEqual(scanFileForViolations("qscan", "packages/qscan/src/x.ts", dynImp), []);
});

test("offline-boundary FLAGS an auto-merge anywhere", () => {
  const merge = 'await exec("gh pr merge --admin --squash");\n';
  assert.ok(
    scanFileForViolations("action", "packages/action/src/x.ts", merge).some(
      (v) => v.rule === "auto-merge",
    ),
  );
});

test("offline-boundary does NOT flag agent (its own network/key) or action's GitHub fetch", () => {
  const agentCode =
    "const k = process.env.OPENAI_API_KEY;\nawait fetch('https://api.openai.com');\n";
  // In the agent package, key reads are allowed; outbound-network only applies to the offline trio.
  assert.deepEqual(scanFileForViolations("agent", "packages/agent/src/x.ts", agentCode), []);
  // The GitHub Action legitimately calls the GitHub API.
  assert.deepEqual(
    scanFileForViolations("action", "packages/action/src/x.ts", "await fetch(url);\n"),
    [],
  );
});

test("offline-boundary masking ignores tokens inside comments and string literals", () => {
  // core's redaction patterns MATCH `fetch(` as a token inside a regex string, and
  // comments mention the agent — neither is a real call/import.
  const masked = maskCode(
    'const RE = "\\\\bfetch\\\\(";\n// see @quantakrypto/agent for the networked plane\n',
  );
  assert.doesNotMatch(masked, /fetch\s*\(/, "the string token is blanked");
  assert.deepEqual(
    scanFileForViolations("core", "packages/core/src/redact.ts", 'const RE = "\\\\bfetch\\\\(";\n'),
    [],
    "a fetch token inside a string is not a violation",
  );
});
