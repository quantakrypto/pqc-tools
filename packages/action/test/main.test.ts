import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { applyBaseline, evaluateMandates, fingerprintFinding } from "@quantakrypto/core";
import type { Baseline, Finding, MandateEvaluation, ScanResult } from "@quantakrypto/core";

import {
  annotateFindings,
  buildMandateSection,
  buildPlanComment,
  buildSummary,
  describeMandateFailure,
  fingerprint,
  mandateGateRows,
  meetsThreshold,
  readInputs,
  run,
  shouldFail,
} from "../src/main.js";

/** Run `fn` with `process.stdout.write` captured; return the written text. */
function captureStdout(fn: () => void): string {
  const original = process.stdout.write.bind(process.stdout);
  let buf = "";
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    buf += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  }) as typeof process.stdout.write;
  try {
    fn();
  } finally {
    process.stdout.write = original;
  }
  return buf;
}

/** Build a Finding with sensible defaults for tests. */
function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "rsa-keygen",
    title: "RSA key generation",
    category: "signature",
    severity: "high",
    confidence: "high",
    algorithm: "RSA",
    hndl: true,
    message: "RSA-2048 key generation detected",
    location: { file: "src/crypto.ts", line: 10 },
    ...over,
  };
}

/** Build a minimal ScanResult around the given findings. */
function makeResult(findings: Finding[], readinessScore = 75): ScanResult {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  return {
    root: ".",
    findings,
    filesScanned: 1,
    inventory: {
      byAlgorithm: {},
      byCategory: {},
      bySeverity,
      hndlCount: findings.filter((f) => f.hndl).length,
      readinessScore,
    },
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    toolVersion: "0.1.0",
  };
}

/** Wrap a set of fingerprints in the shared core baseline shape. */
function baselineOf(...fingerprints: string[]): Baseline {
  return { version: 1, fingerprints };
}

test("readInputs applies defaults when env is empty", () => {
  const i = readInputs({});
  assert.equal(i.path, ".");
  assert.equal(i.severityThreshold, "high");
  assert.equal(i.failOnFindings, true);
  assert.equal(i.format, "sarif");
  assert.equal(i.output, "quantakrypto.sarif.json");
  assert.equal(i.baseline, undefined);
  assert.equal(i.commentPr, false);
  assert.equal(i.githubToken, undefined);
});

test("readInputs reads provided values", () => {
  const i = readInputs({
    INPUT_PATH: "packages/app",
    "INPUT_SEVERITY-THRESHOLD": "medium",
    "INPUT_FAIL-ON-FINDINGS": "false",
    INPUT_FORMAT: "json",
    INPUT_OUTPUT: "report.json",
    INPUT_BASELINE: "base.sarif.json",
    "INPUT_COMMENT-PR": "true",
    "INPUT_GITHUB-TOKEN": "ghs_x",
  });
  assert.equal(i.path, "packages/app");
  assert.equal(i.severityThreshold, "medium");
  assert.equal(i.failOnFindings, false);
  assert.equal(i.format, "json");
  assert.equal(i.output, "report.json");
  assert.equal(i.baseline, "base.sarif.json");
  assert.equal(i.commentPr, true);
  assert.equal(i.githubToken, "ghs_x");
});

test("readInputs rejects an invalid severity-threshold", () => {
  assert.throws(() => readInputs({ "INPUT_SEVERITY-THRESHOLD": "nope" }), TypeError);
});

test("readInputs rejects an invalid format", () => {
  assert.throws(() => readInputs({ INPUT_FORMAT: "xml" }), TypeError);
});

test("meetsThreshold respects severity ordering", () => {
  assert.equal(meetsThreshold("critical", "high"), true);
  assert.equal(meetsThreshold("high", "high"), true);
  assert.equal(meetsThreshold("medium", "high"), false);
  assert.equal(meetsThreshold("info", "info"), true);
  assert.equal(meetsThreshold("low", "critical"), false);
});

test("shouldFail gates on blocking count and fail-on-findings", () => {
  assert.equal(shouldFail(2, true), true);
  assert.equal(shouldFail(0, true), false);
  assert.equal(shouldFail(5, false), false);
});

test("fingerprint is the shared @quantakrypto/core fingerprint", () => {
  // The Action re-exports core's fingerprint so it and the CLI share one
  // baseline format.
  assert.equal(fingerprint, fingerprintFinding);
});

test("applyBaseline (shared) suppresses findings present in the baseline", () => {
  const a = makeFinding({ ruleId: "rsa-keygen" });
  const b = makeFinding({
    ruleId: "ecdh-usage",
    message: "new",
    location: { file: "x.ts", line: 1 },
  });
  const baseline = baselineOf(fingerprint(a));
  const { newFindings, suppressed } = applyBaseline([a, b], baseline);
  assert.equal(newFindings.length, 1);
  assert.equal(newFindings[0]?.ruleId, "ecdh-usage");
  assert.equal(suppressed.length, 1);
  assert.equal(suppressed[0]?.ruleId, "rsa-keygen");
});

test("applyBaseline (shared) is a no-op when the baseline is empty", () => {
  const a = makeFinding();
  const { newFindings, suppressed } = applyBaseline([a], baselineOf());
  assert.deepEqual(newFindings, [a]);
  assert.equal(suppressed.length, 0);
});

test("fingerprint ignores line number so shifted findings still match", () => {
  const a = makeFinding({ location: { file: "src/crypto.ts", line: 10 } });
  const b = makeFinding({ location: { file: "src/crypto.ts", line: 42 } });
  assert.equal(fingerprint(a), fingerprint(b));
});

test("buildSummary reports a clean run when nothing blocks", () => {
  const md = buildSummary(makeResult([], 100), [], "high");
  assert.match(md, /Readiness score:\*\* 100\/100/);
  assert.match(md, /No new quantum-vulnerable cryptography/);
});

test("buildSummary tabulates blocking findings", () => {
  const f = makeFinding();
  const md = buildSummary(makeResult([f]), [f], "high");
  assert.match(md, /\| high \| `rsa-keygen` \| src\/crypto\.ts:10 \|/);
});

// ---------------------------------------------------------------------------
// P0-2: output-injection defenses in the PR-comment Markdown table.
// Finding `file`/`message`/`ruleId` are attacker-controlled in a fork PR.
// ---------------------------------------------------------------------------

test("buildSummary: a hostile filename with a pipe cannot break the table", () => {
  const f = makeFinding({
    location: { file: "evil|name.ts", line: 1 },
    message: "msg",
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  const row = md.split("\n").find((l) => l.includes("evil"));
  assert.ok(row, "expected a row containing the hostile filename");
  // The cell-internal pipe is escaped, so the row still has exactly the 4
  // columns' worth of UNescaped pipes (5 delimiters for 4 cells).
  const unescapedPipes = (row.match(/(?<!\\)\|/g) ?? []).length;
  assert.equal(unescapedPipes, 5);
  assert.match(row, /evil\\\|name\.ts/);
});

test("buildSummary: backticks in finding text are escaped (no code-span breakout)", () => {
  const f = makeFinding({
    ruleId: "r`id",
    message: "see `secret` and `more`",
    location: { file: "a`b.ts", line: 2 },
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  const row = md.split("\n").find((l) => l.includes("a\\`b.ts"));
  assert.ok(row, "expected the file cell with an escaped backtick");
  // No bare backticks survive except the two we add around the (escaped) ruleId.
  assert.match(row, /\\`secret\\`/);
  assert.match(row, /r\\`id/);
});

test("buildSummary: HTML in a filename is entity-encoded (no HTML injection)", () => {
  const f = makeFinding({
    location: { file: '<img src=x onerror="alert(1)">.ts', line: 3 },
    message: "<b>bold</b> & <script>evil</script>",
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  assert.doesNotMatch(md, /<img/);
  assert.doesNotMatch(md, /<script>/);
  assert.doesNotMatch(md, /<b>/);
  assert.match(md, /&lt;img/);
  assert.match(md, /&lt;script&gt;/);
  assert.match(md, /&amp;/);
});

test("buildSummary: newlines and ']' in finding text cannot add rows or break out", () => {
  const f = makeFinding({
    message: "line1\nline2\r\n| injected | row |",
    location: { file: "weird]name::x.ts", line: 4 },
  });
  const md = buildSummary(makeResult([f]), [f], "high");
  // The injected "| injected | row |" must remain inside one cell: the table
  // body has exactly one data row plus the header + divider.
  const dataRows = md
    .split("\n")
    .filter((l) => l.startsWith("|") && !/^\| ---/.test(l) && !/^\| Severity/.test(l));
  assert.equal(dataRows.length, 1);
  // The newline was flattened to a space inside the single cell.
  assert.doesNotMatch(dataRows[0] ?? "", /\n/);
  assert.match(dataRows[0] ?? "", /line1 line2/);
});

test("buildSummary: a backslash before a pipe cannot un-escape the delimiter", () => {
  // Naive `replace(/\|/, "\\|")` is defeated by a trailing backslash:
  // "x\" + "|" would render as an escaped-backslash then a LIVE pipe. mdCell
  // doubles backslashes first, so the pipe stays escaped.
  const f = makeFinding({ message: "x\\| y | z", location: { file: "f.ts", line: 1 } });
  const md = buildSummary(makeResult([f]), [f], "high");
  const row = md.split("\n").find((l) => l.includes("f.ts"));
  assert.ok(row);
  const unescapedPipes = (row.match(/(?<!\\)\|/g) ?? []).length;
  assert.equal(unescapedPipes, 5);
});

// ---------------------------------------------------------------------------
// A2: an `info` finding (below every threshold) must annotate as a `notice`,
// not a `warning`. Previously the two-way error/warning split swallowed the
// dead `notice` branch and routed info findings to ::warning::.
// ---------------------------------------------------------------------------

test("annotateFindings routes an info finding to ::notice:: (not ::warning::)", () => {
  const f = makeFinding({
    severity: "info",
    hndl: false,
    message: "informational note",
    remediation: undefined,
    location: { file: "src/info.ts", line: 7 },
  });
  // threshold "high": the info finding is below it, so it takes the
  // annotationLevel path, which is "notice".
  const out = captureStdout(() => annotateFindings([f], "high"));
  assert.match(out, /^::notice .*::informational note$/m);
  assert.doesNotMatch(out, /::warning /);
  assert.doesNotMatch(out, /::error /);
});

test("annotateFindings still uses ::error:: for blocking and ::warning:: for medium/low", () => {
  const high = makeFinding({ severity: "high", message: "blocking", remediation: undefined });
  const low = makeFinding({
    severity: "low",
    message: "minor",
    remediation: undefined,
    location: { file: "x.ts", line: 1 },
  });
  const out = captureStdout(() => annotateFindings([high, low], "high"));
  assert.match(out, /::error .*::blocking/);
  assert.match(out, /::warning .*::minor/);
});

// ---------------------------------------------------------------------------
// A3: resolveInWorkspace (used for output/baseline) must keep paths inside the
// workspace. A "../../x" input must be rejected rather than escaping the tree.
// resolveInWorkspace is internal, so we exercise it through run()/readInputs.
// ---------------------------------------------------------------------------

test("run rejects an output path that escapes the workspace via ../", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "../../escape.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await assert.rejects(() => run(env), /escapes the workspace/);
});

test("run rejects a baseline path that escapes the workspace via ../", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_BASELINE: "../../../etc/passwd",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await assert.rejects(() => run(env), /escapes the workspace/);
});

test("run warns (does not silently degrade) when the baseline file is missing", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(
    join(ws, "crypto.ts"),
    `const kp = generateKeyPairSync("rsa", { modulusLength: 2048 });\n`,
  );
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_BASELINE: "missing-baseline.json",
    INPUT_OUTPUT: "out.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  const original = process.stdout.write.bind(process.stdout);
  let buf = "";
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    buf += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    return true;
  }) as typeof process.stdout.write;
  try {
    await run(env);
  } finally {
    process.stdout.write = original;
  }
  assert.match(buf, /::warning/);
  assert.match(buf, /baseline file not found/);
});

// ---------------------------------------------------------------------------
// A5: the `redact-snippets` input is parsed and honored end-to-end — when set,
// the written report carries no matched source snippet.
// ---------------------------------------------------------------------------

test("readInputs reads the optional org policy path (default undefined)", () => {
  assert.equal(readInputs({}).policy, undefined);
  assert.equal(readInputs({ INPUT_POLICY: "policy.json" }).policy, "policy.json");
});

/**
 * Run the action against a workspace with stdout silenced (the action logs a lot
 * of workflow-command chatter). Does NOT touch `process.exitCode`, so callers
 * must pick inputs that do not trip a gate — the gate semantics themselves are
 * covered at the core / qScan level; these tests assert the machine-readable
 * SARIF the Action writes.
 */
async function runQuiet(env: NodeJS.ProcessEnv): Promise<void> {
  const originalWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    await run(env);
  } finally {
    process.stdout.write = originalWrite;
  }
}

test("run: a --mandate scan writes SARIF carrying run.properties.mandate", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(
    join(ws, "crypto.ts"),
    `const kp = generateKeyPairSync("rsa", { modulusLength: 2048 });\n`,
  );
  // severity-threshold critical + fail-on-findings false so the (high) RSA
  // finding does not gate; RSA is only "due" in 2026 so the mandate gate is quiet
  // (no setFailed → no process.exitCode pollution).
  await runQuiet({
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "out.sarif.json",
    "INPUT_SEVERITY-THRESHOLD": "critical",
    "INPUT_FAIL-ON-FINDINGS": "false",
    INPUT_MANDATE: "cnsa-2.0",
  });
  const sarif = JSON.parse(readFileSync(join(ws, "out.sarif.json"), "utf8"));
  assert.deepEqual(sarif.runs[0].properties.mandate.mandates, ["cnsa-2.0"]);
});

test("run: an org --policy composes into the written SARIF mandateMapping", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(
    join(ws, "crypto.ts"),
    `const kp = generateKeyPairSync("rsa", { modulusLength: 2048 });\n`,
  );
  writeFileSync(join(ws, "policy.json"), JSON.stringify({ name: "org", inTransition: ["RSA"] }));
  await runQuiet({
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "out.sarif.json",
    "INPUT_SEVERITY-THRESHOLD": "critical",
    "INPUT_FAIL-ON-FINDINGS": "false",
    INPUT_MANDATE: "cnsa-2.0",
    INPUT_POLICY: "policy.json",
  });
  const mandate = JSON.parse(readFileSync(join(ws, "out.sarif.json"), "utf8")).runs[0].properties
    .mandate;
  // The org policy reached evaluateMandates: RSA (inTransition) is acknowledged.
  assert.equal(mandate.policyName, "org");
  assert.equal(mandate.acknowledged, 1);
  assert.equal(mandate.findings[0].acknowledged, true);
  assert.equal(mandate.findings[0].policyVerdict, "transition-pending");
});

test("readInputs parses redact-snippets (default false)", () => {
  assert.equal(readInputs({}).redactSnippets, false);
  assert.equal(readInputs({ "INPUT_REDACT-SNIPPETS": "true" }).redactSnippets, true);
  assert.equal(readInputs({ "INPUT_REDACT-SNIPPETS": "false" }).redactSnippets, false);
});

test("run honors redact-snippets: snippet text is omitted from the written report", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  // A file with detectable, quantum-vulnerable crypto whose snippet is unique.
  const marker = "generateKeyPairSync";
  writeFileSync(
    join(ws, "crypto.ts"),
    `import { ${marker} } from "node:crypto";\nconst kp = ${marker}("rsa", { modulusLength: 2048 });\n`,
  );

  // 1) Without redaction the snippet text appears in the report.
  const plainEnv: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_FORMAT: "sarif",
    INPUT_OUTPUT: "plain.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await run(plainEnv);
  const plain = readFileSync(join(ws, "plain.sarif.json"), "utf8");
  assert.ok(plain.includes(marker), "expected the snippet text in the unredacted report");

  // 2) With redact-snippets=true the snippet text is gone.
  const redactedEnv: NodeJS.ProcessEnv = {
    ...plainEnv,
    INPUT_OUTPUT: "redacted.sarif.json",
    "INPUT_REDACT-SNIPPETS": "true",
  };
  await run(redactedEnv);
  const redacted = readFileSync(join(ws, "redacted.sarif.json"), "utf8");
  assert.ok(!redacted.includes(marker), "expected the snippet text to be redacted out");
});

test("run writes the scan summary to $GITHUB_STEP_SUMMARY (no token/PR needed)", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(
    join(ws, "crypto.ts"),
    `import { generateKeyPairSync } from "node:crypto";\nconst kp = generateKeyPairSync("rsa", { modulusLength: 2048 });\n`,
  );
  const summaryFile = join(ws, "step-summary.md");
  writeFileSync(summaryFile, "");
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    GITHUB_STEP_SUMMARY: summaryFile,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "out.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await run(env);
  const summary = readFileSync(summaryFile, "utf8");
  assert.match(summary, /Quantum Readiness Scan/);
  assert.match(summary, /Readiness score:/);
  // The RSA finding lands in the table.
  assert.match(summary, /\| high \|/);
  assert.match(summary, /classical RSA/);
});

test("run does not throw when $GITHUB_STEP_SUMMARY is unset (local/older runner)", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(join(ws, "crypto.ts"), `const kp = generateKeyPairSync("rsa");\n`);
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "out.sarif.json",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  // No GITHUB_STEP_SUMMARY — the summary write is a silent no-op.
  await run(env);
});

test("buildPlanComment orders HNDL/confidentiality families before signatures", () => {
  const rsa = makeFinding({
    ruleId: "rsa-keygen",
    algorithm: "RSA",
    hndl: true,
    location: { file: "a.ts", line: 1 },
  });
  const ecdsa = makeFinding({
    ruleId: "ecdsa-usage",
    algorithm: "ECDSA",
    hndl: false,
    location: { file: "b.ts", line: 2 },
  });
  const md = buildPlanComment(makeResult([ecdsa, rsa]));
  assert.match(md, /PQC Migration Plan/);
  // RSA (HNDL) must appear before ECDSA (signature) in the ordered plan.
  assert.ok(md.indexOf("**RSA**") < md.indexOf("**ECDSA**"), "HNDL family listed first");
  assert.match(md, /ML-KEM|ML-DSA/);
});

test("buildPlanComment reports a clean tree when there are no findings", () => {
  const md = buildPlanComment(makeResult([], 100));
  assert.match(md, /Nothing to migrate/);
});

test("readInputs parses mode and rejects an invalid one", () => {
  assert.equal(readInputs({ INPUT_MODE: "comment-plan" }).mode, "comment-plan");
  assert.equal(readInputs({}).mode, "scan");
  assert.throws(() => readInputs({ INPUT_MODE: "bogus" }), /Invalid mode/);
});

// ---------------------------------------------------------------------------
// Mandate gate: input parsing, gate rows, failure description, summary section.
// The evaluations come from core's evaluateMandates with a pinned `now` so the
// tests stay deterministic regardless of when they run.
// ---------------------------------------------------------------------------

/** RSA finding evaluated against CNSA 2.0 at three points on its timeline. */
const rsaFinding = makeFinding();
/** Before every deadline (2026): prohibited but only `due`. */
const evDue = evaluateMandates([rsaFinding], ["cnsa-2.0"], new Date("2026-01-01"));
/** Between deprecate (2030) and disallow (2035): `deprecated`, still no failure. */
const evDeprecated = evaluateMandates([rsaFinding], ["cnsa-2.0"], new Date("2031-01-01"));
/** After the DISALLOW deadline (2035): a `violation`. */
const evViolation = evaluateMandates([rsaFinding], ["cnsa-2.0"], new Date("2036-01-01"));

test("readInputs parses mandate ids from a comma/space-separated list", () => {
  assert.deepEqual(readInputs({}).mandates, []);
  assert.deepEqual(readInputs({ INPUT_MANDATE: "cnsa-2.0" }).mandates, ["cnsa-2.0"]);
  assert.deepEqual(readInputs({ INPUT_MANDATE: "cnsa-2.0, nist-ir-8547" }).mandates, [
    "cnsa-2.0",
    "nist-ir-8547",
  ]);
  assert.deepEqual(readInputs({ INPUT_MANDATE: "cnsa-2.0 nist-ir-8547" }).mandates, [
    "cnsa-2.0",
    "nist-ir-8547",
  ]);
  assert.deepEqual(readInputs({ INPUT_MANDATE: " , " }).mandates, []);
});

test("readInputs parses lead-months and fail-now (defaults: unset / false)", () => {
  assert.equal(readInputs({}).leadMonths, undefined);
  assert.equal(readInputs({}).failNow, false);
  assert.equal(readInputs({ "INPUT_LEAD-MONTHS": "24" }).leadMonths, 24);
  assert.equal(readInputs({ "INPUT_FAIL-NOW": "true" }).failNow, true);
  assert.throws(() => readInputs({ "INPUT_LEAD-MONTHS": "soon" }), /Invalid lead-months/);
  assert.throws(() => readInputs({ "INPUT_LEAD-MONTHS": "-3" }), /Invalid lead-months/);
});

test("mandateGateRows: deadline-aware default — due/deprecated rows do not trip the gate", () => {
  assert.deepEqual(mandateGateRows(evDue), []);
  assert.deepEqual(mandateGateRows(evDeprecated), []);
  const rows = mandateGateRows(evViolation);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.status, "violation");
});

test("mandateGateRows: fail-now trips on any prohibited row; lead-months on the disallow window", () => {
  assert.equal(mandateGateRows(evDue, { failNow: true }).length, 1);
  // Disallow (2035-01-01) is ~108 months from the pinned 2026 `now`.
  assert.equal(mandateGateRows(evDue, { leadMonths: 120 }).length, 1);
  assert.deepEqual(mandateGateRows(evDue, { leadMonths: 12 }), []);
});

test("describeMandateFailure names the clause, deadline, and citation — not just a count", () => {
  const msg = describeMandateFailure(evViolation);
  // Expected dates come from the evaluation rows so the test tracks the catalog.
  const deadline = evViolation.findings[0]?.effective;
  assert.match(msg, /"CNSA 2\.0 — disallow classical PKC after 2035"/);
  assert.ok(msg.includes(`(deadline ${deadline} passed)`), `names the deadline: ${msg}`);
  assert.match(msg, /NSA Commercial National Security Algorithm Suite 2\.0/);
  assert.match(msg, /1 prohibited finding\(s\)/);
});

test("describeMandateFailure under fail-now anchors on the upcoming disallow deadline", () => {
  const msg = describeMandateFailure(evDue, { failNow: true });
  const disallow = evDue.findings[0]?.disallowEffective;
  assert.ok(msg.includes(`(disallow deadline ${disallow})`), `names the disallow date: ${msg}`);
  assert.match(msg, /NSA Commercial National Security Algorithm Suite 2\.0/);
});

test("buildMandateSection lists verdicts with clause + deadline, violations first", () => {
  // Violations sort above due rows even when pushed in the opposite order.
  const mixed: MandateEvaluation = {
    ...evViolation,
    summary: { ...evViolation.summary, due: 1 },
    findings: [...evDue.findings, ...evViolation.findings],
  };
  const md = buildMandateSection(mixed);
  assert.match(md, /### Compliance mandates/);
  assert.match(md, /`cnsa-2\.0`/);
  assert.ok(md.includes(`overdue since ${evViolation.findings[0]?.effective}`));
  assert.match(md, /CNSA 2\.0 — disallow classical PKC after 2035/);
  assert.ok(md.indexOf("🔴 violation") < md.indexOf("🟡 due"), "violation row listed first");
});

test("buildMandateSection escapes a hostile filename in the verdict table", () => {
  const hostile = makeFinding({ location: { file: "evil|name.ts", line: 1 } });
  const ev = evaluateMandates([hostile], ["cnsa-2.0"], new Date("2036-01-01"));
  const md = buildMandateSection(ev);
  assert.match(md, /evil\\\|name\.ts/);
});

test("buildSummary appends the mandate section only when an evaluation is passed", () => {
  const f = makeFinding();
  const withMandates = buildSummary(makeResult([f]), [f], "high", evDue);
  assert.match(withMandates, /### Compliance mandates/);
  assert.doesNotMatch(buildSummary(makeResult([f]), [f], "high"), /Compliance mandates/);
  // The clean-run (no blocking findings) path carries the section too.
  const clean = buildSummary(makeResult([], 100), [], "high", evDue);
  assert.match(clean, /No new quantum-vulnerable cryptography/);
  assert.match(clean, /### Compliance mandates/);
});

test("run with mandate: reports the gate in the step summary without failing before a deadline", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(
    join(ws, "crypto.ts"),
    `import { generateKeyPairSync } from "node:crypto";\nconst kp = generateKeyPairSync("rsa", { modulusLength: 2048 });\n`,
  );
  const summaryFile = join(ws, "step-summary.md");
  writeFileSync(summaryFile, "");
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    GITHUB_STEP_SUMMARY: summaryFile,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "out.sarif.json",
    INPUT_MANDATE: "cnsa-2.0",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  // Deadline-aware: the RSA finding is prohibited but its DISALLOW deadline has
  // not passed, so run() must return (a gate failure would process.exit(1)).
  await run(env);
  const summary = readFileSync(summaryFile, "utf8");
  assert.match(summary, /### Compliance mandates/);
  assert.match(summary, /`cnsa-2\.0`/);
});

test("run rejects a typo'd mandate id instead of gating against nothing", async () => {
  const ws = mkdtempSync(join(tmpdir(), "quantakrypto-ws-"));
  writeFileSync(join(ws, "crypto.ts"), `const x = 1;\n`);
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    INPUT_PATH: ".",
    INPUT_OUTPUT: "out.sarif.json",
    INPUT_MANDATE: "cnsa-2",
    "INPUT_FAIL-ON-FINDINGS": "false",
  };
  await assert.rejects(() => run(env), /unknown mandate id/);
});
