/**
 * Detection benchmark + regression guard.
 *
 * Runs the full {@link scan} pipeline over a small, hand-labeled corpus
 * (`test/benchmark/corpus/`) and scores the findings against the ground-truth
 * manifest (`test/benchmark/labels.json`). It computes precision / recall / F1
 * overall and per category, prints a compact table, and asserts thresholds that
 * sit just below the current measured values so the suite catches detector
 * regressions without being brittle.
 *
 * Honesty policy: the negative set is treated strictly — any finding on a
 * negative bait file is a false positive. Exactly one false positive is KNOWN
 * and documented (a comment containing `createECDH (` that the lexical detector
 * cannot distinguish from code); it lives in `negative/crypto-words-in-comment.ts`
 * and is asserted explicitly. Any OTHER false positive, or any false negative,
 * fails the build. See docs/validation/detection-benchmark.md.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { scan } from "../src/index.js";
import type { Finding } from "../src/index.js";

/** One expected finding in the ground-truth manifest. */
interface ExpectedFinding {
  ruleId: string;
  /** Classical family, or null for non-algorithm findings (e.g. TLS config). */
  algorithm: string | null;
  hndl: boolean;
}

/** A labeled corpus entry. `expected: []` marks a negative / false-positive bait. */
interface LabelEntry {
  category: string;
  expected: ExpectedFinding[];
}

type Labels = Record<string, LabelEntry | string[]>;

/** Aggregate confusion-matrix counts. */
interface Counts {
  tp: number;
  fp: number;
  fn: number;
}

interface ScoreReport {
  overall: Counts;
  byCategory: Map<string, Counts>;
  falsePositives: string[];
  falseNegatives: string[];
}

const CORPUS_DIR = fileURLToPath(new URL("./benchmark/corpus", import.meta.url));
const LABELS_PATH = fileURLToPath(new URL("./benchmark/labels.json", import.meta.url));

/** The one documented, accepted false positive (see module doc + the markdown). */
const KNOWN_FALSE_POSITIVE = "negative/crypto-words-in-comment.ts: node-crypto-ecdh|ECDH|true";

/** Canonical key for matching expected vs. actual findings as multiset members. */
function findingKey(ruleId: string, algorithm: string | null, hndl: boolean): string {
  return `${ruleId}|${algorithm ?? "null"}|${hndl}`;
}

/** Group a flat findings list by its (corpus-relative) file path. */
function groupByFile(findings: readonly Finding[]): Map<string, Finding[]> {
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byFile.get(f.location.file) ?? [];
    list.push(f);
    byFile.set(f.location.file, list);
  }
  return byFile;
}

/** Initialise / fetch the per-category counter. */
function counterFor(map: Map<string, Counts>, category: string): Counts {
  let c = map.get(category);
  if (!c) {
    c = { tp: 0, fp: 0, fn: 0 };
    map.set(category, c);
  }
  return c;
}

/**
 * Score actual findings against labels using greedy multiset matching per file:
 * each expected tuple is matched at most once; unmatched actuals are false
 * positives and unmatched expecteds are false negatives.
 */
function score(labels: Labels, byFile: Map<string, Finding[]>): ScoreReport {
  const overall: Counts = { tp: 0, fp: 0, fn: 0 };
  const byCategory = new Map<string, Counts>();
  const falsePositives: string[] = [];
  const falseNegatives: string[] = [];

  for (const [file, raw] of Object.entries(labels)) {
    if (file.startsWith("$")) continue; // skip the "$comment" metadata key
    const entry = raw as LabelEntry;
    const cat = counterFor(byCategory, entry.category);

    const expectedPool = entry.expected.map((e) => findingKey(e.ruleId, e.algorithm, e.hndl));
    const actual = (byFile.get(file) ?? []).map((f) =>
      findingKey(f.ruleId, f.algorithm ?? null, f.hndl),
    );

    for (const a of actual) {
      const i = expectedPool.indexOf(a);
      if (i >= 0) {
        expectedPool.splice(i, 1);
        overall.tp += 1;
        cat.tp += 1;
      } else {
        overall.fp += 1;
        cat.fp += 1;
        falsePositives.push(`${file}: ${a}`);
      }
    }
    for (const leftover of expectedPool) {
      overall.fn += 1;
      cat.fn += 1;
      falseNegatives.push(`${file}: ${leftover}`);
    }
  }

  return { overall, byCategory, falsePositives, falseNegatives };
}

function precision(c: Counts): number {
  return c.tp + c.fp === 0 ? 1 : c.tp / (c.tp + c.fp);
}

function recall(c: Counts): number {
  return c.tp + c.fn === 0 ? 1 : c.tp / (c.tp + c.fn);
}

function f1(c: Counts): number {
  const p = precision(c);
  const r = recall(c);
  return p + r === 0 ? 0 : (2 * p * r) / (p + r);
}

/** Pretty-print the scorecard so it shows up in `node --test` output. */
function printReport(report: ScoreReport): void {
  const { overall } = report;
  const lines: string[] = [];
  lines.push("");
  lines.push("Detection benchmark — precision / recall / F1");
  lines.push("─".repeat(64));
  lines.push("category            TP  FP  FN   prec    rec     F1");
  lines.push("─".repeat(64));
  const cats = [...report.byCategory.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  for (const [name, c] of cats) {
    lines.push(
      `${name.padEnd(18)} ${String(c.tp).padStart(3)} ${String(c.fp).padStart(3)} ` +
        `${String(c.fn).padStart(3)}  ${precision(c).toFixed(3)}  ${recall(c).toFixed(3)}  ` +
        `${f1(c).toFixed(3)}`,
    );
  }
  lines.push("─".repeat(64));
  lines.push(
    `${"OVERALL".padEnd(18)} ${String(overall.tp).padStart(3)} ${String(overall.fp).padStart(3)} ` +
      `${String(overall.fn).padStart(3)}  ${precision(overall).toFixed(3)}  ` +
      `${recall(overall).toFixed(3)}  ${f1(overall).toFixed(3)}`,
  );
  lines.push("─".repeat(64));
  if (report.falsePositives.length > 0) {
    lines.push(`False positives (${report.falsePositives.length}):`);
    for (const fp of report.falsePositives) lines.push(`  - ${fp}`);
  }
  if (report.falseNegatives.length > 0) {
    lines.push(`False negatives (${report.falseNegatives.length}):`);
    for (const fn of report.falseNegatives) lines.push(`  - ${fn}`);
  }
  console.log(lines.join("\n"));
}

async function loadLabels(): Promise<Labels> {
  return JSON.parse(await readFile(LABELS_PATH, "utf8")) as Labels;
}

test("detection benchmark: scores against the labeled corpus", async () => {
  const labels = await loadLabels();
  // noDefaultIgnores keeps any future nested fixture dirs in scope; the corpus
  // has none today, but it makes the scan independent of the default ignore list.
  const result = await scan({ root: CORPUS_DIR, noDefaultIgnores: true });
  const report = score(labels, groupByFile(result.findings));
  printReport(report);

  const { overall } = report;
  const p = precision(overall);
  const r = recall(overall);
  const f = f1(overall);

  // Sanity: the corpus actually exercised the scanner.
  assert.ok(overall.tp >= 30, `expected >=30 true positives, got ${overall.tp}`);

  // Regression guards — thresholds sit JUST BELOW the current measured values
  // (measured: precision 0.969, recall 1.000, F1 0.984).
  assert.ok(p >= 0.95, `precision regressed: ${p.toFixed(4)} < 0.95`);
  assert.ok(r >= 0.99, `recall regressed: ${r.toFixed(4)} < 0.99`);
  assert.ok(f >= 0.97, `F1 regressed: ${f.toFixed(4)} < 0.97`);
});

test("detection benchmark: recall is perfect (no false negatives)", async () => {
  const labels = await loadLabels();
  const result = await scan({ root: CORPUS_DIR, noDefaultIgnores: true });
  const report = score(labels, groupByFile(result.findings));

  // Every expected finding must be produced. A missed detection is a hard fail.
  assert.deepEqual(
    report.falseNegatives,
    [],
    `false negatives detected (recall regression): ${report.falseNegatives.join("; ")}`,
  );
  assert.equal(report.overall.fn, 0);
});

test("detection benchmark: negative set is strict (only the known FP allowed)", async () => {
  const labels = await loadLabels();
  const result = await scan({ root: CORPUS_DIR, noDefaultIgnores: true });
  const report = score(labels, groupByFile(result.findings));

  // Exactly one false positive is documented and accepted. Any new false
  // positive (or removal of the known one without updating labels) fails.
  assert.deepEqual(
    report.falsePositives,
    [KNOWN_FALSE_POSITIVE],
    "negative-set false positives changed — update labels.json and the validation doc",
  );
});
