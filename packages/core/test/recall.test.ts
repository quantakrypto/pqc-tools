/**
 * Recall (false-negative depth) benchmark.
 *
 * A companion to the tuned detection benchmark (`benchmark.test.ts`), which
 * scores precision/recall on a small, curated corpus and gates it at 1.000. That
 * corpus is, by design, tuned to the detectors' documented lexical contract — so
 * it says nothing about **real-world recall over messy code** (its own caveats
 * admit this).
 *
 * This benchmark fills that gap. The corpus under `benchmark/recall/` is
 * deliberately built to be *hard*: real, idiomatic crypto usage across all eight
 * supported languages, including aliased imports, wrapper indirection, uncommon
 * APIs, config/manifest crypto, and adversarially-formatted call sites. Its
 * ground truth (`recall-labels.json`) is labeled by **what the crypto truly is**,
 * independent of what the detectors happen to match — so a missed detection is a
 * genuine false negative, and this number is an honest lower bound on recall.
 *
 * Metric: DETECTION recall. For each expected crypto occurrence in a file we ask
 * "did the scanner surface *any* finding for it?" A finding whose family the
 * scanner could not classify (`algorithm: unknown`, e.g. a one-shot sign or a
 * JWT alg) still counts as a detection — the crypto was surfaced to the user,
 * which is what recall measures; family-classification accuracy is a separate,
 * stricter concern. Matching is greedy multiset per file, families only (not
 * ruleId), so it is robust to which rule fired.
 *
 * Unlike the tuned benchmark this is NOT gated at 1.000 — real-world recall < 1
 * is expected, and the false negatives it prints are the actionable output. The
 * floor assertion is a regression guard set just below the measured value. Set
 * `RECALL_DEBUG=1` to dump per-file found families for calibration.
 *
 * See docs/validation/recall-benchmark.md.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { scan } from "../src/index.js";
import type { Finding } from "../src/index.js";

/** Quantum-vulnerable crypto families the corpus labels. */
type Family =
  | "RSA"
  | "DH"
  | "ECDH"
  | "ECDSA"
  | "DSA"
  | "EDDSA"
  | "X25519"
  | "X448"
  | "SECP256K1"
  | "TLS"
  | "SSH"
  | "DEP";

interface Expected {
  family: Family;
  difficulty: "canonical" | "aliased" | "uncommon" | "config" | "adversarial";
  note: string;
}
interface LabelEntry {
  language: string;
  expected: Expected[];
}
type Labels = Record<string, LabelEntry>;

/** Detection wildcard: the scanner flagged crypto but could not classify the family. */
const WILDCARD = "*";
/** Structural families have their own dedicated rules; a wildcard must NOT satisfy them. */
const STRUCTURAL = new Set<Family>(["TLS", "SSH", "DEP"]);

const RECALL_DIR = fileURLToPath(new URL("./benchmark/recall", import.meta.url));
const LABELS_PATH = fileURLToPath(new URL("./benchmark/recall-labels.json", import.meta.url));

/**
 * Map a scanner finding to a coarse crypto family. Structural families are keyed
 * off the ruleId (they carry no `algorithm`); everything else off the normalized
 * `algorithm`, with an unclassified/`unknown` finding collapsing to the wildcard.
 */
function findingFamily(f: Finding): string {
  const id = f.ruleId.toLowerCase();
  if (id.includes("tls")) return "TLS";
  // Only host-key findings are the structural SSH family; ssh-kex-classical
  // carries a real algorithm (DH/ECDH/X25519) and is mapped off that below.
  if (id === "ssh-public-key") return "SSH";
  if (id.includes("dep") || id.includes("dependency")) return "DEP";
  if (id.includes("secp256k1")) return "SECP256K1";
  const a = (f.algorithm ?? "").toUpperCase();
  switch (a) {
    case "RSA":
    case "DH":
    case "ECDH":
    case "ECDSA":
    case "DSA":
    case "X25519":
    case "X448":
      return a;
    case "EDDSA":
      return "EDDSA";
    default:
      // "unknown", "" or anything unrecognized: the crypto was flagged but not classified.
      return WILDCARD;
  }
}

interface Tally {
  tp: number;
  fn: number;
}
function tallyFor(map: Map<string, Tally>, key: string): Tally {
  let t = map.get(key);
  if (!t) {
    t = { tp: 0, fn: 0 };
    map.set(key, t);
  }
  return t;
}
function recall(t: Tally): number {
  return t.tp + t.fn === 0 ? 1 : t.tp / (t.tp + t.fn);
}

function groupByFile(findings: readonly Finding[]): Map<string, string[]> {
  const byFile = new Map<string, string[]>();
  for (const f of findings) {
    // scan() reports paths relative to its root; labels are keyed with the
    // `recall/` prefix, so re-add it.
    const key = `recall/${f.location.file}`;
    const list = byFile.get(key) ?? [];
    list.push(findingFamily(f));
    byFile.set(key, list);
  }
  return byFile;
}

interface ScoreResult {
  overall: Tally;
  byLanguage: Map<string, Tally>;
  byDifficulty: Map<string, Tally>;
  falseNegatives: string[];
  wildcardHits: number;
  totalExpected: number;
  languages: Set<string>;
}

function scoreRecall(labels: Labels, byFile: Map<string, string[]>): ScoreResult {
  const overall: Tally = { tp: 0, fn: 0 };
  const byLanguage = new Map<string, Tally>();
  const byDifficulty = new Map<string, Tally>();
  const falseNegatives: string[] = [];
  const languages = new Set<string>();
  let wildcardHits = 0;
  let totalExpected = 0;

  for (const [file, entry] of Object.entries(labels)) {
    if (file.startsWith("$")) continue;
    languages.add(entry.language);
    const pool = [...(byFile.get(file) ?? [])];
    const lang = tallyFor(byLanguage, entry.language);
    totalExpected += entry.expected.length;

    const award = (e: Expected, viaWildcard: boolean): void => {
      overall.tp += 1;
      lang.tp += 1;
      tallyFor(byDifficulty, e.difficulty).tp += 1;
      if (viaWildcard) wildcardHits += 1;
    };
    const miss = (e: Expected): void => {
      overall.fn += 1;
      lang.fn += 1;
      tallyFor(byDifficulty, e.difficulty).fn += 1;
      falseNegatives.push(`${file}: ${e.family} [${e.difficulty}] — ${e.note}`);
    };

    // Match in order of specificity so a permissive family never steals a
    // finding a stricter expected needed.
    // Pass 1 — exact family.
    let rem = entry.expected.filter((e) => {
      const i = pool.indexOf(e.family);
      if (i >= 0) {
        pool.splice(i, 1);
        award(e, false);
        return false;
      }
      return true;
    });
    // Pass 2 — curve relaxation: a secp256k1 use caught under the generic EC family.
    rem = rem.filter((e) => {
      if (e.family !== "SECP256K1") return true;
      const i = pool.findIndex((ff) => ff === "ECDSA" || ff === "ECDH");
      if (i >= 0) {
        pool.splice(i, 1);
        award(e, false);
        return false;
      }
      return true;
    });
    // Pass 3 — an unclassified detection (algorithm `unknown`) counts for
    // algorithm families, but not for the structural ones (TLS/SSH/DEP).
    for (const e of rem) {
      const i = STRUCTURAL.has(e.family) ? -1 : pool.indexOf(WILDCARD);
      if (i >= 0) {
        pool.splice(i, 1);
        award(e, true);
      } else {
        miss(e);
      }
    }
  }

  return {
    overall,
    byLanguage,
    byDifficulty,
    falseNegatives,
    wildcardHits,
    totalExpected,
    languages,
  };
}

function printReport(r: ScoreResult): void {
  const lines: string[] = [];
  lines.push("");
  lines.push("Recall (false-negative depth) benchmark — detection recall on real-world idioms");
  lines.push("─".repeat(72));
  lines.push("by language        TP   FN   recall");
  lines.push("─".repeat(72));
  for (const [name, t] of [...r.byLanguage.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    lines.push(
      `${name.padEnd(16)} ${String(t.tp).padStart(4)} ${String(t.fn).padStart(4)}   ${recall(t).toFixed(3)}`,
    );
  }
  lines.push("─".repeat(72));
  lines.push("by difficulty      TP   FN   recall");
  lines.push("─".repeat(72));
  const order = ["canonical", "aliased", "uncommon", "config", "adversarial"];
  for (const d of order) {
    const t = r.byDifficulty.get(d);
    if (!t) continue;
    lines.push(
      `${d.padEnd(16)} ${String(t.tp).padStart(4)} ${String(t.fn).padStart(4)}   ${recall(t).toFixed(3)}`,
    );
  }
  lines.push("─".repeat(72));
  lines.push(
    `OVERALL          ${String(r.overall.tp).padStart(4)} ${String(r.overall.fn).padStart(4)}   ` +
      `${recall(r.overall).toFixed(3)}   ` +
      `(${r.totalExpected} expected; ${r.wildcardHits} caught unclassified)`,
  );
  lines.push("─".repeat(72));
  if (r.falseNegatives.length > 0) {
    lines.push(`False negatives (${r.falseNegatives.length}) — real detector gaps to close:`);
    for (const fn of [...r.falseNegatives].sort()) lines.push(`  - ${fn}`);
  } else {
    lines.push("No false negatives.");
  }
  console.log(lines.join("\n"));
}

async function loadLabels(): Promise<Labels> {
  return JSON.parse(await readFile(LABELS_PATH, "utf8")) as Labels;
}

/**
 * Overall floor, set just below the measured recall so a real regression fails
 * the build but the expected (documented) false negatives do not. Update when the
 * corpus or detectors change, per docs/validation/recall-benchmark.md.
 */
const RECALL_FLOOR = 0.78; // measured 0.847; floor sits just below so real regressions fail.

/**
 * Per-language floors. The overall floor alone hides a single-language regression:
 * one language can collapse while the others hold the aggregate above 0.78. Each
 * language therefore carries its own floor, set ~0.06–0.10 below its measured
 * recall so a 2-occurrence drop in ANY language fails CI while a single borderline
 * flip does not. Every supported language MUST appear here (a new language without
 * a floor fails loudly below), so detector parity stays a per-language commitment.
 */
const PER_LANGUAGE_FLOOR: Readonly<Record<string, number>> = {
  c: 0.85, // measured 0.933
  csharp: 0.75, // measured 0.833
  go: 0.68, // measured 0.760
  java: 0.58, // measured 0.667
  js: 0.88, // measured 0.955
  python: 0.9, // measured 1.000
  ruby: 0.72, // measured 0.800
  rust: 0.8, // measured 0.889
};

test("recall benchmark: detection recall over real-world idioms", async () => {
  const labels = await loadLabels();
  const result = await scan({ root: RECALL_DIR, noDefaultIgnores: true });

  if (process.env.RECALL_DEBUG) {
    const byFile = new Map<string, Finding[]>();
    for (const f of result.findings) {
      const k = `recall/${f.location.file}`;
      const l = byFile.get(k) ?? [];
      l.push(f);
      byFile.set(k, l);
    }
    for (const [file, fs] of [...byFile.entries()].sort()) {
      console.log(
        `DEBUG ${file}: ` +
          fs.map((f) => `${f.ruleId}=${f.algorithm ?? "null"}(${findingFamily(f)})`).join(", "),
      );
    }
  }

  const report = scoreRecall(labels, groupByFile(result.findings));
  printReport(report);

  // The corpus must stay non-trivial and cover every supported language.
  assert.ok(report.totalExpected >= 60, `recall corpus shrank: ${report.totalExpected} < 60`);
  assert.ok(report.languages.size >= 8, `missing languages: only ${report.languages.size}/8`);

  const r = recall(report.overall);
  assert.ok(r >= RECALL_FLOOR, `recall regressed: ${r.toFixed(4)} < ${RECALL_FLOOR}`);

  // Per-language floors: a single language must not silently collapse behind a
  // healthy aggregate. Every measured language must have a declared floor and
  // clear it.
  for (const [lang, tally] of report.byLanguage) {
    const floor = PER_LANGUAGE_FLOOR[lang];
    assert.ok(
      floor !== undefined,
      `language "${lang}" has no PER_LANGUAGE_FLOOR — add one (measured ${recall(tally).toFixed(3)}).`,
    );
    const lr = recall(tally);
    assert.ok(lr >= floor, `recall regressed for ${lang}: ${lr.toFixed(4)} < ${floor}`);
  }
});
