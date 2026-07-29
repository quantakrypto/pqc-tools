/**
 * Policy-as-code compliance mandates → dated, clause-named verdicts for findings.
 *
 * `CryptoPolicy` (policy.ts) classifies findings by algorithm family but is
 * date-blind. A mandate adds the missing dimension: named clauses with an effective
 * DATE ("CNSA 2.0 disallows classical public-key crypto after 2035"). The evaluator
 * compares each finding's algorithm against the selected mandates and today's date,
 * so a finding on a prohibited family reads as `due` (deadline in the future, with
 * months remaining) or `violation` (deadline reached), always naming the clause,
 * deadline, and citation. This is what turns the inventory into an enforceable,
 * mandate-mapped gate rather than a neutral list.
 *
 * Pure and deterministic (the caller supplies `now`), so it drives both qScan
 * (static) and qProbe (live) off the same `Finding[]`, and is trivially testable.
 *
 * Catalog scope: the two regimes that carry hard algorithm deadlines — CNSA 2.0 and
 * NIST IR 8547. DORA / NIS2 / PCI DSS require approved cryptography but set no
 * independent algorithm date; they inherit these timelines and are cited in docs.
 */
import type { AlgorithmFamily, Finding } from "./types.js";

/** Classical asymmetric families a post-quantum mandate deprecates (all Shor-broken). */
const CLASSICAL_PUBLIC_KEY: AlgorithmFamily[] = [
  "RSA",
  "ECDH",
  "ECDSA",
  "EdDSA",
  "DH",
  "DSA",
  "X25519",
  "X448",
  "ECIES",
];

export interface MandateRule {
  /** The named clause this rule encodes (verbatim in the gate's failure message). */
  clause: string;
  /** Algorithm families prohibited from the effective date onward. */
  prohibits: AlgorithmFamily[];
  /** ISO date (YYYY-MM-DD) the prohibition takes effect. */
  effective: string;
  /** One-line human description of the clause. */
  note: string;
}

export interface Mandate {
  id: string;
  name: string;
  authority: string;
  citation: string;
  /** When this catalog entry was last reviewed against the source. */
  asOf: string;
  rules: MandateRule[];
}

/** The bundled mandate catalog. Keyed by `--mandate <id>`. */
export const MANDATES: Record<string, Mandate> = {
  "cnsa-2.0": {
    id: "cnsa-2.0",
    name: "CNSA 2.0",
    authority: "NSA",
    citation: "NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)",
    asOf: "2026-07",
    rules: [
      {
        clause: "CNSA 2.0 — deprecate classical PKC after 2030",
        prohibits: CLASSICAL_PUBLIC_KEY,
        effective: "2030-01-01",
        note: "Classical public-key cryptography deprecated; systems should use CNSA 2.0 PQC exclusively.",
      },
      {
        clause: "CNSA 2.0 — disallow classical PKC after 2035",
        prohibits: CLASSICAL_PUBLIC_KEY,
        effective: "2035-01-01",
        note: "Classical public-key cryptography disallowed; the migration must be complete.",
      },
    ],
  },
  "nist-ir-8547": {
    id: "nist-ir-8547",
    name: "NIST IR 8547",
    authority: "NIST",
    citation: "NIST IR 8547 (Transition to Post-Quantum Cryptography Standards)",
    asOf: "2026-07",
    rules: [
      {
        clause: "NIST IR 8547 — deprecate classical PKC after 2030",
        prohibits: CLASSICAL_PUBLIC_KEY,
        effective: "2030-01-01",
        note: "112-bit-security classical public-key algorithms deprecated after 2030.",
      },
      {
        clause: "NIST IR 8547 — disallow classical PKC after 2035",
        prohibits: CLASSICAL_PUBLIC_KEY,
        effective: "2035-01-01",
        note: "Classical public-key algorithms disallowed after 2035.",
      },
    ],
  },
};

export const mandateIds = (): string[] => Object.keys(MANDATES);
export const getMandate = (id: string): Mandate | undefined => MANDATES[id];

/** A finding's status against a mandate: past a deadline, before it, or unaffected. */
export type MandateStatus = "conformant" | "due" | "violation";

export interface MandateFindingVerdict {
  ruleId: string;
  algorithm: AlgorithmFamily | "unknown";
  file: string;
  line: number;
  /** Mandate id (e.g. "cnsa-2.0"). */
  mandate: string;
  clause: string;
  /** ISO effective date of the governing (earliest applicable) clause. */
  effective: string;
  status: MandateStatus;
  /** Whole months from `now` to the deadline; negative once it has passed. */
  monthsUntil: number;
  citation: string;
}

export interface MandateEvaluation {
  /** The `now` the evaluation was computed against (ISO). */
  now: string;
  /** Mandate ids evaluated. */
  mandates: string[];
  /** Counts of findings by their worst status across the selected mandates. */
  summary: Record<MandateStatus, number>;
  /** One row per (prohibited finding × applicable mandate). */
  findings: MandateFindingVerdict[];
  /** Earliest still-future deadline among `due` findings, or null. */
  nextDeadline: string | null;
  /** True when at least one deadline has passed (a `violation` exists). */
  hasViolation: boolean;
}

const MONTH_MS = 2_629_800_000; // average month

function monthsBetween(fromMs: number, toMs: number): number {
  return Math.round((toMs - fromMs) / MONTH_MS);
}

const STATUS_RANK: Record<MandateStatus, number> = { conformant: 0, due: 1, violation: 2 };

/**
 * Evaluate findings against the selected mandates as of `now`. Unknown mandate ids
 * are ignored (the caller validates + reports them). A finding whose family no
 * mandate prohibits is `conformant` and contributes no verdict row.
 */
export function evaluateMandates(
  findings: readonly Finding[],
  mandateIdList: readonly string[],
  now: Date,
): MandateEvaluation {
  const nowMs = now.getTime();
  const selected = mandateIdList.map(getMandate).filter((m): m is Mandate => Boolean(m));

  const rows: MandateFindingVerdict[] = [];
  const perFindingWorst: MandateStatus[] = [];
  let nextDeadlineMs: number | null = null;

  for (const f of findings) {
    const algo = f.algorithm ?? "unknown";
    let worst: MandateStatus = "conformant";
    for (const mandate of selected) {
      // The applicable rules for this family, earliest deadline first. The earliest
      // is the governing clause: once it passes the finding is a violation.
      const applicable = mandate.rules
        .filter((r) => r.prohibits.includes(algo as AlgorithmFamily))
        .sort((a, b) => a.effective.localeCompare(b.effective));
      if (applicable.length === 0) continue;
      const governing = applicable[0];
      const effMs = new Date(governing.effective).getTime();
      const status: MandateStatus = nowMs >= effMs ? "violation" : "due";
      if (status === "due" && (nextDeadlineMs === null || effMs < nextDeadlineMs))
        nextDeadlineMs = effMs;
      if (STATUS_RANK[status] > STATUS_RANK[worst]) worst = status;
      rows.push({
        ruleId: f.ruleId,
        algorithm: algo,
        file: f.location.file,
        line: f.location.line,
        mandate: mandate.id,
        clause: governing.clause,
        effective: governing.effective,
        status,
        monthsUntil: monthsBetween(nowMs, effMs),
        citation: mandate.citation,
      });
    }
    perFindingWorst.push(worst);
  }

  const summary: Record<MandateStatus, number> = { conformant: 0, due: 0, violation: 0 };
  for (const s of perFindingWorst) summary[s]++;

  return {
    now: now.toISOString(),
    mandates: selected.map((m) => m.id),
    summary,
    findings: rows,
    nextDeadline:
      nextDeadlineMs !== null ? new Date(nextDeadlineMs).toISOString().slice(0, 10) : null,
    hasViolation: summary.violation > 0,
  };
}

export interface MandateGateOptions {
  /** Fail when a deadline is within this many months (early enforcement). */
  leadMonths?: number;
  /** Fail on any mandate-prohibited finding regardless of the deadline. */
  failNow?: boolean;
}

/**
 * The gate decision under the "deadline-aware" default: fail only once a deadline
 * has passed. `leadMonths` fails early when a deadline is within the window;
 * `failNow` fails on any prohibited finding immediately.
 */
export function mandateGateFails(ev: MandateEvaluation, opts: MandateGateOptions = {}): boolean {
  if (ev.hasViolation) return true;
  if (opts.failNow) return ev.findings.length > 0;
  if (opts.leadMonths !== undefined) {
    return ev.findings.some((v) => v.status === "due" && v.monthsUntil <= opts.leadMonths!);
  }
  return false;
}
