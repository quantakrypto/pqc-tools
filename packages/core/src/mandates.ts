/**
 * Policy-as-code compliance mandates → dated, clause-named verdicts for findings.
 *
 * `CryptoPolicy` (policy.ts) classifies findings by algorithm family but is
 * date-blind. A mandate adds the missing dimension: named clauses with an effective
 * DATE ("CNSA 2.0 disallows classical public-key crypto after 2035"). The evaluator
 * compares each finding's algorithm against the selected mandates and today's date,
 * so a finding on a prohibited family reads as `due` (every deadline still ahead),
 * `deprecated` (the DEPRECATE deadline has passed — a warning), or `violation` (the
 * DISALLOW deadline has passed — a failure), always naming the governing clause,
 * deadline, and citation. This is what turns the inventory into an enforceable,
 * mandate-mapped gate rather than a neutral list.
 *
 * Pure and deterministic (the caller supplies `now`), so it is trivially testable.
 * qScan consumes it today for the `--mandate` gate; because it operates on the
 * shared `Finding[]`, qProbe or the GitHub Action can reuse it unchanged.
 *
 * Catalog scope: the two regimes that carry hard algorithm deadlines — CNSA 2.0 and
 * NIST IR 8547. DORA / NIS2 / PCI DSS require approved cryptography but set no
 * independent algorithm date; they inherit these timelines and are cited in docs.
 */
import type { AlgorithmFamily, Finding } from "./types.js";
import { PQC_STANDARDS } from "./standards.js";
import { verdictForAlgorithm } from "./policy.js";
import type { CryptoPolicy, PolicyVerdict } from "./policy.js";

/**
 * All Shor-broken classical asymmetric families — the mandate's SCOPE. A finding
 * on one of these is adjudicated against the selected mandates; findings on
 * anything else (hashes, RNG, dependency, or TLS-configuration findings) are out
 * of scope for a PQC-asymmetric mandate and are tallied as `notInScope` instead
 * of inflating the conformant count.
 */
const CLASSICAL_PUBLIC_KEY: readonly AlgorithmFamily[] = [
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

/**
 * The PROHIBITED subset the dated clauses apply to. X25519 and X448 are
 * deliberately excluded: they are the classical half of the recommended hybrid
 * key exchange (X25519MLKEM768 — permitted and recommended under the NIST
 * profile), and a static scan cannot distinguish a standalone exchange from the
 * hybrid's classical leg. Prohibiting them would false-positive exactly the orgs
 * that hybridized correctly, so they stay in scope but read `conformant`.
 */
const PROHIBITED_FAMILIES: readonly AlgorithmFamily[] = CLASSICAL_PUBLIC_KEY.filter(
  (family) => family !== "X25519" && family !== "X448",
);

/**
 * Effective dates derived from the standards source of truth
 * (`PQC_STANDARDS.transitionTimeline`), so a quarterly standards update moves the
 * mandate deadlines automatically (test/standards.test.ts asserts they agree).
 *
 * Boundary choice: "deprecate AFTER 2030" leaves the whole stated year permitted,
 * so each clause takes effect on the LAST day of its year (`YYYY-12-31`) —
 * conservative by a single day, unlike `YYYY-01-01`, which would bite roughly a
 * year early.
 */
const { deprecateAfter, disallowAfter } = PQC_STANDARDS.transitionTimeline;
const DEPRECATE_EFFECTIVE = `${deprecateAfter}-12-31`;
const DISALLOW_EFFECTIVE = `${disallowAfter}-12-31`;

/** Which enforcement tier a clause encodes: warn (`deprecate`) or fail (`disallow`). */
export type MandateRuleTier = "deprecate" | "disallow";

export interface MandateRule {
  /** The named clause this rule encodes (verbatim in the gate's failure message). */
  clause: string;
  /** Enforcement tier: a passed `deprecate` date warns; a passed `disallow` date fails. */
  tier: MandateRuleTier;
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
        clause: `CNSA 2.0 — deprecate classical PKC after ${deprecateAfter}`,
        tier: "deprecate",
        prohibits: [...PROHIBITED_FAMILIES],
        effective: DEPRECATE_EFFECTIVE,
        note: "Classical public-key cryptography deprecated; systems should use CNSA 2.0 PQC exclusively.",
      },
      {
        clause: `CNSA 2.0 — disallow classical PKC after ${disallowAfter}`,
        tier: "disallow",
        prohibits: [...PROHIBITED_FAMILIES],
        effective: DISALLOW_EFFECTIVE,
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
        clause: `NIST IR 8547 — deprecate classical PKC after ${deprecateAfter}`,
        tier: "deprecate",
        prohibits: [...PROHIBITED_FAMILIES],
        effective: DEPRECATE_EFFECTIVE,
        note: `112-bit-security classical public-key algorithms deprecated after ${deprecateAfter}.`,
      },
      {
        clause: `NIST IR 8547 — disallow classical PKC after ${disallowAfter}`,
        tier: "disallow",
        prohibits: [...PROHIBITED_FAMILIES],
        effective: DISALLOW_EFFECTIVE,
        note: `Classical public-key algorithms disallowed after ${disallowAfter}.`,
      },
    ],
  },
};

export const mandateIds = (): string[] => Object.keys(MANDATES);
export const getMandate = (id: string): Mandate | undefined => MANDATES[id];

/**
 * Validate mandate ids loudly, matching `parseCryptoPolicy`'s fail-loud
 * convention: a mistyped id must never silently evaluate to an empty gate.
 * Throws an `Error` naming every unknown id and the known catalog.
 * `evaluateMandates` itself stays lenient (unknown ids are skipped) so callers
 * decide where to fail.
 */
export function assertKnownMandates(ids: readonly string[]): void {
  const unknown = ids.filter((id) => !MANDATES[id]);
  if (unknown.length > 0) {
    throw new Error(
      `unknown mandate id(s): ${unknown.join(", ")}; known mandates: ${mandateIds().join(", ")}`,
    );
  }
}

/**
 * A finding's status against a mandate, worst last:
 * - `conformant` — in scope (classical asymmetric) but prohibited by no selected
 *   clause (e.g. X25519 as the presumed hybrid leg).
 * - `due` — prohibited, with every deadline still ahead.
 * - `deprecated` — the DEPRECATE deadline has passed; a warning, not a failure.
 * - `violation` — the DISALLOW deadline has passed; fails the default gate.
 */
export type MandateStatus = "conformant" | "due" | "deprecated" | "violation";

export interface MandateFindingVerdict {
  ruleId: string;
  algorithm: AlgorithmFamily | "unknown";
  file: string;
  line: number;
  /** Mandate id (e.g. "cnsa-2.0"). */
  mandate: string;
  /**
   * The governing clause: the next upcoming clause when `due`, the passed
   * DEPRECATE clause when `deprecated`, the passed DISALLOW clause on `violation`.
   */
  clause: string;
  /** ISO effective date of the governing clause. */
  effective: string;
  status: MandateStatus;
  /** Whole months from `now` to the governing deadline; negative once it has passed. */
  monthsUntil: number;
  /**
   * ISO effective date of this mandate's DISALLOW clause for the family, or null
   * when the mandate carries none. The gate's `leadMonths` measures against this.
   */
  disallowEffective: string | null;
  /** Whole months from `now` to `disallowEffective`; null when there is none. */
  monthsUntilDisallow: number | null;
  citation: string;
  /**
   * The org cryptography policy's verdict on this algorithm family when a policy
   * was composed in via {@link evaluateMandates}' `policy` argument, else null.
   * Purely informational — it records the org's own stance next to the mandate's
   * dated clause so a machine-readable report shows both.
   */
  policyVerdict: PolicyVerdict | null;
  /**
   * True when the org policy EXPLICITLY permits or is transitioning this family —
   * an owned, tracked decision. Acknowledged findings are exempt from the EARLY
   * gates (`failNow` / `leadMonths`); a passed DISALLOW deadline (`violation`)
   * still fails regardless, because an org cannot self-exempt from a dated legal
   * disallow. `false` when no policy was supplied.
   */
  acknowledged: boolean;
}

export interface MandateEvaluation {
  /** The `now` the evaluation was computed against (ISO). */
  now: string;
  /** Mandate ids evaluated. */
  mandates: string[];
  /**
   * Counts of IN-SCOPE findings (classical asymmetric families) by their worst
   * status across the selected mandates. Out-of-scope findings are excluded so
   * the conformant count is an honest statement about asymmetric crypto only.
   */
  summary: Record<MandateStatus, number>;
  /**
   * Findings outside the mandate's scope (hashes, RNG, dependency, TLS-config…),
   * which a PQC-asymmetric mandate does not adjudicate.
   */
  notInScope: number;
  /** One row per (prohibited finding × applicable mandate). */
  findings: MandateFindingVerdict[];
  /** Earliest still-future deadline across non-violation rows, or null. */
  nextDeadline: string | null;
  /** True when at least one DISALLOW deadline has passed (a `violation` exists). */
  hasViolation: boolean;
  /** Name of the org policy composed in via `policy`, or null when none was supplied. */
  policyName: string | null;
  /**
   * How many distinct prohibited FINDINGS the org policy explicitly acknowledged
   * (family listed as `permitted` or `inTransition`) — counted per finding, not
   * per verdict row, so a family prohibited by two mandates counts once, matching
   * the per-finding `summary`. 0 when no policy was supplied.
   */
  acknowledged: number;
}

const MONTH_MS = 2_629_800_000; // average month

function monthsBetween(fromMs: number, toMs: number): number {
  return Math.round((toMs - fromMs) / MONTH_MS);
}

const STATUS_RANK: Record<MandateStatus, number> = {
  conformant: 0,
  due: 1,
  deprecated: 2,
  violation: 3,
};

/**
 * True when the org policy EXPLICITLY accepts a family — listed in `permitted`
 * (an owned exception) or `inTransition` (a tracked migration). A `prohibited`
 * family or one covered only by the policy's default fallback is NOT
 * acknowledged: silence is not consent, so an unnamed family never earns a gate
 * exemption.
 *
 * `prohibited` takes precedence, matching {@link verdictForAlgorithm}: a policy
 * that lists a family in BOTH `prohibited` and `permitted` (a plausible merge of
 * two policy fragments) resolves to `violation`, and must not then be silently
 * acknowledged away — that would produce a self-contradictory verdict (verdict
 * `violation`, yet exempt from the gate).
 */
function policyAcknowledges(algo: AlgorithmFamily, policy: CryptoPolicy): boolean {
  if (policy.prohibited?.includes(algo)) return false;
  return Boolean(policy.permitted?.includes(algo) || policy.inTransition?.includes(algo));
}

/**
 * Evaluate findings against the selected mandates as of `now`. Unknown mandate
 * ids are ignored — callers validate up front with {@link assertKnownMandates}.
 * A finding outside the classical-asymmetric scope is counted in `notInScope`;
 * an in-scope finding no selected mandate prohibits is `conformant`. Neither
 * contributes a verdict row.
 *
 * When an org `policy` is supplied (the `--policy` composition), every verdict
 * row is annotated with the org's own `policyVerdict` and an `acknowledged` flag
 * (family explicitly permitted / in-transition). Acknowledgement is purely
 * additive here — it changes no status — but {@link mandateGateFails} honours it
 * to keep the early gates from double-flagging crypto the org is knowingly,
 * traceably managing. A passed DISALLOW deadline is never acknowledgeable away.
 */
export function evaluateMandates(
  findings: readonly Finding[],
  mandateIdList: readonly string[],
  now: Date,
  policy?: CryptoPolicy,
): MandateEvaluation {
  // A compliance verdict is as-of a DAY: the clauses take effect on date
  // boundaries (YYYY-MM-DD), so the exact clock time carries no compliance
  // meaning. Pin `now` to UTC midnight of its date before any arithmetic — this
  // makes the whole evaluation (statuses AND the monthsUntil / monthsUntilDisallow
  // counters) identical for any two runs on the same day, which is what keeps the
  // attested evidence hash reproducible per commit per day. Truncating changes no
  // status: every `effective` date is itself UTC-midnight, so `nowMs >= effMs` has
  // the same truth value at midnight as at any other time that day.
  const nowMs = Date.parse(`${now.toISOString().slice(0, 10)}T00:00:00.000Z`);
  const nowIso = new Date(nowMs).toISOString();
  const selected = mandateIdList.map(getMandate).filter((m): m is Mandate => Boolean(m));

  const rows: MandateFindingVerdict[] = [];
  const perFindingWorst: MandateStatus[] = [];
  let notInScope = 0;
  let acknowledged = 0;
  let nextDeadlineMs: number | null = null;

  for (const f of findings) {
    const algo = f.algorithm ?? "unknown";
    if (!CLASSICAL_PUBLIC_KEY.includes(algo as AlgorithmFamily)) {
      notInScope++;
      continue;
    }
    let worst: MandateStatus = "conformant";
    // Acknowledgement is a property of the FAMILY (fixed for this finding), so it
    // is computed once here and stamped on every row. The tally counts distinct
    // acknowledged findings (not rows), so one family under two mandates is one
    // acknowledgement, matching the per-finding status counts in `summary`.
    const family = algo as AlgorithmFamily;
    const isAcknowledged = policy ? policyAcknowledges(family, policy) : false;
    let producedRow = false;
    for (const mandate of selected) {
      // The applicable clauses for this family, earliest deadline first.
      const applicable = mandate.rules
        .filter((r) => r.prohibits.includes(algo as AlgorithmFamily))
        .sort((a, b) => a.effective.localeCompare(b.effective));
      if (applicable.length === 0) continue;
      producedRow = true;

      // Tier the clauses so both stay live: a passed DISALLOW clause is a
      // violation; a passed DEPRECATE clause (disallow still ahead) is the
      // deprecated warning tier; otherwise the finding is due against the next
      // upcoming clause.
      const passed = applicable.filter((r) => nowMs >= new Date(r.effective).getTime());
      const passedDisallow = passed.filter((r) => r.tier === "disallow");
      let status: MandateStatus;
      let governing: MandateRule;
      if (passedDisallow.length > 0) {
        status = "violation";
        governing = passedDisallow[0];
      } else if (passed.length > 0) {
        status = "deprecated";
        governing = passed[passed.length - 1];
      } else {
        status = "due";
        governing = applicable[0];
      }

      // The disallow clause (earliest, if several) anchors `leadMonths`.
      const disallowRule = applicable.find((r) => r.tier === "disallow") ?? null;
      const disallowMs = disallowRule ? new Date(disallowRule.effective).getTime() : null;

      if (status !== "violation") {
        for (const r of applicable) {
          const effMs = new Date(r.effective).getTime();
          if (effMs > nowMs && (nextDeadlineMs === null || effMs < nextDeadlineMs))
            nextDeadlineMs = effMs;
        }
      }
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
        monthsUntil: monthsBetween(nowMs, new Date(governing.effective).getTime()),
        disallowEffective: disallowRule ? disallowRule.effective : null,
        monthsUntilDisallow: disallowMs !== null ? monthsBetween(nowMs, disallowMs) : null,
        citation: mandate.citation,
        policyVerdict: policy ? verdictForAlgorithm(family, policy).verdict : null,
        acknowledged: isAcknowledged,
      });
    }
    // Count the acknowledged FINDING once (it produced at least one prohibited
    // row and the org policy owns/tracks its family), not once per mandate row.
    if (producedRow && isAcknowledged) acknowledged++;
    perFindingWorst.push(worst);
  }

  const summary: Record<MandateStatus, number> = {
    conformant: 0,
    due: 0,
    deprecated: 0,
    violation: 0,
  };
  for (const s of perFindingWorst) summary[s]++;

  return {
    now: nowIso,
    mandates: selected.map((m) => m.id),
    summary,
    notInScope,
    findings: rows,
    nextDeadline:
      nextDeadlineMs !== null ? new Date(nextDeadlineMs).toISOString().slice(0, 10) : null,
    hasViolation: summary.violation > 0,
    policyName: policy?.name ?? null,
    acknowledged,
  };
}

export interface MandateGateOptions {
  /** Fail when a DISALLOW deadline is within this many months (early enforcement). */
  leadMonths?: number;
  /** Fail on any mandate-prohibited finding regardless of the deadlines. */
  failNow?: boolean;
}

/**
 * The gate decision under the "deadline-aware" default: fail only once a DISALLOW
 * deadline has passed (`violation`). A passed DEPRECATE date (`deprecated`) is a
 * warning and does not fail the build. `leadMonths` fails early when a disallow
 * deadline is within the window; `failNow` fails on any prohibited finding
 * immediately.
 *
 * Policy composition: when a finding was `acknowledged` by the org policy
 * (`--policy`), it is exempt from the EARLY gates (`failNow` / `leadMonths`) —
 * the org is knowingly, traceably managing that family, so its own early
 * enforcement should not re-flag it. A passed DISALLOW deadline (`violation`)
 * still fails regardless: a dated legal disallow is not something an org can
 * self-exempt from.
 */
export function mandateGateFails(ev: MandateEvaluation, opts: MandateGateOptions = {}): boolean {
  if (ev.hasViolation) return true;
  // Early gates skip policy-acknowledged findings; the hard `violation` above did not.
  const gated = ev.findings.filter((v) => !v.acknowledged);
  if (opts.failNow) return gated.length > 0;
  if (opts.leadMonths !== undefined) {
    return gated.some(
      (v) => v.monthsUntilDisallow !== null && v.monthsUntilDisallow <= opts.leadMonths!,
    );
  }
  return false;
}
