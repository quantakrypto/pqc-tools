# 0006 — Human-facing report output is English-only (no i18n)

- **Status:** Accepted
- **Date:** 2026-07-20
- **Deciders:** maintainers
- **Supersedes / Superseded by:** —

## Context

`qscan` and the Action produce a human-facing readiness report. A recurring
open question was whether to internationalise it —
add message catalogs and translate the report into other locales.

The forces at play:

- **The domain vocabulary is English-only.** The report's meaning is carried by
  standards terminology — FIPS 203/204/205, CNSA 2.0, NIST IR 8547, "harvest-now-
  decrypt-later", ML-KEM / ML-DSA, algorithm and cipher-suite identifiers. These
  are proper nouns published in English; they are **not** translated by the bodies
  that define them, and a reader who cannot read them cannot act on the report
  regardless of the surrounding prose language.
- **The machine-readable formats are already locale-neutral.** JSON, SARIF, and
  CBOM output carry the findings as structured data with stable `ruleId`s; any
  consumer that needs localized presentation can render from those without the tool
  translating anything. Colour/accessibility is already handled separately (every
  severity/count is printed as text, not colour alone — see `resolveColor`).
- **i18n is not free.** Message catalogs add a parallel, drift-prone surface: every
  new finding message, remediation string, and summary line would need a
  translation workflow and a staleness gate, or translations silently rot.
- **No concrete localized consumer exists.** No user, integration, or compliance
  requirement has asked for a non-English report.

## Decision

We will **not** internationalise the human-facing report. Its prose is authored in
English only, and the tool ships **no** message catalogs or locale machinery. The
structured formats (JSON / SARIF / CBOM) remain the locale-neutral integration
surface for any consumer that needs localized presentation.

This is a **YAGNI deferral, not a permanent refusal**: it will be revisited **only
when a concrete localized-consumer need appears** (a named user, integration, or
regulatory requirement for a non-English report). Reopening the decision means a
new ADR that supersedes this one.

## Consequences

**Easier:** one authored copy of every message; no translation workflow, no catalog
drift gate, no per-locale test matrix; the report and the standards vocabulary it
cites stay in exact correspondence.

**Harder (costs accepted):** a non-English-reading operator gets an English report.
This is judged acceptable because the actionable content (standards names, algorithm
identifiers) is English regardless, and structured output is available for
re-rendering.

**Enforcement:** this is a *do-not-build* decision, so the enforcement is review-
level — a PR adding message catalogs / a locale-selection flag / translated strings
should be rejected with a pointer to this ADR unless it also supersedes it with a
stated localized-consumer need. There is deliberately no i18n code to gate.

## Alternatives considered

- **Full i18n now (message catalogs + `--locale`).** Rejected: builds and maintains
  a parallel surface for a consumer that does not exist, and cannot translate the
  standards vocabulary that carries the report's meaning.
- **Partial i18n (translate prose, keep terms English).** Rejected: the same
  maintenance/drift cost for a report that would still be unreadable to anyone who
  cannot read the (untranslated, load-bearing) standards terms — i.e. cost without
  the intended benefit.
- **Rely on structured output for localization (chosen posture).** JSON/SARIF/CBOM
  already let any consumer render findings in any locale from stable `ruleId`s and
  algorithm families, with zero translation burden on this tool.
