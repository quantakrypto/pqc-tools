# Attestation as a procurement / underwriting primitive

_One-pager, 2026-08-05. Roadmap item #12. Status: partnership-gated — the
technology is already live; what is missing is a design partner and a thin
packaging layer._

## The problem

Quantum risk is unpriced. A buyer evaluating a vendor, or an insurer writing a
cyber policy, has no trustworthy, machine-readable signal for that vendor's
post-quantum posture. Procurement sends a spreadsheet questionnaire and takes the
answers on faith. Insurers guess, or ignore the dimension entirely. The result is
that doing the migration work earns a vendor nothing it can show a counterparty,
and neglecting it costs nothing until it is far too late.

## What we already have

quantakrypto ships a working, third-party-verifiable attestation today:

- **A posture score** (0-100 readiness) derived from a deterministic scan, with a
  CBOM and an ISO/IEC 27001 A.8.24 evidence chain behind it.
- **A content hash** over the evidence body that is reproducible per commit, plus
  optional external signing and RFC-3161 / transparency-log timestamping
  (`signReadinessReport` / `verifyReadinessReport`).
- **The `/.well-known/crypto-agility.json` self-manifest** — an agent- and
  machine-consumable posture document at a stable, backlink-verifiable URL, plus
  a public validator.
- **Continuous re-verification.** The manifest is regenerated on every deploy, so
  the posture a third party reads is current, not a one-time snapshot. This is the
  property that makes the signal credible to someone with money at stake.

None of this is new engineering. It is shipped and live on quantakrypto.com.

## What this initiative adds

A thin packaging layer plus a go-to-market motion, not new core technology:

1. **A citable posture credential.** Freeze the score + manifest + attestation into
   a stable, versioned artifact a vendor can cite in a security questionnaire, with
   a one-line verify API a counterparty can call to confirm it is current and
   unforged.
2. **A `security.txt`-style badge.** A drop-in posture badge that resolves to the
   verified manifest, designed to sit in a vendor-risk profile or a procurement
   record.
3. **A design-partner pilot.** Bring one cyber-insurer or one vendor-risk /
   procurement platform in as a design partner: surface the attested posture inside
   their workflow, and (for the insurer) pilot a premium adjustment tied to attested
   posture. This is the wedge that turns a measurement into a priced signal.

## Why us

We already run the attestation program end to end, and the continuous
re-verification is the hard, credibility-carrying part that a static PDF or a
self-reported questionnaire can never match. We are early enough that defining the
posture-credential format is defining the category.

## The shape of the work

- **Build:** small. A credential-freeze endpoint, a verify API, a badge, and format
  documentation. Weeks, not quarters, because the inputs already exist.
- **Blocker:** a design partner. The build is short; the partnership sales cycle is
  long. That asymmetry is the reason to open the conversation now, in parallel with
  everything else, rather than waiting until the build is "ready."

## The ask

Approval to start one design-partner conversation (an insurer or a vendor-risk
platform) and to scope the credential + verify-API format against that partner's
actual intake. No core roadmap capacity is committed until a partner is engaged.

## Related

- [`docs/compliance/iso27001-a8.24-evidence.md`](../compliance/iso27001-a8.24-evidence.md) — the evidence chain this builds on.
- [`docs/CRYPTO-AGILITY-MANIFEST.md`](../CRYPTO-AGILITY-MANIFEST.md) — the self-manifest + validator.
- Roadmap item #5 (supply-chain CBOM aggregation) consumes these vendor attestations as inputs and should follow, not lead, this item.
