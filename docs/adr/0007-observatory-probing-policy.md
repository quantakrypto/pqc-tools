# 0007 - Observatory: restrained probing of hosts we do not own

- **Status:** Accepted
- **Date:** 2026-07-25
- **Deciders:** quantakrypto-tools maintainers
- **Supersedes / Superseded by:** -

## Context

qProbe (`@quantakrypto/qprobe`) actively inspects live TLS/SSH endpoints for
post-quantum readiness. By design its public entry point `runProbe` calls
`authorizeTargets(...)` first: an ownership-attestation gate that throws before any
socket is opened (see `packages/qprobe/THREAT-MODEL.md` and ADR-0005). That gate is
correct for qProbe's job, which is to probe infrastructure the operator owns.

We also want an aggregate, longitudinal view of the public web's post-quantum TLS
posture: what fraction of notable hosts have turned on the X25519MLKEM768 hybrid key
exchange, and how that share moves month over month. That measurement is only
meaningful across hosts we do NOT own (major sites, CDNs, cloud and PKI vendors).
Running it through `runProbe` is impossible by construction, and would be wrong to
try: we cannot attest ownership of `google.com`.

## Decision

Build the observatory as an INTERNAL, unpublished worker (`packages/observatory`,
`private: true`) that deliberately bypasses the ownership gate, and constrain it with
a restrained probing policy enforced in code, not merely documented.

**Gate bypass, done narrowly.** The worker does not call `runProbe` and does not
weaken it. It reuses qProbe's lower-level, un-gated primitives by internal source
import: `probeHybridSupport` (raw ClientHello advertising X25519MLKEM768, to see
whether the server SELECTS the hybrid group) and `extractNegotiated` (reads the
negotiated version / cipher / KEX group and the leaf-cert signature family from a
connected socket). We reuse `extractNegotiated` rather than `probeTlsNegotiated`
because the latter discards its socket before returning and we also need the leaf
cert's `notAfter`; the observatory opens the one handshake and reads `valid_to` from
the same peer certificate. No qProbe source is modified, and its public API and
ownership gate are untouched: the observatory simply does not go through the front
door that the gate guards.

**Restrained probing policy (all enforced in `src/probe.ts` / `src/run.ts`):**

- One probe cycle per host per run. A cycle is at most two short-lived, read-only
  handshakes (one TLS handshake for the negotiated posture + cert, one raw
  ClientHello for hybrid support). No content is fetched beyond the handshake.
- A hard per-connection timeout (8s default).
- A minimum interval between hosts (500ms default). Hosts are probed sequentially;
  there is no parallel fan-out.
- Connection refusals and timeouts are recorded as `reachable = false` and never
  retried. A failed host is simply unreachable this cycle.
- Read-only always. We inspect the negotiated reality and disconnect; we never
  modify, authenticate to, or exploit an endpoint. `rejectUnauthorized` is off
  because we inspect posture, not assert trust.
- Opt-out is honored within one cycle: any domain in `optout.txt` (or marked
  `opted_out_at` in the database, e.g. by the website) is recorded and then skipped
  in the same run, before any connection to it is attempted.

The seed host list (`hosts.txt`) is committed and reviewable, scoped to notable
public endpoints. Results and a monthly rollup are written to Postgres
(`observatory_host` / `observatory_probe` / `observatory_rollup`), whose schema the
website owns; the worker only `CREATE TABLE IF NOT EXISTS`es them defensively and
upserts idempotently per `run_month`.

## Legal and ethical posture

An unauthenticated, single TLS handshake to a public host on port 443 is ordinary,
industry-normal internet measurement. It is exactly what a browser does to reach the
site, and it is the same class of read-only observation performed at scale by
long-standing public services such as Qualys SSL Labs and Censys. We read only what
the server volunteers during the handshake (negotiated parameters and the
certificate it presents); we do not authenticate, we do not send application data, we
do not probe non-standard ports, and we do not attempt any exploit. Combined with the
restraint above (one gentle cycle, spacing, no retries, honored opt-out), this keeps
the observatory within the normal-measurement envelope. The opt-out list is the
explicit, low-friction way for any operator to be excluded, honored within a cycle.

## Consequences

**Easier:** a truthful, repeatable public-posture metric that composes with the rest
of the toolchain's PQC framing; a standalone worker that runs from the committed seed
list with only `DATABASE_URL` and `pg`.

**Harder / costs accepted:** the observatory reuses qProbe internals by relative
source import, so a refactor of `packages/qprobe/src/tls.ts` (specifically
`extractNegotiated` / `probeHybridSupport`) can break it; this is the accepted price
of not widening qProbe's public surface or its gate. `pg` is a new dependency, scoped
as a devDependency of this private package only, so the published packages keep the
ADR-0001 zero-runtime-dependency invariant.

**Operations:** the worker runs on the existing dl-latest VM (no separate VM for now),
on a monthly cadence (`observatory run --month YYYY-MM`). Scheduling (cron / systemd
timer) and the `DATABASE_URL` secret are provisioned on that VM.

## Alternatives considered

- **Add an "observatory" mode to the public qProbe CLI.** Rejected: it would either
  route unowned hosts through the ownership gate (impossible) or add a public path
  that skips the gate (erodes the THREAT-MODEL invariant the gate exists to hold).
  Keeping the bypass in a private, unpublished worker confines it.
- **Relax `authorizeTargets` to allow a "public measurement" flag.** Rejected: it
  weakens a security boundary of a published tool to serve an internal need.
- **Re-implement the handshake probes from scratch in the observatory.** Rejected:
  needless duplication of audited byte-level code (the ClientHello codec, the
  negotiated-field and cert-signature extraction) that qProbe already maintains.
