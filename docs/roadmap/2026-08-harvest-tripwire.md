# Harvest tripwire: canary tokens for HNDL

_Research note, 2026-08-05. Frontier roadmap item (harvest tripwire). Status: research-first — stake the
claim now with this note; build when a hire or a research collaboration appears._

## The problem

"Harvest now, decrypt later" (HNDL) is the load-bearing assumption of the entire
post-quantum migration: adversaries are recording classically-encrypted traffic
today to decrypt once a cryptographically-relevant quantum computer exists. But it
is an assumption nobody can prove. There is no evidence that any specific traffic
was harvested, and no way to attribute a decryption when it eventually happens. The
whole field urges migration against a threat it cannot yet observe.

Our product thesis is "evidence over assertion." This is that thesis pointed at the
adversary instead of the codebase.

## The idea

Plant uniquely-identifiable honeytokens that are worthless except as bait, protect
them under classical (quantum-vulnerable) cryptography, expose them where harvesting
would sweep them up, and watch for the day one is used. If the plaintext of a
specific token ever surfaces, that is dated, attributable proof that harvested
ciphertext was decrypted. A quantum honeypot.

## Threat model

- **Adversary:** a passive collector recording ciphertext now for future decryption
  (the canonical HNDL actor), or any party that exfiltrates the protected token
  store.
- **What a firing proves:** that a value which was only ever available as classical
  ciphertext (never in plaintext anywhere reachable) has been recovered — i.e. the
  ciphertext was broken or the key was. A firing is a strong signal; the note below
  on false-positives is about keeping it strong.
- **What it does not prove:** which adversary, or by what means (quantum vs. stolen
  key vs. implementation flaw). Token design has to narrow this, not the marketing.

## Token design

Each token is a distinct, registered, individually-revocable credential:

- A canary API key, signed URL, document watermark, or DNS-resolvable secret — each
  instance unique, so a firing identifies exactly which planted token was used and
  where it was placed.
- **Protected only by classical crypto** on purpose: a TLS session with a
  classical-only KEX, an RSA/ECC-wrapped blob, a classically-signed capability URL.
  The token's secrecy must depend on the primitive we are testing, and on nothing
  else.
- **Never in plaintext at rest anywhere we control**, so that a firing cannot be
  explained by an ordinary plaintext leak. This is the core discipline that keeps a
  firing meaningful.

## Telemetry

- A registration ledger mapping each token to its placement, protecting primitive,
  and issue date.
- A callback surface that fires when a token is exercised (key used, URL resolved,
  watermark observed), recording time and origin.
- A firing is dated evidence: token _T_, only ever available as ciphertext under
  primitive _P_ since date _D_, was used at time _t_ from _o_.

## Evidence value

- A mechanism to **detect decryption of harvested ciphertext in the wild** and
  trace a firing to a specific planted token, rather than only reason about the
  threat — with attribution limited to what the token design supports (see the
  threat model above). That is publishable research and, if it ever fires, a
  genuinely notable data point.
- Even a long null result is informative: a large, well-placed token fleet that
  never fires bounds the observed rate of successful harvest-and-decrypt, which is
  itself a number nobody has today.
- A defensible moat: the value is in the registered fleet and the ledger, which
  compound over time and cannot be retrofitted after the fact.

## Ethics and rules of engagement

- Tokens are bait we own and place; they are not entrapment of third parties and
  carry no real data. Placement stays within systems we control or are authorized to
  instrument.
- A firing is intelligence, not an accusation. Attribution claims must be
  proportionate to what the token design actually supports (see threat model).
- Coordinate any public disclosure of a firing responsibly; a real firing has
  implications well beyond one vendor.

## Why us

It follows directly from the HNDL exposure model qScan already ships (the debt
clock, the Mosca-inequality scoring): we already quantify HNDL risk per finding, so
instrumenting the world to test the assumption behind that risk is the natural next
question. No competitor is positioned to make the "evidence over assertion" claim
credibly here.

## Sizing and next step

- **Size:** L, research-first. It depends on nothing we have built; it is a new
  capability with its own infrastructure (registration, telemetry, fleet ops).
- **Next step:** publish a short paper from this note to stake the idea and open a
  research collaboration. Build the fleet when a hire or a collaborator with the
  right background lands. Do not open core roadmap capacity for it before then.

## Related

- [`docs/HNDL.md`](../HNDL.md) — the exposure model this extends from measurement to detection.
- The HNDL debt clock (shipped) — the quantification this pairs with.
