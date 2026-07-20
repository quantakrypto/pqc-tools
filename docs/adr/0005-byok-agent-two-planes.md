# 0005 — The BYOK agent line: `@quantakrypto/agent` is the sole networked plane; the engine disposes

- **Status:** Accepted
- **Date:** 2026-07-15
- **Deciders:** quantakrypto-tools maintainers
- **Supersedes / Superseded by:** —

## Context

Through v0.2 the toolset was entirely **deterministic and offline**: core, qscan,
mcp, action, and sieve make no network calls and hold no credentials. v0.4 adds an
optional **bring-your-own-key (BYOK) LLM** capability — `qscan --triage`
(re-rank + explain findings) and `qremediate --llm` (propose code fixes) — plus a
new package, [`@quantakrypto/agent`](../../packages/agent).

An LLM feature is a different kind of code: it is **networked**, it **handles a
secret** (the operator's API key), it **sends source context to a third party**,
and — for remediation — it **writes code**. Bolted into the existing packages it
would erode the property that makes the rest of the toolset easy to trust and to
host (the MCP especially): *these tools do not phone home and do not hold keys.*
The [security audit](../audits/security.md) covers the offline scanner; the
[agent-line adversarial audit](../THREAT-MODEL.md) (2026-07-15) covers this plane
and confirmed the invariants below hold in code (with the residual gaps noted).

## Decision

Adopt a **two-plane architecture** with a hard boundary between them.

1. **`@quantakrypto/agent` is the ONLY package permitted to make network calls or
   read an API key.** It is zero-dependency (native `fetch`; Anthropic + OpenAI-
   compatible adapters). core, qscan(-offline), **mcp**, action, and sieve stay
   offline and key-free. qscan reaches the agent only via a **dynamic import** on
   the `--triage` / `--llm` paths, so offline use never loads networked code.

2. **Model proposes, engine disposes.** The LLM never has authority over a
   security verdict or a write. The **deterministic core engine** owns every
   consequential decision, and the load-bearing rules are enforced in *code*, not
   in prompt text:
   - **Triage never suppresses.** The exit code is computed from raw finding
     severities **before** triage runs; triage may only annotate and re-rank —
     it cannot remove a finding or change CI pass/fail.
   - **Remediation is gated and contained.** Patches apply in an **ephemeral git
     worktree**, must pass a **`verify_fix` re-scan gate** and a **patch-policy**
     scope check (no secret/VCS/CI/lockfile/off-target paths), and are **never
     auto-merged** (`--mode diff|apply|pr` only; `pr` opens a *draft*).
   - **Secrets are redacted before egress** on every path that builds LLM context;
     files whose secrets were stripped are skipped for remediation.

3. **The MCP exposes triage/remediation as deterministic request/apply tools and
   stays offline/key-free.** `triage_findings` / `remediate_findings` emit a
   *request bundle*; the **host agent** (which the user already trusts with a key)
   does the reasoning. The MCP never imports `@quantakrypto/agent`, never reads a
   key, and never calls the network.

## Consequences

**Easier:** the offline guarantee stays crisp and auditable — one package to
review for network/secret behaviour; the MCP remains safe to host without handing
it a key; offline users never pull networked code at runtime. The shared-core
contract ([ADR-0002](0002-shared-core-contract.md)) holds — rubrics, schemas, the
redactor, `verifyFix`, codemods, and the patch-policy all live in core and are
imported by both planes.

**Harder (costs accepted):** qscan takes a package-level dependency on `agent`
(dynamically imported); the two-plane split adds indirection versus a single
"just call the model" path. Accepted for the isolation it buys.

## Guardrails this ADR protects (do not erode)

- **No new networked package, and no network/`fetch`/key access outside
  `@quantakrypto/agent`.** Per [ADR-0001](0001-zero-runtime-dependencies.md) this
  is **enforced by a CI check** — [`scripts/check-offline-boundary.mjs`](../../scripts/check-offline-boundary.mjs),
  wired into `ci.yml` and `supply-chain-audit.yml`. It asserts (via a masked
  source scan that ignores tokens inside comments/strings): core/mcp/sieve import
  no `@quantakrypto/agent`, make no outbound `fetch(`/WebSocket/XHR call, and read
  no LLM API key; `qscan` reaches the agent **only** via a dynamic `import()`; and
  **no package or workflow auto-merges** (`gh pr merge` / `--admin`). Its own
  reject logic is covered by known-bad fixtures in `scripts/test/guards.test.mjs`.
- **Triage must never gain the ability to drop a finding or alter the exit code.**
- **No auto-merge, ever.** No `gh pr merge` / `--admin` in any package.

## Known limitations (from the 2026-07-15 agent audit — tracked in [ROADMAP §1](../ROADMAP.md))

- **The `verify_fix` gate is *crypto-count* only** (target rule gone + no new
  *crypto* findings + fewer total). It does **not** validate the rest of a
  full-file LLM rewrite, so an injected/hostile model could pass unrelated code
  through it; `--mode apply` then writes it unreviewed. LLM fixes are therefore
  **"crypto-verified, not security-reviewed"** and must be reviewed as a diff.
  *(F1) **Resolved**: a blast-radius guard now bounds a patch to the finding's file
  set + dependency manifests, and the output framing says "crypto-verified, not
  security-reviewed" honestly — see [ROADMAP §1](../ROADMAP.md).*
- **On the MCP plane the gates are advisory** — the host agent writes files, so
  patch-policy/`verify_fix` are not enforced there. Documented, not code-guaranteed. (F5)
- *(F2, F3) **Resolved**: instruction/data separation now travels via the provider's
  real `system` role (the rubric out-ranks the untrusted user turn, with an explicit
  anti-injection preamble), and a per-run spend ceiling (`--max-findings`) caps LLM
  calls. See [ROADMAP §1](../ROADMAP.md) and `packages/agent/src/loop.ts`.*

## Alternatives considered

- **Fold the LLM calls into qscan/core directly.** Rejected: it spreads network +
  key handling across the offline packages and forfeits the "one plane to audit"
  property; the MCP could no longer be hosted key-free.
- **Let the model apply fixes directly (agentic write loop).** Rejected: it makes
  the model authoritative over writes. "Model proposes, engine disposes" keeps the
  deterministic gates in control of every change.
