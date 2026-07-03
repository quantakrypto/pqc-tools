# BYOK Agent Tools — Design Spec

- **Date:** 2026-07-03
- **Status:** Approved design; ready for implementation planning.
- **Scope:** All three LLM-agent layers (triage, deterministic remediation, BYOK LLM remediation) + CI plan-comments, delivered as one spec built in three phases.
- **Repo:** `quantakrypto/pqc-tools` (monorepo: `@quantakrypto/{core,qscan,mcp,sieve}` + `@quantakrypto/action`), currently `0.4.0` unpublished on `main`.

## 1. Motivation

qScan finds quantum-vulnerable cryptography deterministically. The next value step is helping users **act** on findings: understand which ones actually matter (triage) and fix them (remediation). Both benefit from an LLM, but the product's credibility rests on determinism and privacy. This design adds LLM assistance **without** surrendering either: the LLM only ever *proposes*; a deterministic engine *disposes* (verifies, gates, and decides).

## 2. Principles & invariants

These hold across all layers and are non-negotiable acceptance criteria:

1. **Engine disposes.** The LLM proposes triage verdicts or patches; deterministic code makes the final decision (re-scan/verify, patch-policy, exit codes). No LLM output is trusted unverified.
2. **`verify_fix` gate.** Every applied patch must re-scan clean: the target finding is gone and **no new finding** is introduced in the changed region. Unverified patches are discarded.
3. **Secrets never leave.** Findings whose snippet is key material (`sensitive: true`) are **always** redacted from any provider payload, at every context level. This is a hard guarantee, independent of the `--context` setting.
4. **Zero third-party runtime dependencies.** The BYOK client uses native `fetch` (Node ≥ 20, already used by `@quantakrypto/action`). No SDKs.
5. **No auto-merge.** Remediation may open a **draft** PR at most. A human always merges.
6. **Triage never suppresses.** Triage annotates and re-sorts; it never removes a finding, and it never changes the CI exit code (which stays driven by the raw severity threshold).
7. **Opt-in / graceful degrade.** Everything BYOK is opt-in. With no key configured: `--triage` becomes a no-op annotation, `qremediate` runs deterministic codemods only. The MCP server never needs a key at all.
8. **Two planes.** *Deterministic plane* (MCP + `@quantakrypto/core`) stays offline and key-free; the host agent does any reasoning. *BYOK plane* (`qscan --triage`, `qremediate`, PR bot) embeds the network client for CI/pipelines that have no host agent.

## 3. Architecture overview

```
                       ┌─────────────────────────────────────────┐
   Deterministic plane │  @quantakrypto/core   (offline, key-free)      │
   (host agent reasons)│  @quantakrypto/mcp    triage_findings /        │
                       │                  apply_triage /           │
                       │                  remediate_findings        │
                       │                  (emit request → agent →   │
                       │                   deterministic apply-back) │
                       └─────────────────────────────────────────┘
                                        ▲
                     shared deterministic engine (verify_fix,
                     codemod registry, patch-policy, redactor rubric)
                                        ▼
                       ┌─────────────────────────────────────────┐
   BYOK plane          │  @quantakrypto/agent   (ONLY networked pkg)    │
   (embeds client)     │    LlmClient + provider adapters (fetch)   │
                       │    context redactor + preflight            │
                       │    structured-output validator + cache     │
                       │  @quantakrypto/qscan   --triage (lazy-imports agent)│
                       │  qremediate       codemods → LLM → PR      │
                       │  @quantakrypto/action  comment-plan             │
                       └─────────────────────────────────────────┘
```

The **only** new networked code lives in `@quantakrypto/agent`. `@quantakrypto/core`, `mcp`, and `sieve` remain offline. `qscan` depends on `agent` but **lazy-imports** it solely on the `--triage` / remediation code paths, so a plain `qscan` scan never loads networking.

**Deterministic engine lives in `core`.** The redactor, `verify_fix` logic, codemod registry, and patch-policy engine are all pure/offline and live in `@quantakrypto/core`, because **both planes need them**: the MCP tools (offline plane) redact context and drive verify/patch loops without ever touching the network. `@quantakrypto/agent` adds **only** the networked client, prompt assembly, response validation, and the response cache — it imports the deterministic pieces from `core`.

## 4. New package: `@quantakrypto/agent`

Zero third-party deps; native `fetch` only. Adds **only** the networked pieces (client, prompt assembly, response validation, cache); the deterministic redactor lives in `@quantakrypto/core` and is imported here. Modules:

### 4.1 `LlmClient` + provider adapters
```ts
interface LlmRequest {
  system: string;
  user: string;            // the rendered, redacted prompt
  schema: object;          // JSON Schema the response must satisfy
  maxTokens: number;
}
interface LlmClient {
  complete(req: LlmRequest): Promise<unknown>; // returns schema-validated JSON
}
```
- **Adapters:** `anthropicClient` (Messages API) and `openAiCompatibleClient` (chat/completions; also covers OpenAI, Azure, Ollama/vLLM, OpenRouter via `baseURL`).
- **Config:** `{ provider, baseURL?, model, apiKeyEnv, temperature: 0, timeoutMs, maxRetries: 1 }`. Key read from env (`QK_LLM_API_KEY`, else provider-native `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`). The key is never logged, never written to disk, never placed in a report.
- **Endpoint allowlist:** only the configured `baseURL` (or the provider default) is ever contacted. No telemetry, no secondary hosts.

### 4.2 Context redactor + preflight (implemented in `core`, offline)
- `buildContext(finding, level, fileContent): RedactedContext` where `level ∈ {metadata, snippet, function, file}`. Pure and offline so the MCP plane reuses it.
  - `metadata` — ruleId, algorithm, severity, HNDL, `file:line`, message. No source.
  - `snippet` (**default**) — metadata + a bounded window (±~8 lines) around the match.
  - `function` — metadata + the enclosing function/block (best-effort, language-aware via the comment/lexer utilities already in `core`).
  - `file` — metadata + full file.
- **Always** removes `sensitive` snippets regardless of level. Also masks obvious secret patterns (PEM blocks, long base64 keys) as defense-in-depth.
- **Level is configurable two ways:** a default in `quantakrypto.config.json` (`agent.contextLevel`) and a per-invocation override (`--context <level>`).
- `--dry-run` / preflight renders the **exact** payload(s) that would be sent, and exits without calling the provider.

### 4.3 Structured-output validator
The provider must return JSON matching the request schema. On mismatch: one repair-retry with the validation error appended, then fail closed (the finding keeps its deterministic state). Mirrors the workflow structured-output discipline.

### 4.4 Response cache
- Keyed by `(promptVersion, model, contextLevel, findingFingerprint)`; `findingFingerprint` reuses `@quantakrypto/qscan`'s existing baseline `fingerprint` (line-insensitive sha256).
- `temperature 0` + cache ⇒ reruns are reproducible and cheap. Cache file default `.quantakrypto-agent-cache.json`, atomic write (same pattern as the scan cache in `core/src/cache.ts`).

## 5. Layer 1 — Triage

### 5.1 CLI: `qscan --triage` (BYOK plane)
- After a normal scan, each finding at/above `--triage-floor` (default: `medium`) gets an LLM verdict:
  ```ts
  interface TriageVerdict {
    exposureScore: number;     // 0–100, real-world exploitability/exposure
    priority: "now" | "soon" | "later";
    rationale: string;         // one paragraph, cites the finding context
  }
  ```
- The verdict is attached to the finding as `finding.triage` and the **human report re-sorts by `exposureScore`** (severity as tiebreak). JSON/SARIF carry the triage fields under `properties.triage`.
- **Never suppresses.** All findings remain present. **Exit code is unchanged** — still `EXIT.FINDINGS` iff a kept finding meets the severity threshold. Triage cannot make CI pass.
- New flags: `--triage`, `--triage-floor <sev>`, `--context <level>`, `--dry-run`, `--llm-model <m>`, `--llm-provider <p>`. Config block `agent: { provider, model, contextLevel, triageFloor }`.
- No key ⇒ `--triage` prints a notice and returns findings unannotated (exit unchanged).

### 5.2 MCP: `triage_findings` + `apply_triage` (deterministic plane)
- `triage_findings(findings | scan args, contextLevel?)` → returns a **triage request**: the rubric (what exposureScore means), the redacted per-finding context, and the response schema. It does **not** call any model.
- The host agent reasons over the request and calls `apply_triage(verdicts)` → deterministic tool that validates the verdicts against the schema, attaches them, and returns the re-sorted, annotated result. Server stays offline/key-free.

## 6. Layer 2 — Deterministic remediation (`qremediate`, no LLM)

### 6.1 Codemod registry
- A registry mirroring the detector registry: `Codemod { id, applies(finding): boolean, apply(fileContent, finding): Patch }`, keyed by ruleId / algorithm / ecosystem.
- Initial codemods (mechanical, template-able only):
  - **Dependency swaps** — add a PQC/hybrid dependency to the manifest and annotate the classical one (e.g. flag `elliptic`, add a migration TODO + suggested replacement). Does **not** silently delete the old dep.
  - **Config toggles** — TLS/cert config where a PQC/hybrid option is a known key.
  - **Import/algorithm rewrites** — only where the replacement is unambiguous and local.
- Anything not unambiguously template-able is **out of scope for Layer 2** and falls to Layer 3.

### 6.2 Execution pipeline (shared with Layer 3)
```
finding → codemod (or LLM) → Patch
  → ephemeral git worktree (isolated apply)
  → patch-policy engine (allowlist check)
  → verify_fix gate (re-scan changed region)
  → keep iff verified & in-policy, else drop with reason
```
- **Ephemeral worktree:** patches apply in a throwaway `git worktree` so the user's checkout is never touched mid-pipeline; cleaned up after.
- **Patch-policy engine (allowlist):** a patch may only (a) edit files that already contain a finding, and (b) add dependencies to a manifest. It may **not** touch CI config, lockfiles (beyond the single targeted dep), secrets/env files, or unrelated files. Violations are rejected with a human-readable reason.
- **`verify_fix` gate:** reuse the logic behind the existing MCP `verify_fix` tool (re-run `detectFile` on the patched content across all 8 languages): the target finding must be gone and no new finding introduced in the changed region.

### 6.3 CLI: `qremediate`
- `qremediate [path] --mode <pr|apply|diff>` (default **pr**), plus `--llm` (Layer 3), `--context`, `--dry-run`, standard scan flags.
- **`diff`** — print a unified diff per verified patch; write nothing.
- **`apply`** — write verified patches into the working tree; user reviews via git.
- **`pr`** — commit verified patches to a new branch and open a **draft** PR (via `gh` locally, or the Action in CI) whose body summarizes each patch, its verify result, and — for LLM patches — the context level that was sent. Never merges.

## 7. Layer 3 — BYOK LLM remediation

- `qremediate --llm`: for each finding **no codemod covers**, build a fix request at the configured context level; the LLM returns a **proposed unified diff** (structured JSON: `{ path, diff, explanation }`). The diff enters the **same** Layer-2 pipeline: worktree → patch-policy → `verify_fix`. Only verified, in-policy patches survive.
- Deterministic first: codemods run before the LLM; the LLM is only invoked for the residue.
- **MCP `remediate_findings`** (deterministic): emits a fix-request bundle (redacted context + schema) for the host agent; the agent proposes diffs and drives a deterministic `apply_patch` + `verify_fix` loop. Server key-free.

## 8. CI plan-comments (`comment-plan`)

- Deterministic mini-migration-plan derived from the existing `plan_migration` (already deterministic, HNDL-first), posted as a PR comment via the Action's existing comment-upsert (marker + PATCH).
- Requires **no key**. Optional `--triage` enrichment (exposure re-rank) only when a key is present.

## 9. Package / dependency stance

- `@quantakrypto/agent` — new, the **only** networked package; zero third-party deps (native `fetch`).
- `@quantakrypto/qscan` — depends on `agent` but **lazy-imports** it only inside the `--triage` / remediation paths; a plain scan never loads it.
- `@quantakrypto/core`, `mcp`, `sieve` — unchanged offline guarantee. The shared deterministic engine (redactor, `verify_fix`, codemod registry, patch-policy) lives in `@quantakrypto/core` so both planes share one implementation and the MCP plane stays offline.

## 10. Privacy & safety summary (cross-cutting)

| Guarantee | Mechanism |
|---|---|
| Secrets never sent | `sensitive` snippets always redacted; PEM/base64 masking; enforced in the redactor, not the caller |
| User controls exposure | `--context {metadata\|snippet\|function\|file}`, config default + per-request override, `--dry-run` preflight |
| No surprise network | Single configured endpoint allowlist; no telemetry; key never logged/persisted |
| No bad fixes | patch-policy allowlist + `verify_fix` gate; unverified patches dropped |
| No silent CI pass | triage never changes exit code; exit still driven by raw severity threshold |
| Reproducible | `temperature 0` + response cache keyed by finding fingerprint |
| Reversible | worktree isolation; draft PR only; never auto-merge |

## 11. Testing strategy

- **Provider client:** fake-`fetch` fixtures (recorded request/response); timeout + single-retry paths; malformed-response repair-retry-then-fail-closed.
- **Redactor:** proves `sensitive` findings never appear in any payload; each context level includes exactly its documented scope and no more; preflight output equals the actual payload.
- **Triage:** never-suppress invariant (finding count and exit code identical with/without triage); re-sort correctness; no-key degrade path.
- **Codemods:** golden before/after files per codemod; a codemod that would go out-of-policy is rejected.
- **Pipeline:** a deliberately-bad patch is rejected by `verify_fix`; an out-of-scope edit is rejected by patch-policy; worktree is cleaned up on success and failure.
- **Determinism/cache:** identical inputs → identical output; cache hit avoids a second provider call.
- All existing gates unchanged: `build`, `test`, `lint`, `format:check`, benchmark ≥ 0.98, action dist fresh.

## 12. Build phasing

- **Phase 1 — Triage.** `@quantakrypto/agent` (client + adapters + redactor + preflight + validator + cache) → `qscan --triage` (+ flags/config, degrade path) → MCP `triage_findings` / `apply_triage`.
- **Phase 2 — Deterministic remediation.** Shared pipeline (worktree + patch-policy + verify gate) → codemod registry (initial codemods) → `qremediate --mode diff|apply`.
- **Phase 3 — BYOK remediation + CI.** LLM fix requests → `--llm` → `--mode pr` (draft PR) → MCP `remediate_findings` → `comment-plan`.

Each phase ships independently, CI-green, and is individually publish-worthy.

## 13. Open questions (defaults chosen; revisit if needed)

- Provider set at launch: **Anthropic + generic OpenAI-compatible** (covers OpenAI/Azure/Ollama/vLLM/OpenRouter). More can be added as adapters.
- `--triage-floor` default: **medium** (don't spend tokens triaging low/info by default).
- `agent.contextLevel` default: **snippet**.
- Codemod breadth in Phase 2: start with dependency swaps + config toggles; expand by demand.

## 14. Non-goals

- No auto-merge, ever.
- No fine-tuning / model hosting; strictly BYOK.
- No telemetry or usage exfiltration.
- Triage does not gate CI.
- The MCP server never embeds a key or calls a provider.
