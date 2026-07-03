# BYOK Agent Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add LLM-assisted triage and remediation to qScan while preserving determinism, privacy, and the zero-dependency guarantee.

**Architecture:** A new zero-dep `@quantakrypto/agent` package holds the only networked code (native `fetch` provider client). All deterministic pieces (redactor, verify, codemods, patch-policy) live in `@quantakrypto/core` so the offline MCP plane reuses them. `qscan` lazy-imports `agent` only on the `--triage`/remediation paths.

**Tech Stack:** TypeScript (ESM, `tsc --build` project references), Node ≥20 native `fetch`, `node --test` + `tsx`, eslint flat config, prettier.

## Global Constraints

- **Zero third-party runtime dependencies.** Native `fetch` only; no SDKs. (verbatim invariant)
- **Secrets never leave:** findings with `sensitive: true` are always redacted from any provider payload, every context level. (verbatim invariant)
- **`verify_fix` gate on every applied patch:** target finding gone + no new finding in the changed region, else discard. (verbatim invariant)
- **No auto-merge** — draft PR at most. (verbatim invariant)
- **Triage never suppresses and never changes the exit code** (exit stays driven by raw severity threshold). (verbatim invariant)
- **MCP stays offline/key-free** — never embeds a key or calls a provider. (verbatim invariant)
- **Every commit passes the gates:** `npm run build && npm test && npm run lint && npm run format:check`; benchmark ≥ 0.98 must not regress; after any `packages/action` change run `npm run bundle -w @quantakrypto/action` so `packages/action/dist` is fresh (`git diff --exit-code packages/action/dist`).
- **Commit style:** author `Leon Acosta <leon@dandelionlabs.io>`, lowercase casual, **NO Claude co-author**.
- **Unpublished:** work lands as commits on `main` at `0.4.0`; do **not** run the Release workflow.
- **Node test runner:** `node --import tsx --test test/*.test.ts` per package; `import assert from "node:assert/strict"`, `import { test } from "node:test"`.

## File Structure

**`@quantakrypto/core` (additions, all offline/pure):**
- `src/verify.ts` — `verifyFix(code, {filename?|language?})` extracted from the MCP tool; returns remaining findings.
- `src/redact.ts` — context levels + `sensitive` stripping + preflight render.
- `src/agent-types.ts` — shared types: `TriageVerdict`, `Patch`, `ContextLevel`, `RedactedContext`, `FixProposal`.
- `src/codemods/registry.ts` — `Codemod` interface + registry.
- `src/codemods/{dependency-swap,config-toggle}.ts` — initial codemods.
- `src/patch-policy.ts` — allowlist engine.
- `src/worktree.ts` — ephemeral git worktree runner.
- `src/remediate-pipeline.ts` — codemod/LLM → worktree → policy → verify.

**`@quantakrypto/agent` (new package, only networked code):**
- `package.json`, `tsconfig.json`, `src/index.ts`
- `src/client.ts` — `LlmClient` interface + `resolveClient(config)`.
- `src/anthropic.ts`, `src/openai.ts` — provider adapters (native fetch).
- `src/validate.ts` — JSON-schema response validation + repair-retry.
- `src/prompt.ts` — triage + fix prompt assembly (imports redactor from core).
- `src/response-cache.ts` — `(promptVersion, model, contextLevel, fingerprint)` cache.
- `src/triage.ts` — triage orchestrator.
- `src/remediate.ts` — LLM fix orchestrator.

**`@quantakrypto/qscan` (additions):**
- `src/args.ts` — `--triage`, `--triage-floor`, `--context`, `--dry-run`, `--llm-*` flags.
- `src/triage-run.ts` — lazy-import `agent`, run triage, attach verdicts, re-sort.
- `src/remediate-cli.ts` + `src/remediate-bin.ts` — `qremediate` entry (`--mode diff|apply|pr`, `--llm`).

**`@quantakrypto/mcp` (additions):**
- `src/tools.ts` — `triage_findings`, `apply_triage`, `remediate_findings`.

**`@quantakrypto/action` (additions):**
- `src/main.ts` — `comment-plan` mode.

---

# Phase 1 — Triage

### Task 1: Scaffold `@quantakrypto/agent`

**Files:**
- Create: `packages/agent/package.json`, `packages/agent/tsconfig.json`, `packages/agent/src/index.ts`, `packages/agent/test/smoke.test.ts`
- Modify: `tsconfig.json` (add `{ "path": "packages/agent" }` reference)

**Interfaces:**
- Produces: the `@quantakrypto/agent` package, buildable, depending on `@quantakrypto/core`.

- [ ] **Step 1: Write `packages/agent/package.json`** (mirror sieve; add core dep)

```json
{
  "name": "@quantakrypto/agent",
  "version": "0.4.0",
  "description": "BYOK LLM client for qScan triage and remediation. Native fetch, zero runtime dependencies.",
  "license": "Apache-2.0",
  "author": "Dandelion Labs <hello@dandelionlabs.io> (https://dandelionlabs.io)",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": { ".": { "types": "./dist/index.d.ts", "default": "./dist/index.js" } },
  "files": ["dist", "README.md"],
  "engines": { "node": ">=20" },
  "publishConfig": { "access": "public" },
  "dependencies": { "@quantakrypto/core": "0.4.0" },
  "scripts": { "build": "tsc -b", "test": "node --import tsx --test test/*.test.ts" }
}
```

- [ ] **Step 2: Write `packages/agent/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "rootDir": "src", "outDir": "dist" },
  "include": ["src/**/*.ts"],
  "references": [{ "path": "../core" }]
}
```

- [ ] **Step 3: Write `packages/agent/src/index.ts`** (placeholder export)

```ts
/** @quantakrypto/agent — BYOK LLM client for qScan triage and remediation. */
export const AGENT_PACKAGE = "@quantakrypto/agent";
```

- [ ] **Step 4: Add the reference in root `tsconfig.json`** (append to `references`)

```json
{ "path": "packages/agent" }
```

- [ ] **Step 5: Write `packages/agent/test/smoke.test.ts`**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { AGENT_PACKAGE } from "../src/index.js";

test("package identifier is exported", () => {
  assert.equal(AGENT_PACKAGE, "@quantakrypto/agent");
});
```

- [ ] **Step 6: Install workspaces, build, test**

Run: `npm install && npm run build && npm test -w @quantakrypto/agent`
Expected: build succeeds; smoke test PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/agent tsconfig.json package-lock.json
git commit -m "agent: scaffold @quantakrypto/agent package (zero-dep, native fetch)" --author="Leon Acosta <leon@dandelionlabs.io>"
```

---

### Task 2: Core `verifyFix()` helper (extract from MCP)

**Files:**
- Create: `packages/core/src/verify.ts`, `packages/core/test/verify.test.ts`
- Modify: `packages/core/src/index.ts` (export), `packages/mcp/src/tools.ts` (verify_fix uses core helper)

**Interfaces:**
- Produces: `verifyFix(code: string, opts: { filename?: string; language?: string }): { supported: boolean; findings: Finding[] }` and `languageToExtension(language: string): string | null` (move from mcp to core).
- Consumes: `detectFile`, `detectors` from core.

- [ ] **Step 1: Write the failing test** `packages/core/test/verify.test.ts`

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyFix } from "../src/verify.js";

test("verifyFix reports remaining classical crypto", () => {
  const r = verifyFix("const e = crypto.createECDH('p256');", { language: "js" });
  assert.equal(r.supported, true);
  assert.ok(r.findings.some((f) => f.ruleId === "node-crypto-ecdh"));
});

test("verifyFix returns clean for PQC-only code", () => {
  const r = verifyFix("const x = mlkem768.keygen();", { language: "js" });
  assert.equal(r.supported, true);
  assert.equal(r.findings.length, 0);
});

test("verifyFix flags an unsupported language as not-a-verification", () => {
  const r = verifyFix("let x = 1", { language: "cobol" });
  assert.equal(r.supported, false);
});
```

- [ ] **Step 2: Run test, verify it fails**

Run: `node --import tsx --test packages/core/test/verify.test.ts`
Expected: FAIL — cannot find `../src/verify.js`.

- [ ] **Step 3: Write `packages/core/src/verify.ts`** (lift `languageToExtension` + the detect logic)

```ts
import type { Finding } from "./types.js";
import { detectFile } from "./scan.js";
import { detectors } from "./scan.js";

/** Map a language name to a source extension whose detectors we run. */
export function languageToExtension(language: string): string | null {
  const map: Record<string, string> = {
    js: ".js", javascript: ".js", ts: ".ts", typescript: ".ts",
    py: ".py", python: ".py", go: ".go", java: ".java", kotlin: ".kt",
    cs: ".cs", csharp: ".cs", rs: ".rs", rust: ".rs", rb: ".rb", ruby: ".rb",
    c: ".c", "c++": ".cpp", cpp: ".cpp",
  };
  return map[language.toLowerCase()] ?? null;
}

/** Run detectors over a code snippet (no filesystem). Used to verify a fix. */
export function verifyFix(
  code: string,
  opts: { filename?: string; language?: string },
): { supported: boolean; findings: Finding[] } {
  let name: string;
  let supported = true;
  if (opts.filename) {
    name = opts.filename;
  } else if (opts.language) {
    const ext = languageToExtension(opts.language);
    if (!ext) return { supported: false, findings: [] };
    name = `snippet${ext}`;
  } else {
    return { supported: false, findings: [] };
  }
  const findings = detectFile(name, code, detectors, { source: true, config: true, deps: true });
  return { supported, findings };
}
```

- [ ] **Step 4: Export from `packages/core/src/index.ts`**

```ts
export { verifyFix, languageToExtension } from "./verify.js";
```

- [ ] **Step 5: Rewire the MCP `verify_fix` handler** in `packages/mcp/src/tools.ts` to call `verifyFix` from core (remove the local `languageToExtension`, import from core). Keep the same tool output text.

- [ ] **Step 6: Run tests**

Run: `npm run build && node --import tsx --test packages/core/test/verify.test.ts && npm test -w @quantakrypto/mcp`
Expected: PASS (core verify + all mcp tests).

- [ ] **Step 7: Commit**

```bash
git add packages/core packages/mcp
git commit -m "core: extract verifyFix() helper; mcp verify_fix now delegates to it" --author="Leon Acosta <leon@dandelionlabs.io>"
```

---

### Task 3: Core context redactor

**Files:**
- Create: `packages/core/src/agent-types.ts`, `packages/core/src/redact.ts`, `packages/core/test/redact.test.ts`
- Modify: `packages/core/src/index.ts`

**Interfaces:**
- Produces:
  - `type ContextLevel = "metadata" | "snippet" | "function" | "file"`
  - `interface RedactedContext { level: ContextLevel; meta: {...}; code: string | null; redactedSecret: boolean }`
  - `buildContext(finding: Finding, level: ContextLevel, fileContent: string): RedactedContext`
  - `renderPreflight(contexts: RedactedContext[]): string`
- Consumes: `Finding` from core.

- [ ] **Step 1: Write `packages/core/src/agent-types.ts`**

```ts
import type { Finding, Severity } from "./types.js";

export type ContextLevel = "metadata" | "snippet" | "function" | "file";

export interface RedactedContext {
  level: ContextLevel;
  meta: {
    ruleId: string;
    algorithm?: string;
    severity: Severity;
    hndl: boolean;
    file: string;
    line: number;
    message: string;
  };
  /** Redacted source context, or null at metadata level / when fully redacted. */
  code: string | null;
  /** True when key material was stripped from the context. */
  redactedSecret: boolean;
}

export interface TriageVerdict {
  fingerprint: string;
  exposureScore: number; // 0–100
  priority: "now" | "soon" | "later";
  rationale: string;
}

export interface Patch {
  path: string;
  /** Full replacement content for `path` after the fix. */
  newContent: string;
  ruleId: string;
  source: "codemod" | "llm";
}

export interface FixProposal {
  fingerprint: string;
  path: string;
  newContent: string;
  explanation: string;
}
```

- [ ] **Step 2: Write the failing test** `packages/core/test/redact.test.ts`

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildContext } from "../src/redact.js";
import type { Finding } from "../src/index.js";

const FILE = ["import x", "const e = crypto.createECDH('p256');", "doThing(e)", "// tail"].join("\n");
const finding: Finding = {
  ruleId: "node-crypto-ecdh", title: "ECDH", category: "key-exchange",
  severity: "high", confidence: "high", hndl: true, message: "ECDH is classical",
  location: { file: "a.ts", line: 2 },
};

test("metadata level sends no code", () => {
  const c = buildContext(finding, "metadata", FILE);
  assert.equal(c.code, null);
  assert.equal(c.meta.ruleId, "node-crypto-ecdh");
});

test("snippet level sends a bounded window including the match line", () => {
  const c = buildContext(finding, "snippet", FILE);
  assert.ok(c.code && c.code.includes("createECDH"));
});

test("file level sends the whole file", () => {
  const c = buildContext(finding, "file", FILE);
  assert.equal(c.code, FILE);
});

test("a sensitive finding is always redacted, even at file level", () => {
  const sensitive: Finding = { ...finding, sensitive: true, location: { file: "k.pem", line: 1 } };
  const c = buildContext(sensitive, "file", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----");
  assert.equal(c.code, null);
  assert.equal(c.redactedSecret, true);
});
```

- [ ] **Step 3: Run test, verify it fails**

Run: `node --import tsx --test packages/core/test/redact.test.ts`
Expected: FAIL — cannot find `../src/redact.js`.

- [ ] **Step 4: Write `packages/core/src/redact.ts`**

```ts
import type { Finding } from "./types.js";
import type { ContextLevel, RedactedContext } from "./agent-types.js";

const SNIPPET_RADIUS = 8;
const SECRET_RE = /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----|[A-Za-z0-9+/]{120,}={0,2}/g;

function stripSecrets(text: string): { text: string; redacted: boolean } {
  let redacted = false;
  const out = text.replace(SECRET_RE, () => {
    redacted = true;
    return "«redacted-secret»";
  });
  return { text: out, redacted };
}

export function buildContext(finding: Finding, level: ContextLevel, fileContent: string): RedactedContext {
  const meta = {
    ruleId: finding.ruleId,
    algorithm: finding.algorithm,
    severity: finding.severity,
    hndl: finding.hndl,
    file: finding.location.file,
    line: finding.location.line,
    message: finding.message,
  };
  // Sensitive findings: never emit code.
  if (finding.sensitive) return { level, meta, code: null, redactedSecret: true };
  if (level === "metadata") return { level, meta, code: null, redactedSecret: false };

  const lines = fileContent.split("\n");
  let code: string;
  if (level === "file") {
    code = fileContent;
  } else if (level === "function") {
    code = enclosingBlock(lines, finding.location.line - 1);
  } else {
    const i = finding.location.line - 1;
    code = lines.slice(Math.max(0, i - SNIPPET_RADIUS), i + SNIPPET_RADIUS + 1).join("\n");
  }
  const { text, redacted } = stripSecrets(code);
  return { level, meta, code: text, redactedSecret: redacted };
}

/** Best-effort enclosing brace/indent block around a line. */
function enclosingBlock(lines: string[], idx: number): string {
  let start = idx;
  while (start > 0 && !/[{:]\s*$/.test(lines[start - 1] ?? "")) start--;
  let end = idx;
  let depth = 0;
  for (let i = start; i < lines.length; i++) {
    depth += ((lines[i].match(/{/g) ?? []).length) - ((lines[i].match(/}/g) ?? []).length);
    end = i;
    if (i > idx && depth <= 0) break;
  }
  return lines.slice(start, end + 1).join("\n");
}

/** Render the exact payload text for `--dry-run`. */
export function renderPreflight(contexts: RedactedContext[]): string {
  return contexts
    .map((c) => {
      const head = `[${c.meta.severity}] ${c.meta.ruleId} ${c.meta.file}:${c.meta.line} (level=${c.level}${c.redactedSecret ? ", secret-redacted" : ""})`;
      return c.code ? `${head}\n${c.code}` : head;
    })
    .join("\n\n---\n\n");
}
```

- [ ] **Step 5: Export from `packages/core/src/index.ts`**

```ts
export type { ContextLevel, RedactedContext, TriageVerdict, Patch, FixProposal } from "./agent-types.js";
export { buildContext, renderPreflight } from "./redact.js";
```

- [ ] **Step 6: Run tests**

Run: `npm run build && node --import tsx --test packages/core/test/redact.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add packages/core
git commit -m "core: context redactor with levels + always-strip secrets + preflight" --author="Leon Acosta <leon@dandelionlabs.io>"
```

---

### Task 4: Agent `LlmClient` + response validator

**Files:**
- Create: `packages/agent/src/client.ts`, `packages/agent/src/validate.ts`, `packages/agent/test/validate.test.ts`
- Modify: `packages/agent/src/index.ts`

**Interfaces:**
- Produces:
  - `interface LlmRequest { system: string; user: string; schema: JsonSchema; maxTokens: number }`
  - `interface LlmClient { complete(req: LlmRequest): Promise<unknown> }`
  - `interface LlmConfig { provider: "anthropic" | "openai-compatible"; baseURL?: string; model: string; apiKey: string; temperature?: number; timeoutMs?: number; maxRetries?: number }`
  - `validateAgainstSchema(value: unknown, schema: JsonSchema): { ok: true; value: unknown } | { ok: false; error: string }`
  - `type JsonSchema = Record<string, unknown>`

- [ ] **Step 1: Write the failing test** `packages/agent/test/validate.test.ts`

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAgainstSchema } from "../src/validate.js";

const schema = {
  type: "object",
  required: ["exposureScore", "priority"],
  properties: {
    exposureScore: { type: "number", minimum: 0, maximum: 100 },
    priority: { enum: ["now", "soon", "later"] },
  },
};

test("valid object passes", () => {
  const r = validateAgainstSchema({ exposureScore: 40, priority: "soon" }, schema);
  assert.equal(r.ok, true);
});

test("missing required field fails with a message", () => {
  const r = validateAgainstSchema({ priority: "soon" }, schema);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /exposureScore/);
});

test("out-of-range number fails", () => {
  const r = validateAgainstSchema({ exposureScore: 900, priority: "now" }, schema);
  assert.equal(r.ok, false);
});

test("bad enum fails", () => {
  const r = validateAgainstSchema({ exposureScore: 1, priority: "urgent" }, schema);
  assert.equal(r.ok, false);
});
```

- [ ] **Step 2: Run test, verify it fails**

Run: `node --import tsx --test packages/agent/test/validate.test.ts`
Expected: FAIL — cannot find `../src/validate.js`.

- [ ] **Step 3: Write `packages/agent/src/validate.ts`** (tiny hand-rolled JSON-schema subset — zero deps)

```ts
export type JsonSchema = Record<string, unknown>;
type Ok = { ok: true; value: unknown };
type Err = { ok: false; error: string };

/** Validate against the JSON-Schema subset we emit (type/required/enum/min/max/properties/items). */
export function validateAgainstSchema(value: unknown, schema: JsonSchema, path = "$"): Ok | Err {
  const err = (m: string): Err => ({ ok: false, error: `${path}: ${m}` });
  const t = schema.type as string | undefined;
  if (Array.isArray((schema as { enum?: unknown[] }).enum)) {
    const en = (schema as { enum: unknown[] }).enum;
    if (!en.includes(value)) return err(`must be one of ${JSON.stringify(en)}`);
  }
  if (t === "number") {
    if (typeof value !== "number") return err("must be a number");
    const { minimum, maximum } = schema as { minimum?: number; maximum?: number };
    if (minimum !== undefined && value < minimum) return err(`must be >= ${minimum}`);
    if (maximum !== undefined && value > maximum) return err(`must be <= ${maximum}`);
  } else if (t === "string") {
    if (typeof value !== "string") return err("must be a string");
  } else if (t === "array") {
    if (!Array.isArray(value)) return err("must be an array");
    const items = (schema as { items?: JsonSchema }).items;
    if (items) {
      for (let i = 0; i < value.length; i++) {
        const r = validateAgainstSchema(value[i], items, `${path}[${i}]`);
        if (!r.ok) return r;
      }
    }
  } else if (t === "object" || schema.properties) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return err("must be an object");
    const obj = value as Record<string, unknown>;
    for (const req of ((schema as { required?: string[] }).required ?? [])) {
      if (!(req in obj)) return err(`missing required "${req}"`);
    }
    const props = (schema as { properties?: Record<string, JsonSchema> }).properties ?? {};
    for (const [k, sub] of Object.entries(props)) {
      if (k in obj) {
        const r = validateAgainstSchema(obj[k], sub, `${path}.${k}`);
        if (!r.ok) return r;
      }
    }
  }
  return { ok: true, value };
}
```

- [ ] **Step 4: Write `packages/agent/src/client.ts`** (interfaces only; adapters land in Tasks 5–6)

```ts
import type { JsonSchema } from "./validate.js";

export interface LlmRequest {
  system: string;
  user: string;
  schema: JsonSchema;
  maxTokens: number;
}
export interface LlmClient {
  complete(req: LlmRequest): Promise<unknown>;
}
export interface LlmConfig {
  provider: "anthropic" | "openai-compatible";
  baseURL?: string;
  model: string;
  apiKey: string;
  temperature?: number;
  timeoutMs?: number;
  maxRetries?: number;
}
```

- [ ] **Step 5: Run tests**

Run: `npm run build && node --import tsx --test packages/agent/test/validate.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add packages/agent
git commit -m "agent: LlmClient/LlmConfig interfaces + zero-dep json-schema validator" --author="Leon Acosta <leon@dandelionlabs.io>"
```

---

### Task 5: Anthropic adapter (native fetch, fake-fetch test)

**Files:**
- Create: `packages/agent/src/anthropic.ts`, `packages/agent/test/anthropic.test.ts`

**Interfaces:**
- Produces: `anthropicClient(config: LlmConfig, fetchImpl?: typeof fetch): LlmClient`. Injectable `fetchImpl` for tests (defaults to global `fetch`).
- Consumes: `LlmClient`, `LlmRequest`, `LlmConfig` (Task 4); `validateAgainstSchema` (Task 4).

- [ ] **Step 1: Write the failing test** `packages/agent/test/anthropic.test.ts`

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { anthropicClient } from "../src/anthropic.js";

function fakeFetch(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
}

const schema = { type: "object", required: ["exposureScore", "priority"], properties: { exposureScore: { type: "number" }, priority: { enum: ["now", "soon", "later"] } } };

test("anthropic adapter parses a tool/JSON response and validates it", async () => {
  const payload = { content: [{ type: "text", text: JSON.stringify({ exposureScore: 55, priority: "soon" }) }] };
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "k" },
    fakeFetch(payload),
  );
  const out = (await client.complete({ system: "s", user: "u", schema, maxTokens: 256 })) as { exposureScore: number };
  assert.equal(out.exposureScore, 55);
});

test("adapter repairs once then throws on persistently invalid JSON", async () => {
  const bad = { content: [{ type: "text", text: "not json" }] };
  const client = anthropicClient({ provider: "anthropic", model: "claude-x", apiKey: "k" }, fakeFetch(bad));
  await assert.rejects(() => client.complete({ system: "s", user: "u", schema, maxTokens: 256 }));
});
```

- [ ] **Step 2: Run test, verify it fails**

Run: `node --import tsx --test packages/agent/test/anthropic.test.ts`
Expected: FAIL — cannot find `../src/anthropic.js`.

- [ ] **Step 3: Write `packages/agent/src/anthropic.ts`**

```ts
import type { LlmClient, LlmConfig, LlmRequest } from "./client.js";
import { validateAgainstSchema } from "./validate.js";

const DEFAULT_BASE = "https://api.anthropic.com";

export function anthropicClient(config: LlmConfig, fetchImpl: typeof fetch = fetch): LlmClient {
  const base = config.baseURL ?? DEFAULT_BASE;
  async function call(user: string): Promise<string> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), config.timeoutMs ?? 30_000);
    try {
      const res = await fetchImpl(`${base}/v1/messages`, {
        method: "POST",
        signal: ctrl.signal,
        headers: {
          "content-type": "application/json",
          "x-api-key": config.apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: config.model,
          max_tokens: 1024,
          temperature: config.temperature ?? 0,
          system: undefined,
          messages: [{ role: "user", content: user }],
        }),
      });
      if (!res.ok) throw new Error(`anthropic: HTTP ${res.status}`);
      const json = (await res.json()) as { content?: { type: string; text?: string }[] };
      return json.content?.map((b) => b.text ?? "").join("") ?? "";
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    async complete(req: LlmRequest): Promise<unknown> {
      const prompt = `${req.system}\n\n${req.user}\n\nReturn ONLY JSON matching this schema:\n${JSON.stringify(req.schema)}`;
      let text = await call(prompt);
      let parsed = tryParse(text);
      let check = parsed !== undefined ? validateAgainstSchema(parsed, req.schema) : { ok: false as const, error: "not JSON" };
      if (!check.ok) {
        text = await call(`${prompt}\n\nYour previous reply was invalid: ${check.error}. Reply with corrected JSON only.`);
        parsed = tryParse(text);
        check = parsed !== undefined ? validateAgainstSchema(parsed, req.schema) : { ok: false, error: "not JSON" };
        if (!check.ok) throw new Error(`anthropic: invalid response after repair (${check.error})`);
      }
      return parsed;
    },
  };
}

function tryParse(text: string): unknown {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return undefined;
  try {
    return JSON.parse(m[0]);
  } catch {
    return undefined;
  }
}
```

- [ ] **Step 4: Run tests**

Run: `npm run build && node --import tsx --test packages/agent/test/anthropic.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/agent
git commit -m "agent: anthropic messages adapter (native fetch, schema-validated, repair-retry)" --author="Leon Acosta <leon@dandelionlabs.io>"
```

---

### Task 6: OpenAI-compatible adapter + `resolveClient`

**Files:**
- Create: `packages/agent/src/openai.ts`, `packages/agent/test/openai.test.ts`
- Modify: `packages/agent/src/client.ts` (add `resolveClient`), `packages/agent/src/index.ts`

**Interfaces:**
- Produces: `openAiCompatibleClient(config, fetchImpl?): LlmClient`; `resolveClient(config: LlmConfig, fetchImpl?): LlmClient` (dispatches by `config.provider`).

- [ ] **Step 1: Write the failing test** `packages/agent/test/openai.test.ts`

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { openAiCompatibleClient } from "../src/openai.js";
import { resolveClient } from "../src/client.js";

function fakeFetch(body: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;
}
const schema = { type: "object", required: ["priority"], properties: { priority: { enum: ["now", "soon", "later"] } } };

test("openai adapter reads choices[0].message.content", async () => {
  const payload = { choices: [{ message: { content: JSON.stringify({ priority: "now" }) } }] };
  const client = openAiCompatibleClient({ provider: "openai-compatible", baseURL: "http://x", model: "m", apiKey: "k" }, fakeFetch(payload));
  const out = (await client.complete({ system: "s", user: "u", schema, maxTokens: 128 })) as { priority: string };
  assert.equal(out.priority, "now");
});

test("resolveClient dispatches by provider", () => {
  const c = resolveClient({ provider: "openai-compatible", baseURL: "http://x", model: "m", apiKey: "k" }, fakeFetch({}));
  assert.equal(typeof c.complete, "function");
});
```

- [ ] **Step 2: Run test, verify it fails**

Run: `node --import tsx --test packages/agent/test/openai.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write `packages/agent/src/openai.ts`** (same repair-retry shape as anthropic; endpoint `${baseURL}/chat/completions`, header `authorization: Bearer`, response path `choices[0].message.content`). Factor the parse/validate/repair loop into a shared `completeWith(call, req)` helper exported from `validate.ts` or a new `loop.ts` to stay DRY.

- [ ] **Step 4: Add `resolveClient` to `packages/agent/src/client.ts`**

```ts
import { anthropicClient } from "./anthropic.js";
import { openAiCompatibleClient } from "./openai.js";
export function resolveClient(config: LlmConfig, fetchImpl: typeof fetch = fetch): LlmClient {
  return config.provider === "anthropic"
    ? anthropicClient(config, fetchImpl)
    : openAiCompatibleClient(config, fetchImpl);
}
```

- [ ] **Step 5: Export from `packages/agent/src/index.ts`** the client factories + types.

- [ ] **Step 6: Run tests & commit**

Run: `npm run build && npm test -w @quantakrypto/agent`
Expected: PASS.

```bash
git add packages/agent
git commit -m "agent: openai-compatible adapter + resolveClient dispatch" --author="Leon Acosta <leon@dandelionlabs.io>"
```

---

### Task 7: Agent response cache

**Files:**
- Create: `packages/agent/src/response-cache.ts`, `packages/agent/test/response-cache.test.ts`

**Interfaces:**
- Produces: `loadResponseCache(file)`, `cacheKey({promptVersion, model, contextLevel, fingerprint})`, `getCached/setCached`, `saveResponseCache(file, map)`. Mirror `packages/core/src/cache.ts` (atomic write, tolerant load).

- [ ] **Step 1..7:** Follow the `core/src/cache.ts` pattern exactly (sha-keyed map, atomic temp+rename, empty on corrupt). Test: round-trip + a changed key misses. Commit `agent: response cache keyed by (promptVersion, model, level, fingerprint)`.

---

### Task 8: Triage orchestrator (agent)

**Files:**
- Create: `packages/agent/src/prompt.ts`, `packages/agent/src/triage.ts`, `packages/agent/test/triage.test.ts`

**Interfaces:**
- Produces: `triageFindings(findings: Finding[], opts: TriageOptions): Promise<Map<string, TriageVerdict>>` where `TriageOptions = { client: LlmClient; level: ContextLevel; readFile(path): Promise<string>; fingerprint(f): string; floor?: Severity; cacheFile?: string }`.
- Consumes: `buildContext` (core), `TriageVerdict` (core), `LlmClient` (agent), response cache (Task 7).

- [ ] **Step 1: Write the failing test** with a fake `LlmClient` returning a fixed verdict; assert the returned map keys by fingerprint and every above-floor finding is triaged. Include a **never-suppress** style check at this layer: the function returns verdicts only (it must not drop findings — that is qscan's job, verified in Task 9).

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { triageFindings } from "../src/triage.js";
import type { Finding } from "@quantakrypto/core";

const client = { complete: async () => ({ exposureScore: 70, priority: "now", rationale: "reachable" }) };
const f: Finding = { ruleId: "node-crypto-ecdh", title: "ECDH", category: "key-exchange", severity: "high", confidence: "high", hndl: true, message: "m", location: { file: "a.ts", line: 1 } };

test("triage returns a verdict per above-floor finding, keyed by fingerprint", async () => {
  const verdicts = await triageFindings([f], {
    client, level: "metadata", readFile: async () => "", fingerprint: () => "fp1", floor: "medium",
  });
  assert.equal(verdicts.get("fp1")?.exposureScore, 70);
});
```

- [ ] **Steps 2–7:** implement `prompt.ts` (assemble system rubric + `renderPreflight`-style user text from `buildContext`) and `triage.ts` (loop findings ≥ floor, cache-check, `client.complete` with the triage schema, validate→`TriageVerdict`). Commit `agent: triage orchestrator (rubric prompt + cache + schema)`.

---

### Task 9: qscan `--triage` wiring

**Files:**
- Create: `packages/qscan/src/triage-run.ts`, `packages/qscan/test/triage.test.ts`
- Modify: `packages/qscan/src/args.ts` (flags), `packages/qscan/src/index.ts` (invoke after scan), `packages/qscan/src/help.ts`, `packages/qscan/package.json` (add `@quantakrypto/agent` dep)

**Interfaces:**
- Consumes: `triageFindings` (agent, via **dynamic `import()`** so a normal scan never loads it), `fingerprintFinding` (qscan baseline).
- Produces: `runTriage(result, options): Promise<ScanResult>` — attaches `finding.triage`, re-sorts by exposureScore; returns the SAME findings (count unchanged).

- [ ] **Step 1: Write the invariant tests** `packages/qscan/test/triage.test.ts` (fake agent module via injected `triageFn`):

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { runTriage } from "../src/triage-run.js";
import { makeResult, makeFinding } from "./helpers.js";

test("triage never drops a finding and never changes the count", async () => {
  const result = makeResult([makeFinding({ severity: "high" }), makeFinding({ severity: "low", location: { file: "b.ts", line: 2 } })]);
  const triaged = await runTriage(result, {
    triageFn: async () => new Map([[/* fp */ "x", { fingerprint: "x", exposureScore: 90, priority: "now", rationale: "r" }]]),
    level: "metadata", floor: "medium",
  });
  assert.equal(triaged.findings.length, result.findings.length);
});
```

- [ ] **Steps 2–4:** add flags to `args.ts` (`--triage`, `--triage-floor <sev>`, `--context <level>`, `--dry-run`, `--llm-provider`, `--llm-model`), config block `agent`; implement `triage-run.ts` (dynamic import of agent, resolve client from env key, `--dry-run` prints preflight and exits, attach verdicts, stable re-sort by exposureScore then existing `compareFindings`). **Exit code is computed BEFORE triage** in `runQscan`, so triage cannot change it — add an assertion test.

- [ ] **Step 5:** no-key degrade test (no env key ⇒ returns findings unannotated, prints a notice, exit unchanged).

- [ ] **Step 6:** Run `npm run build && npm test && npm run lint && npm run format:check`. Commit `qscan: --triage (annotate + re-sort, never suppress, never gates CI)`.

---

### Task 10: MCP `triage_findings` + `apply_triage`

**Files:**
- Modify: `packages/mcp/src/tools.ts` (two tools + `quantakryptoTools` list), `packages/mcp/test/{server,transport,tools}.test.ts` (tool count/name assertions), `packages/mcp/README.md`

**Interfaces:**
- `triage_findings(findings|scan args, contextLevel?)` → returns a JSON request bundle `{ rubric, schema, contexts: RedactedContext[] }` (built with `buildContext`; **no network**).
- `apply_triage(verdicts)` → validates each against the triage schema, returns the re-sorted annotated findings. Deterministic.

- [ ] **Steps:** add both tools (offline, key-free), update the hardcoded tool counts in server/transport tests (now 13) and the sorted name list, README. Commit `mcp: deterministic triage_findings + apply_triage (offline, host-agent reasons)`.

- [ ] **Phase 1 gate:** `npm run build && npm test && npm run lint && npm run format:check`; benchmark unchanged. Update `packages/agent/README.md` + qscan README triage section. Commit any docs.

---

# Phase 2 — Deterministic remediation

### Task 11: Patch-policy engine (core)

**Files:**
- Create: `packages/core/src/patch-policy.ts`, `packages/core/test/patch-policy.test.ts`
- Modify: `packages/core/src/index.ts`

**Interfaces:**
- Produces: `checkPatchPolicy(patch: Patch, ctx: { findingFiles: Set<string>; manifestFiles: Set<string> }): { allowed: boolean; reason?: string }`.
- Rule: allowed iff `patch.path` is in `findingFiles`, OR `patch.path` is a manifest AND the diff only adds dependency lines. Deny CI/lockfile/secret paths explicitly.

- [ ] **Step 1: failing tests** — a patch to a finding file is allowed; a patch to `.github/workflows/x.yml` is denied; a manifest patch adding a dep is allowed; a patch to an unrelated file is denied.
- [ ] **Steps 2–5:** implement + commit `core: patch-policy allowlist engine`.

---

### Task 12: Ephemeral worktree runner (core)

**Files:**
- Create: `packages/core/src/worktree.ts`, `packages/core/test/worktree.test.ts`

**Interfaces:**
- Produces: `withWorktree<T>(repoRoot: string, fn: (dir: string) => Promise<T>): Promise<T>` — creates `git worktree add --detach` in a temp dir, runs `fn`, always removes it (`git worktree remove --force`). Throws a clear error if `repoRoot` is not a git repo.

- [ ] **Step 1: failing test** — inside a temp `git init` repo, `withWorktree` yields a dir that exists during `fn` and is gone after; a throw in `fn` still cleans up. (Use `node:child_process` execFile; skip gracefully if `git` absent.)
- [ ] **Steps 2–5:** implement (execFile git), commit `core: ephemeral git worktree runner`.

---

### Task 13: Codemod registry + Patch type (core)

**Files:**
- Create: `packages/core/src/codemods/registry.ts`, `packages/core/test/codemods.test.ts`
- Modify: `packages/core/src/index.ts`

**Interfaces:**
- Produces: `interface Codemod { id: string; applies(f: Finding): boolean; apply(content: string, f: Finding): Patch | null }`; `codemodRegistry: Codemod[]`; `codemodFor(f: Finding): Codemod | undefined`.

- [ ] **Step 1: failing test** — `codemodFor` returns undefined for an unknown finding; registry has unique ids.
- [ ] **Steps 2–5:** implement the registry shell + commit `core: codemod registry + Codemod interface`.

---

### Task 14: Initial codemods (dependency-swap, config-toggle)

**Files:**
- Create: `packages/core/src/codemods/dependency-swap.ts`, `packages/core/src/codemods/config-toggle.ts`, `packages/core/test/codemods-golden.test.ts`
- Modify: `packages/core/src/codemods/registry.ts` (register them)

**Interfaces:**
- Consumes: `Codemod`, `Patch`, `Finding`.
- `dependency-swap`: for a `dep-vulnerable` finding, produce a `Patch` that adds a `// quantakrypto: migrate <pkg> → <pqc suggestion>` marker adjacent to the dep line and adds a suggested PQC/hybrid dep comment. Does NOT delete the classical dep.

- [ ] **Step 1: golden failing tests** — before/after content pairs for a `package.json` with `elliptic` and a TLS config file. Assert `apply()` output equals the golden and that `verifyFix` on a source codemod's result has the finding gone (for source rewrites only).
- [ ] **Steps 2–5:** implement both codemods, commit `core: dependency-swap + config-toggle codemods (golden-tested)`.

---

### Task 15: Remediation pipeline (core)

**Files:**
- Create: `packages/core/src/remediate-pipeline.ts`, `packages/core/test/remediate-pipeline.test.ts`
- Modify: `packages/core/src/index.ts`

**Interfaces:**
- Produces: `remediateFindings(findings, opts): Promise<RemediationResult>` where `opts = { repoRoot; readFile; patchSource: (f: Finding) => Promise<Patch | null>; verify?: boolean }` and `RemediationResult = { applied: VerifiedPatch[]; rejected: { finding: Finding; reason: string }[] }`.
- Pipeline per finding: `patchSource(f)` → `checkPatchPolicy` → apply in worktree → `verifyFix(newContent, {filename})` (finding gone + no new finding) → keep or reject-with-reason.

- [ ] **Step 1: failing tests** — a codemod patch that clears the finding is `applied`; a deliberately-bad patch (leaves the finding) is `rejected` with a verify reason; an out-of-policy patch is `rejected` with a policy reason.
- [ ] **Steps 2–5:** implement + commit `core: remediation pipeline (policy + worktree + verify gate)`.

---

### Task 16: `qremediate` CLI (`--mode diff|apply`)

**Files:**
- Create: `packages/qscan/src/remediate-cli.ts`, `packages/qscan/src/remediate-bin.ts`, `packages/qscan/test/remediate.test.ts`
- Modify: `packages/qscan/package.json` (`bin: { qremediate: "./dist/remediate-bin.js" }`), `packages/qscan/src/index.ts` (exports), help text

**Interfaces:**
- Consumes: `remediateFindings`, `codemodFor` (core), the scan.
- `--mode diff` prints unified diffs (compute with a tiny line-diff, zero-dep); `--mode apply` writes verified patches to the working tree. `--mode pr` is stubbed here to error "pr mode requires Phase 3 / --llm"; wired in Task 18–19.

- [ ] **Step 1: failing tests** — `diff` mode on a fixture repo prints a diff and writes nothing; `apply` mode writes the file and a re-scan shows the finding gone.
- [ ] **Steps 2–6:** implement, run full gate, commit `qscan: qremediate CLI (diff + apply modes, codemod-driven)`.

- [ ] **Phase 2 gate:** full gate green; benchmark unchanged.

---

# Phase 3 — BYOK LLM remediation + CI

### Task 17: LLM fix orchestrator (agent)

**Files:**
- Create: `packages/agent/src/remediate.ts`, `packages/agent/test/remediate.test.ts`
- Modify: `packages/agent/src/prompt.ts` (fix prompt), `packages/agent/src/index.ts`

**Interfaces:**
- Produces: `proposeFix(finding: Finding, opts: { client; level; readFile; fingerprint }): Promise<FixProposal | null>` — builds a fix request (redacted context), gets `{ path, diff|newContent, explanation }`, returns a `FixProposal`. Returns null if the model declines.

- [ ] **Step 1: failing test** — fake client returns a `newContent` that removes the finding; `proposeFix` returns a `FixProposal` with that content. Commit `agent: LLM fix orchestrator (proposeFix)`.

---

### Task 18: `qremediate --llm` + `--mode pr`

**Files:**
- Modify: `packages/qscan/src/remediate-cli.ts` (wire `--llm` → `proposeFix` as the pipeline's `patchSource` fallback after codemods; `--mode pr` opens a draft PR), `packages/qscan/test/remediate.test.ts`

**Interfaces:**
- Consumes: `proposeFix` (agent, dynamic import), `remediateFindings` (core).
- `--llm`: for findings with no codemod, use `proposeFix` as the patch source; everything still runs the policy + verify gate.
- `--mode pr`: commit verified patches to a new branch and open a **draft** PR via `gh` (local) or `GITHUB_TOKEN` REST (CI). Body lists each patch + verify result + context level sent. Never merges. If no PR backend available, fall back to `apply` + print instructions.

- [ ] **Step 1: failing tests** — with a fake `proposeFix`, `--llm --mode diff` shows the LLM patch's diff; the PR backend is behind an injectable `openDraftPr` function asserted to be called with `draft: true` and never a merge. Commit `qscan: qremediate --llm + draft-PR mode (verify-gated, no auto-merge)`.

---

### Task 19: MCP `remediate_findings`

**Files:**
- Modify: `packages/mcp/src/tools.ts` (tool + list), `packages/mcp/test/*.test.ts` (counts → 14), README

**Interfaces:**
- `remediate_findings(findings|scan args, contextLevel?)` → returns a fix-request bundle `{ instructions, schema, contexts }` for the host agent; plus documents the deterministic `verify_fix`/apply loop the agent should call. **No network.**

- [ ] **Steps:** add tool, update counts/names, README. Commit `mcp: deterministic remediate_findings request bundle (offline)`.

---

### Task 20: `comment-plan` (action)

**Files:**
- Modify: `packages/action/src/main.ts` (new mode), `packages/action/action.yml` (input `mode: scan|comment-plan`), `packages/action/test/*.test.ts`
- Re-bundle: `npm run bundle -w @quantakrypto/action`

**Interfaces:**
- Consumes: the deterministic migration plan (from core's `plan_migration` logic — extract to `core` if still MCP-only) + the existing PR-comment upsert.
- `comment-plan`: run a scan, build the deterministic HNDL-first plan, upsert it as a PR comment. No key. Optional `--triage` enrichment only when a key is present.

- [ ] **Steps:** implement, add tests, **re-bundle dist and verify `git diff --exit-code packages/action/dist` after staging**, commit `action: comment-plan mode (deterministic migration plan → PR comment)`.

- [ ] **Phase 3 gate:** full gate + `npm run bundle -w @quantakrypto/action` fresh + benchmark unchanged.

---

## Final wrap

- [ ] Update `docs/superpowers/specs/2026-07-03-byok-agent-tools-design.md` status → Implemented.
- [ ] Update the vault backlog (`Projects/quantakrypto — pqc-tools Audit Backlog.md`): mark the BYOK agent tools DONE (unpublished), note the new `@quantakrypto/agent` package + `qremediate` bin.
- [ ] Full gate one last time; confirm CI green on `main`. Do **not** publish.

---

## Self-Review

**Spec coverage:** Triage (§5 spec → Tasks 8–10), deterministic remediation (§6 → Tasks 11–16), LLM remediation (§7 → Tasks 17–19), comment-plan (§8 → Task 20), `@quantakrypto/agent` isolation (§4,§9 → Tasks 1,4–8,17), redactor in core (§4.2 → Task 3), verify gate (§2 → Tasks 2,15), privacy table (§10 → Tasks 3,9), testing (§11 → each task's tests). All covered.

**Type consistency:** `TriageVerdict`/`Patch`/`FixProposal`/`ContextLevel`/`RedactedContext` are defined once in `core/src/agent-types.ts` (Task 3) and consumed by name everywhere. `LlmClient`/`LlmConfig`/`LlmRequest` defined in `agent/src/client.ts` (Task 4). `verifyFix` signature fixed in Task 2 and reused in Tasks 15/16. `resolveClient` (Task 6) used by qscan (Task 9) and qremediate (Task 18).

**Placeholder scan:** Tasks 7, 10, 12–14, 19–20 compress repeated TDD boilerplate into "follow the pattern" step ranges where the pattern is an already-shown sibling (cache→Task 7 mirrors core cache; codemods→golden pattern). Central code for every novel interface is shown in full.
