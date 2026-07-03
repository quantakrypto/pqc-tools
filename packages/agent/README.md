# @quantakrypto/agent

BYOK (bring-your-own-key) LLM client for [qScan](https://www.npmjs.com/package/@quantakrypto/qscan) triage and remediation. **Native `fetch`, zero third-party runtime dependencies.**

This is the only networked package in the quantakrypto toolset. All deterministic
pieces (the context redactor, the `verify_fix` gate, codemods, the patch-policy
engine) live in [`@quantakrypto/core`](https://www.npmjs.com/package/@quantakrypto/core),
so the offline MCP server never loads this package.

## What it provides

- **`resolveClient(config)`** → an `LlmClient` for `anthropic` or any
  `openai-compatible` endpoint (baseURL + key + model). Responses are
  JSON-schema-validated with one repair-retry.
- **`triageFindings(findings, opts)`** — ask the model for an exposure verdict
  per finding (annotate + re-rank, never suppress).
- **`proposeFix(finding, opts)`** — ask the model for a corrected full file. Skips
  any file containing secrets; the result is gated downstream by `verify_fix`.
- A response cache keyed by `(promptVersion, model, contextLevel, fingerprint)`
  so reruns are reproducible and cheap.

## Usage

You normally reach these through `qscan --triage` and `qremediate --llm` rather
than directly. The BYOK key is read from the environment: `QK_LLM_API_KEY`, or the
provider-native `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.

```ts
import { resolveClient, triageFindings } from "@quantakrypto/agent";

const client = resolveClient({
  provider: "anthropic",
  model: "claude-sonnet-5",
  apiKey: process.env.ANTHROPIC_API_KEY!,
});

const verdicts = await triageFindings(findings, {
  client,
  level: "snippet", // metadata | snippet | function | file — secrets always redacted
  readFile: (p) => fs.promises.readFile(p, "utf8"),
  fingerprint: fingerprintFinding,
});
```

## Guarantees

- **Secrets never leave.** Findings whose match is key material are always
  redacted; a file with any stripped secret is never sent for a full-file rewrite.
- **Zero third-party runtime deps** — native `fetch` only.
- **Only the configured endpoint is contacted.** No telemetry.

Apache-2.0 · [quantakrypto.com/tools](https://quantakrypto.com/tools)
