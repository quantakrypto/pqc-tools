/**
 * @quantakrypto/agent — BYOK LLM client for qScan triage and remediation.
 *
 * This is the ONLY networked package in the monorepo: it talks to an LLM
 * provider over native `fetch` (zero third-party dependencies). All
 * deterministic pieces (the context redactor, the verify gate, codemods, the
 * patch-policy engine) live in `@quantakrypto/core` so the offline MCP plane
 * reuses them without ever loading this package.
 */
export const AGENT_PACKAGE = "@quantakrypto/agent";

export type { LlmClient, LlmConfig, LlmRequest } from "./client.js";
export { resolveClient } from "./client.js";
export { anthropicClient } from "./anthropic.js";
export { openAiCompatibleClient } from "./openai.js";
export type { JsonSchema } from "./validate.js";
export { validateAgainstSchema } from "./validate.js";
export { triageFindings } from "./triage.js";
export type { TriageOptions } from "./triage.js";
export { proposeFix, FIX_PROMPT_VERSION } from "./remediate.js";
export type { ProposeFixOptions } from "./remediate.js";
export { TRIAGE_PROMPT_VERSION } from "./prompt.js";
export { loadResponseCache, saveResponseCache, cacheKey } from "./response-cache.js";
