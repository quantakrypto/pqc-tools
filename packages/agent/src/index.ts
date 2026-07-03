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
