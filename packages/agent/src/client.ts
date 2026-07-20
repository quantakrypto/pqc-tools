/**
 * The provider-agnostic LLM client contract. Adapters (anthropic.ts, openai.ts)
 * implement {@link LlmClient}; {@link resolveClient} picks one from config.
 */
import type { JsonSchema } from "./validate.js";
import { anthropicClient } from "./anthropic.js";
import { openAiCompatibleClient } from "./openai.js";

/** A single structured completion request. */
export interface LlmRequest {
  system: string;
  user: string;
  /** JSON Schema the response MUST satisfy (validated + repair-retried). */
  schema: JsonSchema;
  maxTokens: number;
}

/** A provider adapter: turns an {@link LlmRequest} into schema-valid JSON. */
export interface LlmClient {
  complete(req: LlmRequest): Promise<unknown>;
}

/** BYOK provider configuration. `apiKey` is resolved from env by the caller. */
export interface LlmConfig {
  provider: "anthropic" | "openai-compatible";
  /** Override the provider's default base URL (e.g. a local or Azure endpoint). */
  baseURL?: string;
  model: string;
  apiKey: string;
  /** Sampling temperature; defaults to 0 for reproducibility. */
  temperature?: number;
  timeoutMs?: number;
  /** Repair retries on an invalid response. Defaults to 1. */
  maxRetries?: number;
}

/**
 * Reject a base URL that would send the BYOK key over plaintext to a non-local
 * host. A poisoned `baseURL` must not be able to redirect the API key + code
 * context to an attacker endpoint over http (agent audit — provider spoofing).
 * Plain http is permitted only for loopback (local LLM servers: Ollama/vLLM).
 */
function assertSafeBaseUrl(baseURL: string | undefined): void {
  if (!baseURL) return;
  let u: URL;
  try {
    u = new URL(baseURL);
  } catch {
    throw new Error(`invalid LLM baseURL: ${baseURL}`);
  }
  const isLoopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopback)) {
    throw new Error(
      `refusing to send the API key over ${u.protocol}//${u.hostname} — the LLM baseURL must use https (http is allowed only for localhost).`,
    );
  }
}

/** Pick the adapter for `config.provider`. `fetchImpl` is injectable for tests. */
export function resolveClient(config: LlmConfig, fetchImpl: typeof fetch = fetch): LlmClient {
  assertSafeBaseUrl(config.baseURL);
  return config.provider === "anthropic"
    ? anthropicClient(config, fetchImpl)
    : openAiCompatibleClient(config, fetchImpl);
}
