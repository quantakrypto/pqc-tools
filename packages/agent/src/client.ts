/**
 * The provider-agnostic LLM client contract. Adapters (anthropic.ts, openai.ts)
 * implement {@link LlmClient}; {@link resolveClient} picks one from config.
 */
import type { JsonSchema } from "./validate.js";

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
