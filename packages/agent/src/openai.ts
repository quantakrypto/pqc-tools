/**
 * OpenAI-compatible chat/completions adapter (native fetch, zero deps). Covers
 * OpenAI, Azure OpenAI, OpenRouter, and local servers (Ollama/vLLM) via
 * `config.baseURL`. Same repair-retry loop as the Anthropic adapter.
 */
import type { LlmClient, LlmConfig, LlmRequest } from "./client.js";
import { completeWith } from "./loop.js";

const DEFAULT_BASE = "https://api.openai.com/v1";

export function openAiCompatibleClient(
  config: LlmConfig,
  fetchImpl: typeof fetch = fetch,
): LlmClient {
  const base = (config.baseURL ?? DEFAULT_BASE).replace(/\/+$/, "");

  function makeCall(
    maxTokens: number,
  ): (payload: { system: string; user: string }) => Promise<string> {
    return async ({ system, user }) => {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), config.timeoutMs ?? 30_000);
      try {
        const res = await fetchImpl(`${base}/chat/completions`, {
          method: "POST",
          signal: ctrl.signal,
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${config.apiKey}`,
          },
          body: JSON.stringify({
            model: config.model,
            max_tokens: maxTokens,
            temperature: config.temperature ?? 0,
            messages: [
              { role: "system", content: system },
              { role: "user", content: user },
            ],
          }),
        });
        if (!res.ok) throw new Error(`openai-compatible: HTTP ${res.status}`);
        const json = (await res.json()) as {
          choices?: { message?: { content?: string } }[];
        };
        return json.choices?.[0]?.message?.content ?? "";
      } finally {
        clearTimeout(timer);
      }
    };
  }

  return {
    complete(req: LlmRequest): Promise<unknown> {
      return completeWith(
        makeCall(req.maxTokens),
        req,
        config.maxRetries ?? 1,
        "openai-compatible",
      );
    },
  };
}
