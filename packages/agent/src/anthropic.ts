/**
 * Anthropic Messages API adapter (native fetch, zero deps). The system + user +
 * schema are bundled into a single user message so {@link completeWith} can
 * uniformly repair-retry; the API key travels only in the `x-api-key` header.
 */
import type { LlmClient, LlmConfig, LlmRequest } from "./client.js";
import { completeWith } from "./loop.js";

const DEFAULT_BASE = "https://api.anthropic.com";

export function anthropicClient(config: LlmConfig, fetchImpl: typeof fetch = fetch): LlmClient {
  const base = (config.baseURL ?? DEFAULT_BASE).replace(/\/+$/, "");

  function makeCall(maxTokens: number): (prompt: string) => Promise<string> {
    return async (prompt) => {
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
            max_tokens: maxTokens,
            temperature: config.temperature ?? 0,
            messages: [{ role: "user", content: prompt }],
          }),
        });
        if (!res.ok) throw new Error(`anthropic: HTTP ${res.status}`);
        const json = (await res.json()) as { content?: { type: string; text?: string }[] };
        return (json.content ?? []).map((b) => b.text ?? "").join("");
      } finally {
        clearTimeout(timer);
      }
    };
  }

  return {
    complete(req: LlmRequest): Promise<unknown> {
      return completeWith(makeCall(req.maxTokens), req, config.maxRetries ?? 1, "anthropic");
    },
  };
}
