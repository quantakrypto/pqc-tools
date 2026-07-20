import { test } from "node:test";
import assert from "node:assert/strict";

import { openAiCompatibleClient } from "../src/openai.js";
import { resolveClient } from "../src/client.js";

function fakeFetch(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;
}

const schema = {
  type: "object",
  required: ["priority"],
  properties: { priority: { enum: ["now", "soon", "later"] } },
};

test("openai adapter reads choices[0].message.content", async () => {
  const payload = { choices: [{ message: { content: JSON.stringify({ priority: "now" }) } }] };
  const client = openAiCompatibleClient(
    { provider: "openai-compatible", baseURL: "http://x", model: "m", apiKey: "k" },
    fakeFetch(payload),
  );
  const out = (await client.complete({ system: "s", user: "u", schema, maxTokens: 128 })) as {
    priority: string;
  };
  assert.equal(out.priority, "now");
});

test("resolveClient dispatches by provider", () => {
  const a = resolveClient({ provider: "anthropic", model: "m", apiKey: "k" }, fakeFetch({}));
  const o = resolveClient(
    { provider: "openai-compatible", baseURL: "https://x", model: "m", apiKey: "k" },
    fakeFetch({}),
  );
  assert.equal(typeof a.complete, "function");
  assert.equal(typeof o.complete, "function");
});

test("openai adapter surfaces an HTTP error", async () => {
  const errFetch = (async () =>
    new Response("upstream boom", { status: 500 })) as unknown as typeof fetch;
  const client = openAiCompatibleClient(
    { provider: "openai-compatible", baseURL: "https://x", model: "m", apiKey: "k" },
    errFetch,
  );
  await assert.rejects(
    () => client.complete({ system: "s", user: "u", schema, maxTokens: 128 }),
    /HTTP 500/,
  );
});

test("openai adapter aborts a hung request when the timeout fires", async () => {
  const hangUntilAbort = (async (_url: string, init: { signal: AbortSignal }) =>
    new Promise<Response>((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted by signal")));
    })) as unknown as typeof fetch;
  const client = openAiCompatibleClient(
    { provider: "openai-compatible", baseURL: "https://x", model: "m", apiKey: "k", timeoutMs: 20 },
    hangUntilAbort,
  );
  await assert.rejects(
    () => client.complete({ system: "s", user: "u", schema, maxTokens: 128 }),
    /aborted/,
  );
});

test("openai adapter propagates a transport (network) error", async () => {
  const netFail = (async () => {
    throw new Error("ENOTFOUND api.openai.com");
  }) as unknown as typeof fetch;
  const client = openAiCompatibleClient(
    { provider: "openai-compatible", baseURL: "https://x", model: "m", apiKey: "k" },
    netFail,
  );
  await assert.rejects(
    () => client.complete({ system: "s", user: "u", schema, maxTokens: 128 }),
    /ENOTFOUND/,
  );
});

test("the API key travels ONLY in the Authorization header, never in the URL or body", async () => {
  const SECRET = "sk-openai-SECRET-xyz789";
  let captured: { url: string; init: { headers: Record<string, string>; body: string } } = {
    url: "",
    init: { headers: {}, body: "" },
  };
  const capFetch = (async (
    url: string,
    init: { headers: Record<string, string>; body: string },
  ) => {
    captured = { url, init };
    return new Response(
      JSON.stringify({
        choices: [{ message: { content: JSON.stringify({ priority: "later" }) } }],
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;
  const client = openAiCompatibleClient(
    { provider: "openai-compatible", baseURL: "https://x", model: "m", apiKey: SECRET },
    capFetch,
  );
  await client.complete({ system: "s", user: "u", schema, maxTokens: 64 });
  assert.equal(captured.init.headers["authorization"], `Bearer ${SECRET}`, "key is in the header");
  assert.doesNotMatch(captured.url, /SECRET/, "key is not in the request URL");
  assert.doesNotMatch(captured.init.body, /SECRET/, "key is not in the request body");
});

test("resolveClient refuses a plaintext non-local baseURL (key-exfil guard)", () => {
  assert.throws(
    () =>
      resolveClient(
        {
          provider: "openai-compatible",
          baseURL: "http://evil.example/v1",
          model: "m",
          apiKey: "k",
        },
        fakeFetch({}),
      ),
    /https/,
  );
  // http is allowed for loopback (local LLM servers like Ollama/vLLM).
  assert.doesNotThrow(() =>
    resolveClient(
      {
        provider: "openai-compatible",
        baseURL: "http://localhost:11434/v1",
        model: "m",
        apiKey: "k",
      },
      fakeFetch({}),
    ),
  );
});
