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
    { provider: "openai-compatible", baseURL: "http://x", model: "m", apiKey: "k" },
    fakeFetch({}),
  );
  assert.equal(typeof a.complete, "function");
  assert.equal(typeof o.complete, "function");
});
