import { test } from "node:test";
import assert from "node:assert/strict";

import { anthropicClient } from "../src/anthropic.js";

function fakeFetch(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

const schema = {
  type: "object",
  required: ["exposureScore", "priority"],
  properties: {
    exposureScore: { type: "number" },
    priority: { enum: ["now", "soon", "later"] },
  },
};

test("anthropic adapter parses a JSON response and validates it", async () => {
  const payload = {
    content: [{ type: "text", text: JSON.stringify({ exposureScore: 55, priority: "soon" }) }],
  };
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "k" },
    fakeFetch(payload),
  );
  const out = (await client.complete({ system: "s", user: "u", schema, maxTokens: 256 })) as {
    exposureScore: number;
  };
  assert.equal(out.exposureScore, 55);
});

test("adapter throws on persistently invalid JSON (after repair)", async () => {
  const bad = { content: [{ type: "text", text: "not json at all" }] };
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "k" },
    fakeFetch(bad),
  );
  await assert.rejects(() => client.complete({ system: "s", user: "u", schema, maxTokens: 256 }));
});

test("adapter surfaces an HTTP error", async () => {
  const errFetch = (async () => new Response("nope", { status: 401 })) as unknown as typeof fetch;
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "bad" },
    errFetch,
  );
  await assert.rejects(
    () => client.complete({ system: "s", user: "u", schema, maxTokens: 256 }),
    /HTTP 401/,
  );
});
