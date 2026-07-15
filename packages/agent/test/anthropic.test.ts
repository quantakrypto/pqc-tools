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

test("rubric goes in the system field; untrusted content stays in the user message", async () => {
  let sent: { system?: string; messages?: { role: string; content: string }[] } = {};
  const capFetch = (async (_url: string, init: { body: string }) => {
    sent = JSON.parse(init.body);
    return new Response(
      JSON.stringify({
        content: [{ type: "text", text: JSON.stringify({ exposureScore: 1, priority: "later" }) }],
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "k" },
    capFetch,
  );
  await client.complete({
    system: "RUBRIC_MARKER",
    user: "UNTRUSTED_MARKER",
    schema,
    maxTokens: 128,
  });
  assert.match(sent.system ?? "", /RUBRIC_MARKER/, "rubric is in the system field");
  assert.match(sent.system ?? "", /untrusted/i, "system carries the anti-injection guard");
  assert.equal(sent.messages?.length, 1);
  assert.equal(sent.messages?.[0].role, "user");
  assert.match(sent.messages?.[0].content ?? "", /UNTRUSTED_MARKER/);
  assert.doesNotMatch(
    sent.messages?.[0].content ?? "",
    /RUBRIC_MARKER/,
    "rubric is NOT in the user turn",
  );
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
