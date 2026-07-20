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

test("adapter aborts a hung request when the timeout fires", async () => {
  // The fetch only settles when the request's AbortSignal fires, so this proves
  // the adapter's timeout actually aborts an unresponsive endpoint.
  const hangUntilAbort = (async (_url: string, init: { signal: AbortSignal }) =>
    new Promise<Response>((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted by signal")));
    })) as unknown as typeof fetch;
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "k", timeoutMs: 20 },
    hangUntilAbort,
  );
  await assert.rejects(
    () => client.complete({ system: "s", user: "u", schema, maxTokens: 256 }),
    /aborted/,
  );
});

test("adapter propagates a transport (network) error", async () => {
  const netFail = (async () => {
    throw new Error("ECONNREFUSED 127.0.0.1:443");
  }) as unknown as typeof fetch;
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: "k" },
    netFail,
  );
  await assert.rejects(
    () => client.complete({ system: "s", user: "u", schema, maxTokens: 256 }),
    /ECONNREFUSED/,
  );
});

test("the API key travels ONLY in the x-api-key header, never in the URL or body", async () => {
  const SECRET = "sk-ant-SECRET-abc123";
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
        content: [{ type: "text", text: JSON.stringify({ exposureScore: 1, priority: "later" }) }],
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;
  const client = anthropicClient(
    { provider: "anthropic", model: "claude-x", apiKey: SECRET },
    capFetch,
  );
  await client.complete({ system: "s", user: "u", schema, maxTokens: 64 });
  assert.equal(captured.init.headers["x-api-key"], SECRET, "key is in the x-api-key header");
  assert.doesNotMatch(captured.url, /SECRET/, "key is not in the request URL");
  assert.doesNotMatch(captured.init.body, /SECRET/, "key is not in the request body");
});
