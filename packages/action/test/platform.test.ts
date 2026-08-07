import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  conformanceResult,
  isAllowedResultUrl,
  RESULT_ORIGIN,
  crashedResult,
  postResult,
  readDispatchContext,
  scoredResult,
  toPayloadFindings,
} from "../src/platform.js";

/**
 * This module replaces the `jq` that used to live inside every user's workflow.
 * That placement was the defect: payload logic in repositories we do not
 * control cannot be fixed. These tests pin the behaviour that was wrong there.
 */

const dir = mkdtempSync(join(tmpdir(), "quantakrypto-platform-"));
function eventFile(payload: unknown): NodeJS.ProcessEnv {
  const path = join(dir, `event-${Math.abs(JSON.stringify(payload).length)}.json`);
  writeFileSync(path, JSON.stringify(payload));
  return { GITHUB_EVENT_PATH: path };
}

test("reads the dispatch context the platform sends", () => {
  const env = eventFile({
    action: "quantakrypto-scan",
    client_payload: {
      auditRunId: "au-1",
      token: "tok",
      resultUrl: "https://quantakrypto.com/api/github/scan-result",
    },
  });
  assert.deepEqual(readDispatchContext(env), {
    auditRunId: "au-1",
    token: "tok",
    resultUrl: "https://quantakrypto.com/api/github/scan-result",
    eventType: "quantakrypto-scan",
  });
});

/**
 * An ordinary CI run must report nowhere. The action still gates the build; it
 * simply has no audit run to speak for.
 */
test("returns null for a run the platform did not trigger", () => {
  assert.equal(readDispatchContext({}), null);
  assert.equal(readDispatchContext(eventFile({ pull_request: { number: 3 } })), null);
  assert.equal(readDispatchContext({ GITHUB_EVENT_PATH: join(dir, "does-not-exist.json") }), null);
});

test("a partial client_payload reports nothing rather than guessing", () => {
  for (const partial of [
    { auditRunId: "au-1", token: "tok" },
    { auditRunId: "au-1", resultUrl: "https://quantakrypto.com/api/github/scan-result" },
    { token: "tok", resultUrl: "https://quantakrypto.com/api/github/scan-result" },
    { auditRunId: "", token: "tok", resultUrl: "https://quantakrypto.com/api/github/scan-result" },
  ]) {
    assert.equal(readDispatchContext(eventFile({ client_payload: partial })), null);
  }
});

test("survives a malformed event file", () => {
  const path = join(dir, "garbage.json");
  writeFileSync(path, "{not json");
  assert.equal(readDispatchContext({ GITHUB_EVENT_PATH: path }), null);
});

test("maps findings to the payload shape and caps them", () => {
  const many = Array.from({ length: 250 }, (_, i) => ({
    ruleId: `r${i}`,
    severity: "high",
    title: "t",
    location: { file: "a.ts", line: i },
  }));
  const out = toPayloadFindings(many);
  assert.equal(out.length, 200, "must not post more than the server keeps");
  assert.deepEqual(out[0], { rule: "r0", severity: "high", file: "a.ts", line: 0, message: "t" });
});

test("omits absent fields rather than emitting nulls", () => {
  assert.deepEqual(toPayloadFindings([{ title: "just a message" }]), [
    { message: "just a message" },
  ]);
});

test("a scored check reports its score and findings", () => {
  const r = scoredResult("qScan", 66, [{ ruleId: "x", severity: "high", title: "t" }]);
  assert.equal(r.status, "complete");
  assert.equal(r.score, 66);
  assert.match(r.summary, /qScan: 1 finding\(s\), readiness 66\/100/);
});

/**
 * The case that started all of this: `--impl` pointing at a file that does not
 * exist made every probe fail with the same spawn error, and the run was
 * ingested as a completed verdict carrying ~35 high-severity crypto defects
 * against code that never executed.
 */
test("a conformance run that never executed is reported as failed, not as a verdict", () => {
  const report = {
    param: "ml-kem-768",
    overall: "ERROR",
    impl: ["node", "./my-impl.js"],
    counts: { pass: 0, fail: 35, skip: 1 },
    categories: [
      {
        category: "correctness",
        checks: Array.from({ length: 35 }, (_, i) => ({
          name: `roundtrip[${i}]`,
          status: "fail",
          detail: "harness error: SUT exited with code 1",
        })),
      },
    ],
  };
  const r = conformanceResult(report, ".github/workflows/quantakrypto.yml");

  // Not a verdict: keeps it out of badges and the posture series.
  assert.equal(r.status, "failed");
  assert.equal(r.score, null);
  // 35 identical failures collapse to the one actionable item.
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0]?.rule, "harness/implementation-not-runnable");
  assert.match(r.findings[0]?.message ?? "", /node \.\/my-impl\.js/);
  assert.match(r.findings[0]?.message ?? "", /quantakrypto\.yml/);
  assert.doesNotMatch(r.summary, /FAIL/);
});

/**
 * The guard must also hold against Sieve releases that predate the ERROR
 * verdict, which reported the same situation as overall: "FAIL".
 */
test("counts.pass === 0 is enough, without the ERROR verdict", () => {
  const r = conformanceResult(
    {
      param: "ml-kem-768",
      overall: "FAIL",
      counts: { pass: 0, fail: 2 },
      categories: [{ category: "sizes", checks: [{ name: "a", status: "fail", detail: "boom" }] }],
    },
    "wf.yml",
  );
  assert.equal(r.status, "failed");
});

test("a real conformance failure stays a verdict with its findings", () => {
  const r = conformanceResult(
    {
      param: "ml-kem-768",
      overall: "FAIL",
      counts: { pass: 12, fail: 1 },
      categories: [
        {
          category: "implicit-rejection",
          checks: [
            { name: "reject-malformed", status: "fail", detail: "returned a usable secret" },
            { name: "reject-truncated", status: "pass", detail: "ok" },
          ],
        },
      ],
    },
    "wf.yml",
  );
  assert.equal(r.status, "complete");
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0]?.rule, "implicit-rejection/reject-malformed");
  assert.match(r.summary, /FAIL, 1 failing check/);
});

test("a passing conformance run has no findings", () => {
  const r = conformanceResult(
    { param: "ml-kem-768", overall: "PASS", counts: { pass: 13, fail: 0 }, categories: [] },
    "wf.yml",
  );
  assert.equal(r.status, "complete");
  assert.deepEqual(r.findings, []);
  assert.match(r.summary, /PASS, 0 failing check/);
});

test("a crashed check reports the reason", () => {
  const r = crashedResult("qProbe", "spawn ENOENT");
  assert.equal(r.status, "failed");
  assert.match(r.summary, /qProbe did not produce a result: spawn ENOENT/);
});

test("posts the payload with the run id and token merged in", async () => {
  let seen: { url: string; body: unknown } | null = null;
  const ok = await postResult(
    {
      auditRunId: "au-9",
      token: "tok-9",
      resultUrl: "https://quantakrypto.com/api/github/scan-result",
      eventType: null,
    },
    scoredResult("qScan", 100, []),
    (async (url: string, init: { body: string }) => {
      seen = { url, body: JSON.parse(init.body) };
      return { ok: true } as Response;
    }) as unknown as typeof fetch,
  );
  assert.ok(ok);
  assert.equal(seen!.url, "https://quantakrypto.com/api/github/scan-result");
  assert.equal((seen!.body as { auditRunId: string }).auditRunId, "au-9");
  assert.equal((seen!.body as { token: string }).token, "tok-9");
});

/**
 * The check already ran and its verdict is on the job summary either way, so a
 * reporting failure must never fail someone's build.
 */
test("a failed post is reported, never thrown", async () => {
  const rejecting = (() => Promise.reject(new Error("network"))) as unknown as typeof fetch;
  const ctx = {
    auditRunId: "a",
    token: "t",
    resultUrl: "https://quantakrypto.com/api/github/scan-result",
    eventType: null,
  };
  assert.equal(await postResult(ctx, crashedResult("qScan", "x"), rejecting), false);

  const notOk = (async () => ({ ok: false }) as Response) as unknown as typeof fetch;
  assert.equal(await postResult(ctx, crashedResult("qScan", "x"), notOk), false);
});

/**
 * `resultUrl` arrives in the dispatch payload, and firing a repository_dispatch
 * needs contents:write — which any repo collaborator has. Unpinned, whoever
 * composes that payload chooses where a token-bearing POST lands: cleartext
 * http, an arbitrary host, or an address inside a self-hosted runner's network.
 */
test("only https on our own origin may receive the token", () => {
  assert.ok(isAllowedResultUrl(`${RESULT_ORIGIN}/api/github/scan-result`));
  assert.ok(isAllowedResultUrl(`${RESULT_ORIGIN}/anything`));

  assert.ok(!isAllowedResultUrl("http://quantakrypto.com/api"), "cleartext");
  assert.ok(!isAllowedResultUrl("https://evil.test/collect"), "another origin");
  assert.ok(!isAllowedResultUrl("https://quantakrypto.com.evil.test/"), "suffix lookalike");
  assert.ok(!isAllowedResultUrl("https://quantakrypto.com:8443/"), "origin includes the port");
  assert.ok(!isAllowedResultUrl("file:///etc/passwd"), "non-http scheme");
  assert.ok(!isAllowedResultUrl("not a url"), "unparseable");
  assert.ok(!isAllowedResultUrl(""), "empty");
});

test("a dispatch naming a foreign resultUrl is refused outright", () => {
  const env = eventFile({
    action: "quantakrypto-scan",
    client_payload: { auditRunId: "au-1", token: "tok", resultUrl: "https://evil.test/collect" },
  });
  // Not "post nothing to it" — no context at all, so no later code path can use it.
  assert.equal(readDispatchContext(env), null);
});

test("only a repository_dispatch may carry a platform payload", () => {
  const base = {
    action: "quantakrypto-scan",
    client_payload: {
      auditRunId: "au-1",
      token: "tok",
      resultUrl: `${RESULT_ORIGIN}/api/github/scan-result`,
    },
  };
  const env = eventFile(base);
  assert.ok(readDispatchContext({ ...env, GITHUB_EVENT_NAME: "repository_dispatch" }));
  assert.equal(readDispatchContext({ ...env, GITHUB_EVENT_NAME: "pull_request" }), null);
  assert.equal(readDispatchContext({ ...env, GITHUB_EVENT_NAME: "workflow_dispatch" }), null);
});
