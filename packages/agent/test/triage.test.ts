import { test } from "node:test";
import assert from "node:assert/strict";

import { triageFindings } from "../src/triage.js";
import type { LlmClient } from "../src/client.js";
import type { Finding } from "@quantakrypto/core";

const client: LlmClient = {
  complete: async () => ({ exposureScore: 70, priority: "now", rationale: "reachable" }),
};

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "node-crypto-ecdh",
    title: "ECDH",
    category: "key-exchange",
    severity: "high",
    confidence: "high",
    hndl: true,
    message: "m",
    location: { file: "a.ts", line: 1 },
    ...over,
  };
}

test("triage returns a verdict per above-floor finding, keyed by fingerprint", async () => {
  const verdicts = await triageFindings([finding()], {
    client,
    level: "metadata",
    readFile: async () => "",
    fingerprint: () => "fp1",
    floor: "medium",
  });
  assert.equal(verdicts.get("fp1")?.exposureScore, 70);
  assert.equal(verdicts.get("fp1")?.priority, "now");
});

test("findings below the floor are skipped (no provider call)", async () => {
  let calls = 0;
  const counting: LlmClient = {
    complete: async () => {
      calls++;
      return { exposureScore: 1, priority: "later", rationale: "x" };
    },
  };
  const verdicts = await triageFindings([finding({ severity: "info" })], {
    client: counting,
    level: "metadata",
    readFile: async () => "",
    fingerprint: () => "fp-info",
    floor: "medium",
  });
  assert.equal(verdicts.size, 0);
  assert.equal(calls, 0);
});
