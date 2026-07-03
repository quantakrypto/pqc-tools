import { test } from "node:test";
import assert from "node:assert/strict";

import { proposeFix } from "../src/remediate.js";
import type { LlmClient } from "../src/client.js";
import type { Finding } from "@quantakrypto/core";

function rsaFinding(file = "a.ts"): Finding {
  return {
    ruleId: "node-crypto-keygen",
    title: "RSA keygen",
    category: "kem",
    severity: "high",
    confidence: "high",
    hndl: true,
    message: "RSA is classical",
    location: { file, line: 1 },
  };
}

const RSA_SRC = "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n";

test("proposeFix returns a full-file proposal from the model", async () => {
  const client: LlmClient = {
    complete: async () => ({
      path: "a.ts",
      newContent: "const k = mlkem768.keygen();\n",
      explanation: "replaced RSA with ML-KEM",
    }),
  };
  const proposal = await proposeFix(rsaFinding(), {
    client,
    readFile: async () => RSA_SRC,
    fingerprint: () => "fp1",
  });
  assert.equal(proposal?.newContent, "const k = mlkem768.keygen();\n");
  assert.equal(proposal?.fingerprint, "fp1");
});

test("proposeFix returns null when the model echoes the input unchanged", async () => {
  const client: LlmClient = {
    complete: async () => ({ path: "a.ts", newContent: RSA_SRC, explanation: "no change" }),
  };
  const p = await proposeFix(rsaFinding(), {
    client,
    readFile: async () => RSA_SRC,
    fingerprint: () => "fp",
  });
  assert.equal(p, null);
});

test("proposeFix skips a secret-bearing file entirely (no model call)", async () => {
  let called = false;
  const client: LlmClient = {
    complete: async () => {
      called = true;
      return { path: "a.ts", newContent: "x", explanation: "y" };
    },
  };
  const withSecret = `${RSA_SRC}const key = \`-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\`;\n`;
  const p = await proposeFix(rsaFinding(), {
    client,
    readFile: async () => withSecret,
    fingerprint: () => "fp",
  });
  assert.equal(p, null);
  assert.equal(called, false, "the model is never asked to rewrite a file with secrets");
});

test("proposeFix rejects a proposal that contains the redaction placeholder", async () => {
  const client: LlmClient = {
    complete: async () => ({
      path: "a.ts",
      newContent: "const k = mlkem768.keygen();\nconst s = «redacted-secret»;\n",
      explanation: "x",
    }),
  };
  const p = await proposeFix(rsaFinding(), {
    client,
    readFile: async () => RSA_SRC,
    fingerprint: () => "fp",
  });
  assert.equal(p, null);
});
