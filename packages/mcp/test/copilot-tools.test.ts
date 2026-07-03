/**
 * Tests for the copilot tools (plan_migration / get_fix_examples / verify_fix /
 * check_dependency / score_delta) — the "migrate through the engine" surface.
 * Driven through the server so the MCP envelope contract is exercised too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import process from "node:process";
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createQuantakryptoServer } from "../src/index.js";
import type { JsonRpcSuccess, ToolContext } from "../src/protocol.js";

interface ToolCallResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

async function callTool(
  name: string,
  args: Record<string, unknown>,
  context?: ToolContext,
): Promise<ToolCallResult> {
  const server = createQuantakryptoServer();
  const res = await server.handle(
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } },
    context,
  );
  assert.ok(res && "result" in (res as object), `tools/call ${name} should succeed`);
  return (res as JsonRpcSuccess).result as ToolCallResult;
}

const textOf = (r: ToolCallResult) => r.content.map((c) => c.text).join("\n");

/* ------------------------------- verify_fix ------------------------------- */

test("verify_fix confirms clean code and flags remaining classical crypto", async () => {
  const clean = await callTool("verify_fix", {
    code: "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\nconst k = ml_dsa65.keygen();",
    language: "js",
  });
  assert.match(textOf(clean), /Fix verified/);

  const dirty = await callTool("verify_fix", {
    code: "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });",
    language: "js",
  });
  assert.match(textOf(dirty), /NOT complete/);
  assert.match(textOf(dirty), /node-crypto-keygen/);
});

test("verify_fix works across languages (Python) and rejects unknown ones", async () => {
  const py = await callTool("verify_fix", {
    code: "key = rsa.generate_private_key(key_size=2048)",
    language: "python",
  });
  assert.match(textOf(py), /python-rsa-keygen/);

  const bad = await callTool("verify_fix", { code: "x = 1", language: "cobol" });
  assert.equal(bad.isError, true);
  assert.match(textOf(bad), /unknown language/i);

  const missing = await callTool("verify_fix", { code: "x = 1" });
  assert.equal(missing.isError, true);
});

/* ----------------------------- check_dependency --------------------------- */

test("check_dependency finds a known vulnerable package and misses unknowns honestly", async () => {
  const forge = await callTool("check_dependency", { name: "node-forge" });
  assert.match(textOf(forge), /quantum-vulnerable/);
  assert.match(textOf(forge), /RSA/);

  const unknown = await callTool("check_dependency", { name: "totally-made-up-pkg-xyz" });
  assert.match(textOf(unknown), /NOT in the known/);
  assert.match(textOf(unknown), /not proof it's safe/);
});

/* ----------------------------- get_fix_examples --------------------------- */

test("get_fix_examples returns before/after for an algorithm and resolves a ruleId", async () => {
  const rsa = await callTool("get_fix_examples", { algorithm: "RSA" });
  assert.match(textOf(rsa), /BEFORE \(classical\)/);
  assert.match(textOf(rsa), /AFTER \(post-quantum/);

  const byRule = await callTool("get_fix_examples", { ruleId: "node-crypto-ecdh" });
  assert.match(textOf(byRule), /ECDH/);

  const none = await callTool("get_fix_examples", {});
  assert.equal(none.isError, true);
});

/* ------------------------------- score_delta ------------------------------ */

test("score_delta computes the readiness improvement between two finding sets", async () => {
  const before = [
    {
      ruleId: "node-crypto-keygen",
      title: "RSA",
      category: "kem",
      severity: "high",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      message: "rsa",
      location: { file: "a.ts", line: 1 },
    },
  ];
  const res = await callTool("score_delta", { before, after: [] });
  const text = textOf(res);
  assert.match(text, /Readiness delta/);
  assert.match(text, /Progress: readiness improved/);
  assert.match(text, /HNDL:\s*1 → 0/);
});

/* ------------------------------ plan_migration ---------------------------- */

test("plan_migration produces a phased, prioritized plan", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "qk-plan-")));
  writeFileSync(
    join(root, "a.ts"),
    "crypto.createECDH('prime256v1');\ncrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
  );
  const prev = process.env.QUANTAKRYPTO_MCP_ROOT;
  process.env.QUANTAKRYPTO_MCP_ROOT = root;
  try {
    const res = await callTool("plan_migration", { path: root });
    const text = textOf(res);
    assert.match(text, /migration plan/i);
    assert.match(text, /Phase 1: Harvest-now-decrypt-later/);
    assert.match(text, /Readiness score:/);
  } finally {
    if (prev === undefined) delete process.env.QUANTAKRYPTO_MCP_ROOT;
    else process.env.QUANTAKRYPTO_MCP_ROOT = prev;
    rmSync(root, { recursive: true, force: true });
  }
});

/* --------------------------- triage_findings / apply_triage --------------------------- */

const twoFindings = [
  {
    ruleId: "a-rule",
    title: "A",
    category: "signature",
    severity: "high",
    confidence: "high",
    hndl: false,
    message: "classical A",
    location: { file: "a.ts", line: 1 },
  },
  {
    ruleId: "b-rule",
    title: "B",
    category: "key-exchange",
    severity: "high",
    confidence: "high",
    hndl: true,
    message: "classical B",
    location: { file: "b.ts", line: 2 },
  },
];

test("triage_findings emits an offline request bundle (rubric + schema + fingerprints, no code)", async () => {
  const r = await callTool("triage_findings", { findings: twoFindings });
  const bundle = JSON.parse(r.content[1].text) as {
    rubric: string;
    schema: unknown;
    items: { fingerprint: string; context: { code: string | null } }[];
  };
  assert.match(bundle.rubric, /exposure/i);
  assert.equal(bundle.items.length, 2);
  assert.ok(
    bundle.items.every((i) => typeof i.fingerprint === "string" && i.fingerprint.length > 0),
  );
  // metadata level → no source code leaves.
  assert.ok(bundle.items.every((i) => i.context.code === null));
});

test("apply_triage attaches verdicts, re-sorts by exposure, and never drops a finding", async () => {
  const bundle = JSON.parse(
    (await callTool("triage_findings", { findings: twoFindings })).content[1].text,
  ) as {
    items: { fingerprint: string }[];
  };
  const [fpA, fpB] = bundle.items.map((i) => i.fingerprint);
  const verdicts = [
    { fingerprint: fpA, exposureScore: 10, priority: "later", rationale: "local" },
    { fingerprint: fpB, exposureScore: 95, priority: "now", rationale: "HNDL over the wire" },
  ];
  const r = await callTool("apply_triage", { findings: twoFindings, verdicts });
  const sorted = JSON.parse(r.content[1].text) as {
    ruleId: string;
    triage?: { exposureScore: number };
  }[];
  assert.equal(sorted.length, 2, "never drops a finding");
  assert.equal(sorted[0].ruleId, "b-rule", "highest exposure first");
  assert.equal(sorted[0].triage?.exposureScore, 95);
});

test("apply_triage ignores malformed verdicts rather than throwing", async () => {
  const r = await callTool("apply_triage", {
    findings: twoFindings,
    verdicts: [{ fingerprint: "x", exposureScore: 999, priority: "nope", rationale: 5 }],
  });
  assert.equal(r.isError ?? false, false);
  assert.match(textOf(r), /malformed verdict/);
});

test("remediate_findings emits an offline fix-request bundle (rubric + schema + fingerprints)", async () => {
  const r = await callTool("remediate_findings", { findings: twoFindings });
  const bundle = JSON.parse(r.content[1].text) as {
    instructions: string;
    schema: { required: string[] };
    items: { fingerprint: string; context: { code: string | null } }[];
  };
  assert.match(bundle.instructions, /verify_fix/);
  assert.deepEqual(bundle.schema.required, ["path", "newContent", "explanation"]);
  assert.equal(bundle.items.length, 2);
  assert.ok(
    bundle.items.every((i) => typeof i.fingerprint === "string" && i.fingerprint.length > 0),
  );
  assert.ok(bundle.items.every((i) => i.context.code === null));
});

test("apply_triage rejects a NaN exposureScore instead of accepting it (audit: mcp #3)", async () => {
  const r = await callTool("apply_triage", {
    findings: twoFindings,
    verdicts: [{ fingerprint: "x", exposureScore: NaN, priority: "now", rationale: "r" }],
  });
  assert.match(textOf(r), /malformed verdict/);
});

test("triage_findings bundle schema requires the fingerprint field (audit: mcp bundle)", async () => {
  const r = await callTool("triage_findings", { findings: twoFindings });
  const bundle = JSON.parse(r.content[1].text) as { schema: { required: string[] } };
  assert.ok(bundle.schema.required.includes("fingerprint"), "schema demands fingerprint");
});

test("triage_findings surfaces a malformed finding as a tool error, not a crash (audit: mcp #4)", async () => {
  const r = await callTool("triage_findings", { findings: [{}] });
  assert.equal(r.isError, true);
  assert.match(textOf(r), /ruleId/);
});
