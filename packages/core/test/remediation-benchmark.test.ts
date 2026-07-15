/**
 * Remediation-correctness benchmark + regression guard.
 *
 * The detection benchmark measures whether qScan FINDS classical crypto; this
 * one measures whether the deterministic codemod layer FIXES it correctly. For a
 * hand-labeled corpus of (vulnerable file → target finding) cases it scores four
 * properties of every produced patch and asserts the deterministic layer is
 * perfect on all of them:
 *
 *   1. applied      — a codemod exists and returns a non-null patch.
 *   2. cleared      — re-running the detectors on the patched code no longer
 *                     reports the target rule (the classical crypto is gone).
 *   3. no-regression — the patch introduces NO new finding it didn't start with
 *                     (it fixed the target without adding a fresh problem).
 *   4. idempotent   — re-applying the codemod to already-fixed code is a no-op.
 *
 * A second corpus checks the layer's HONESTY: for findings with no safe
 * mechanical fix (an RSA keygen, an ECDH handshake — there is no drop-in
 * replacement), the deterministic layer must DECLINE rather than emit a wrong
 * patch. Those are left to triage + the LLM remediation layer.
 *
 * Because these codemods are deterministic, correctness is gated at 1.000 (unlike
 * detection recall, which is floored). A codemod that stops clearing its finding,
 * starts over-reaching, or loses idempotence fails the build. This is the harness
 * future codemods plug into; LLM-produced fixes (non-deterministic) would be
 * measured by the same four properties but reported, not gated.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { codemodFor, verifyFix } from "../src/index.js";
import type { Finding } from "../src/index.js";

/** A fixable case: `before` contains `ruleId`, and a codemod must clear it. */
interface FixCase {
  name: string;
  filename: string;
  ruleId: string;
  before: string;
}

/** A decline case: `before` contains `ruleId`, but no safe mechanical fix exists. */
interface DeclineCase {
  name: string;
  filename: string;
  ruleId: string;
  before: string;
}

// ---- Corpus A: deterministic fixes that MUST clear the finding ----
const FIX_CASES: FixCase[] = [
  {
    name: "tls minVersion TLSv1 → TLSv1.3",
    filename: "server.js",
    ruleId: "tls-legacy-version",
    before: "const s = tls.connect({ host, minVersion: 'TLSv1' });\n",
  },
  {
    name: "tls secureProtocol TLSv1_1_method → TLSv1_3_method",
    filename: "client.js",
    ruleId: "tls-legacy-version",
    before: "https.request({ secureProtocol: 'TLSv1_1_method' }, cb);\n",
  },
  {
    name: "rejectUnauthorized:false → true",
    filename: "fetch.js",
    ruleId: "tls-reject-unauthorized",
    before: "https.get(url, { rejectUnauthorized: false }, cb);\n",
  },
  {
    name: "both legacy-version AND reject-unauthorized fixed in one patch",
    filename: "both.ts",
    ruleId: "tls-reject-unauthorized",
    before: "const opts = { minVersion: 'TLSv1.1', rejectUnauthorized: false };\n",
  },
];

// ---- Corpus B: findings the deterministic layer must honestly DECLINE ----
const DECLINE_CASES: DeclineCase[] = [
  {
    name: "RSA keygen has no drop-in mechanical fix",
    filename: "keys.js",
    ruleId: "node-crypto-keygen",
    before: "const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
  },
  {
    name: "ECDH handshake has no drop-in mechanical fix",
    filename: "kex.js",
    ruleId: "node-crypto-ecdh",
    before: "const ecdh = crypto.createECDH('prime256v1');\n",
  },
];

/** Find the finding with `ruleId` produced by the detectors over `code`. */
function findingFor(code: string, filename: string, ruleId: string): Finding {
  const { findings } = verifyFix(code, { filename });
  const f = findings.find((x) => x.ruleId === ruleId);
  assert.ok(f, `fixture must actually produce a ${ruleId} finding (corpus is self-checking)`);
  return f;
}

test("remediation benchmark: deterministic codemods clear their finding (and stay honest)", () => {
  let applied = 0;
  let cleared = 0;
  let idempotent = 0;
  let noRegression = 0;

  for (const c of FIX_CASES) {
    const finding = findingFor(c.before, c.filename, c.ruleId);
    const before = new Set(
      verifyFix(c.before, { filename: c.filename }).findings.map((f) => f.ruleId),
    );

    const codemod = codemodFor(finding);
    assert.ok(codemod, `${c.name}: a codemod applies`);

    const patch = codemod.apply(c.before, finding);
    assert.ok(patch, `${c.name}: the codemod produced a patch`);
    applied++;

    // (2) cleared: the target rule is gone from the patched code.
    const after = verifyFix(patch.newContent, { filename: c.filename });
    const stillThere = after.findings.some((f) => f.ruleId === c.ruleId);
    assert.equal(stillThere, false, `${c.name}: the patch cleared ${c.ruleId}`);
    cleared++;

    // (3) no-regression: no finding that wasn't already present appears.
    const introduced = after.findings.map((f) => f.ruleId).filter((id) => !before.has(id));
    assert.deepEqual(introduced, [], `${c.name}: the patch introduced no new finding`);
    noRegression++;

    // (4) idempotent: re-applying to fixed code is a no-op.
    const second = codemod.apply(patch.newContent, finding);
    assert.equal(second, null, `${c.name}: re-applying the codemod is a no-op`);
    idempotent++;
  }

  let declined = 0;
  for (const c of DECLINE_CASES) {
    const finding = findingFor(c.before, c.filename, c.ruleId);
    // Honest decline: the deterministic layer offers no wrong mechanical fix.
    assert.equal(
      codemodFor(finding),
      undefined,
      `${c.name}: the deterministic layer declines (no wrong auto-fix)`,
    );
    declined++;
  }

  const n = FIX_CASES.length;
  const rate = (x: number) => (x / n).toFixed(3);
  // Compact summary line, mirroring the detection benchmark's OVERALL row.
  console.log(
    `REMEDIATION  applied ${applied}/${n} (${rate(applied)})  cleared ${cleared}/${n} (${rate(
      cleared,
    )})  no-regression ${rate(noRegression)}  idempotent ${rate(idempotent)}  declined ${declined}/${DECLINE_CASES.length}`,
  );

  // Deterministic layer → gated at perfect. Any drop is a real regression.
  assert.equal(applied, n, "every fixable case produced a patch");
  assert.equal(cleared, n, "every patch cleared its finding");
  assert.equal(noRegression, n, "no patch introduced a new finding");
  assert.equal(idempotent, n, "every codemod is idempotent");
  assert.equal(declined, DECLINE_CASES.length, "the layer declined every unsafe case");
});
