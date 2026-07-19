/**
 * Tests for committed-keystore detection (JKS/JCEKS/PKCS#12/BKS), including the
 * scan-pipeline path that reads keystore files byte-preserving (latin1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { detectors, scan } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function has(fs: Finding[], id: string): boolean {
  return fs.some((f) => f.ruleId === id);
}

test("JKS / JCEKS / PKCS#12 / BKS keystores are identified by magic / extension", () => {
  const jks = String.fromCharCode(0xfe, 0xed, 0xfe, 0xed) + "\x00\x00\x00\x02";
  const f = run("app.jks", jks).find((x) => x.ruleId === "keystore-jks");
  assert.ok(f, "JKS magic fires");
  assert.equal(f?.hndl, true);
  assert.equal(f?.sensitive, true); // key material — snippet dropped by reporters

  assert.ok(has(run("k.jceks", String.fromCharCode(0xce, 0xce, 0xce, 0xce)), "keystore-jceks"));
  assert.ok(has(run("k.p12", String.fromCharCode(0x30, 0x82, 0x04, 0x00)), "keystore-pkcs12"));
  assert.ok(has(run("k.pfx", String.fromCharCode(0x30, 0x82, 0x01, 0x00)), "keystore-pkcs12"));
  assert.ok(has(run("truststore.bks", "bouncy castle bytes"), "keystore-bks"));
});

test("a .jks whose bytes are NOT a keystore magic does not fire", () => {
  assert.deepEqual(
    run("notes.jks", "this is not a real keystore file").filter((f) =>
      f.ruleId.startsWith("keystore-"),
    ),
    [],
  );
  // A .p12 without the DER SEQUENCE start does not fire either.
  assert.deepEqual(
    run("x.p12", "plain text").filter((f) => f.ruleId.startsWith("keystore-")),
    [],
  );
});

test("the scan pipeline reads a real binary .jks (latin1) and flags it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qk-ks-"));
  try {
    // A real JKS starts with the 0xFEEDFEED magic; the rest is arbitrary bytes,
    // including high bytes that would be mangled by a utf8 read.
    const bytes = Buffer.from([
      0xfe,
      0xed,
      0xfe,
      0xed,
      0x00,
      0x00,
      0x00,
      0x02,
      ...Array(64).fill(0x9c),
    ]);
    writeFileSync(join(dir, "server.jks"), bytes);
    const result = await scan({ root: dir });
    assert.ok(
      result.findings.some((f) => f.ruleId === "keystore-jks"),
      "keystore-jks fires through the full scan pipeline (byte-preserving read)",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
