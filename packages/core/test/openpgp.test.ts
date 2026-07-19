/**
 * Tests for binary OpenPGP key-material detection (secret/public keys, encrypted
 * messages, GnuPG keyboxes), including the byte-preserving scan-pipeline path.
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
const bytes = (...b: number[]): string => String.fromCharCode(...b);

test("binary OpenPGP secret / public / encrypted / keybox classify", () => {
  // Old-format Secret-Key packet (tag 5), v4, RSA (algo 1).
  const sec = bytes(0x94, 0x20, 0x04, 0, 0, 0, 0, 0x01) + "\x00".repeat(20);
  const f = run("secring.gpg", sec).find((x) => x.ruleId === "openpgp-secret-key");
  assert.ok(f, "secret key fires");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.sensitive, true);
  assert.equal(f?.hndl, true);

  // Public-Key packet (tag 6), v4, ECDSA (algo 19).
  const pub = bytes(0x98, 0x20, 0x04, 0, 0, 0, 0, 19) + "\x00".repeat(20);
  assert.equal(
    run("pubring.gpg", pub).find((x) => x.ruleId === "openpgp-public-key")?.algorithm,
    "ECDSA",
  );

  // PKESK packet (tag 1), v3, 8-byte key id, RSA (algo 1) → encrypted message.
  const enc = bytes(0x84, 0x20, 0x03, 1, 2, 3, 4, 5, 6, 7, 8, 0x01) + "\x00".repeat(10);
  const e = run("secret.gpg", enc).find((x) => x.ruleId === "openpgp-encrypted-message");
  assert.ok(e, "PKESK encrypted message fires");
  assert.equal(e?.hndl, true);

  // GnuPG keybox.
  assert.ok(run("pubring.kbx", "KBXf\x00\x01").some((x) => x.ruleId === "openpgp-keybox"));
});

test("new-format Secret-Key packet is parsed", () => {
  const sec = bytes(0xc5, 0x20, 0x04, 0, 0, 0, 0, 0x01) + "\x00".repeat(10);
  assert.ok(run("k.gpg", sec).some((x) => x.ruleId === "openpgp-secret-key"));
});

test("a .gpg that is not an OpenPGP packet does not fire; a non-.gpg is not scanned here", () => {
  assert.deepEqual(
    run("notes.gpg", "just text, no packet high bit").filter((f) =>
      f.ruleId.startsWith("openpgp-"),
    ),
    [],
  );
  assert.deepEqual(
    run("a.txt", bytes(0x94, 0x20, 0x04, 0, 0, 0, 0, 0x01)).filter((f) =>
      f.ruleId.startsWith("openpgp-"),
    ),
    [],
  );
});

test("the packet parser never throws on truncated / random binary input", () => {
  const samples = [
    "",
    bytes(0x94),
    bytes(0xc5, 0xff),
    bytes(0x84, 0x03),
    bytes(0x94, 0x20, 0x04),
    bytes(0x98, 0xff, 0xff, 0xff),
    bytes(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
  ];
  for (const s of samples) {
    assert.doesNotThrow(() => run("fuzz.gpg", s), `threw on ${JSON.stringify(s)}`);
  }
});

test("the scan pipeline reads a binary secret-key .gpg (latin1) and flags it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qk-pgp-"));
  try {
    const buf = Buffer.from([0x94, 0x20, 0x04, 0, 0, 0, 0, 0x01, ...Array(24).fill(0x9c)]);
    writeFileSync(join(dir, "secring.gpg"), buf);
    const result = await scan({ root: dir });
    assert.ok(
      result.findings.some((f) => f.ruleId === "openpgp-secret-key"),
      "openpgp-secret-key fires through the full scan pipeline",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
