/**
 * CLI-shell tests for `main()`: the meta paths (help/version), usage errors,
 * and the argv → exit-code wiring. Output streams are captured rather than
 * printed. `main()` drives the genuine `@quantakrypto/core` scanner, so the
 * scan-outcome exit codes (clean → 0, findings → 1, bad path → 2) are asserted
 * deterministically here against real temp fixtures.
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { test } from "node:test";

import { main } from "../src/cli.js";
import { EXIT } from "../src/index.js";

/**
 * Materialize a fixture the REAL core scanner (which `main()` uses by default)
 * flags: an RSA key-generation call is a `node-crypto-keygen` finding at `high`.
 * `main()` runs the genuine detector pipeline, so its exit code is deterministic
 * — no `scanFn` injection and no "either 0/1/2" tolerance is needed here.
 */
async function makeCryptoFixture(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "qscan-cli-"));
  await writeFile(
    join(dir, "keys.ts"),
    "import { generateKeyPairSync } from 'node:crypto';\n" +
      "export const k = () => generateKeyPairSync('rsa', { modulusLength: 2048 });\n",
    "utf8",
  );
  return dir;
}

/** A fixture with no crypto at all — the scanner must find nothing (exit 0). */
async function makeCleanFixture(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "qscan-cli-"));
  await writeFile(
    join(dir, "util.ts"),
    "export const add = (a: number, b: number) => a + b;\n",
    "utf8",
  );
  return dir;
}

/** Capture stdout + stderr written during `fn`. */
async function capture(
  fn: () => Promise<number>,
): Promise<{ code: number; out: string; err: string }> {
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  let out = "";
  let err = "";
  // @ts-expect-error narrow override for the test
  process.stdout.write = (chunk: string) => ((out += chunk), true);
  // @ts-expect-error narrow override for the test
  process.stderr.write = (chunk: string) => ((err += chunk), true);
  try {
    const code = await fn();
    return { code, out, err };
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

test("--help prints usage and exits 0", async () => {
  const { code, out } = await capture(() => main(["--help"]));
  assert.equal(code, EXIT.OK);
  assert.match(out, /USAGE/);
  assert.match(out, /--severity-threshold/);
  assert.match(out, /EXIT CODES/);
});

test("--version prints a version line and exits 0", async () => {
  const { code, out } = await capture(() => main(["--version"]));
  assert.equal(code, EXIT.OK);
  assert.match(out, /^qscan \d+\.\d+\.\d+/);
});

test("unknown flag exits 2 with a hint to --help", async () => {
  const { code, err } = await capture(() => main(["--bogus"]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /unknown option/);
  assert.match(err, /--help/);
});

test("invalid format exits 2", async () => {
  const { code, err } = await capture(() => main(["--format", "xml"]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /invalid --format/);
});

test("--write-baseline writes a baseline of the real findings and exits 0", async () => {
  const dir = await makeCryptoFixture();
  try {
    const baseline = join(dir, "b.json");
    const { code } = await capture(() => main([dir, "--write-baseline", baseline]));
    // Writing a baseline is a bookkeeping run: exit 0 regardless of findings.
    assert.equal(code, EXIT.OK);
    const written = JSON.parse(await readFile(baseline, "utf8")) as { fingerprints: unknown[] };
    assert.ok(
      Array.isArray(written.fingerprints) && written.fingerprints.length >= 1,
      "the RSA finding is recorded as a baseline fingerprint",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanning a directory with classical crypto exits 1 (FINDINGS)", async () => {
  // main() drives the genuine core scanner; an RSA keygen call is a real finding.
  const dir = await makeCryptoFixture();
  try {
    const { code } = await capture(() => main([dir, "--severity-threshold", "high"]));
    assert.equal(code, EXIT.FINDINGS);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanning a directory with no crypto exits 0 (clean)", async () => {
  const dir = await makeCleanFixture();
  try {
    const { code } = await capture(() => main([dir]));
    assert.equal(code, EXIT.OK);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a missing scan path exits 2 with a friendly message (not a raw ENOENT)", async () => {
  const missing = join(tmpdir(), "qscan-does-not-exist-9c3f1a2b", "nope");
  const { code, err } = await capture(() => main([missing]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /path not found/);
  assert.doesNotMatch(err, /ENOENT/, "the raw stat error should not leak to the user");
});

test("report is written to a file as parseable JSON containing the real findings", async () => {
  const dir = await makeCryptoFixture();
  try {
    const outFile = join(dir, "report.json");
    const { code } = await capture(() => main([dir, "--format", "json", "-o", outFile]));
    assert.equal(code, EXIT.FINDINGS);
    const report = JSON.parse(await readFile(outFile, "utf8")) as {
      findings: { ruleId: string }[];
    };
    assert.ok(
      report.findings.some((f) => f.ruleId === "node-crypto-keygen"),
      "the RSA keygen finding is present in the written JSON report",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("crypto-agility emit writes a valid manifest to stdout and always exits 0", async () => {
  // A repo WITH classical crypto: a normal scan exits 1, but the emit must exit 0.
  const dir = await makeCryptoFixture();
  try {
    const { code, out } = await capture(() => main(["crypto-agility", "emit", dir]));
    assert.equal(code, EXIT.OK, "emit is additive and never fails CI");
    const manifest = JSON.parse(out) as {
      version: number;
      manifestType: string;
      posture: { quantumVulnerable: { total: number } };
      cbomSummary: { algorithmFamilies: { family: string }[] };
    };
    assert.equal(manifest.version, 1);
    assert.equal(manifest.manifestType, "crypto-agility");
    assert.ok(manifest.posture.quantumVulnerable.total >= 1);
    assert.ok(manifest.cbomSummary.algorithmFamilies.length >= 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--crypto-agility flag is equivalent to the emit subcommand (exit 0)", async () => {
  const dir = await makeCryptoFixture();
  try {
    const { code, out } = await capture(() =>
      main([dir, "--crypto-agility", "--attestation", "https://example.com/cred", "--hybrid-kex"]),
    );
    assert.equal(code, EXIT.OK);
    const m = JSON.parse(out) as {
      attestation?: { url: string };
      posture: { hybridKexInUse: boolean | null };
    };
    assert.deepEqual(m.attestation, { url: "https://example.com/cred" });
    assert.equal(m.posture.hybridKexInUse, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("crypto-agility emit round-trips through validate (exit 0)", async () => {
  const dir = await makeCryptoFixture();
  try {
    const manifestFile = join(dir, "crypto-agility.json");
    const emit = await capture(() => main(["crypto-agility", "emit", dir, "-o", manifestFile]));
    assert.equal(emit.code, EXIT.OK);
    const { code, out } = await capture(() => main(["crypto-agility", "validate", manifestFile]));
    assert.equal(code, EXIT.OK);
    assert.match(out, /valid crypto-agility manifest/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("crypto-agility validate rejects a malformed manifest (exit 1)", async () => {
  const dir = await makeCleanFixture();
  try {
    const bad = join(dir, "bad.json");
    await writeFile(bad, JSON.stringify({ version: 1 }), "utf8");
    const { code, err } = await capture(() => main(["crypto-agility", "validate", bad]));
    assert.equal(code, EXIT.FINDINGS);
    assert.match(err, /not a valid crypto-agility manifest/);
    assert.match(err, /missing required field: posture/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("crypto-agility validate rejects non-JSON (exit 1)", async () => {
  const dir = await makeCleanFixture();
  try {
    const bad = join(dir, "notjson.json");
    await writeFile(bad, "this is not json", "utf8");
    const { code, err } = await capture(() => main(["crypto-agility", "validate", bad]));
    assert.equal(code, EXIT.FINDINGS);
    assert.match(err, /not valid JSON/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("crypto-agility validate on a missing file exits 2", async () => {
  const missing = join(tmpdir(), "qscan-no-manifest-7a1b", "x.json");
  const { code, err } = await capture(() => main(["crypto-agility", "validate", missing]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /path not found/);
});

test("crypto-agility with no subcommand is a usage error (exit 2)", async () => {
  const { code, err } = await capture(() => main(["crypto-agility"]));
  assert.equal(code, EXIT.ERROR);
  assert.match(err, /requires a subcommand/);
});
