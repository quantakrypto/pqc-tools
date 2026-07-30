/**
 * Tests for the post-quantum KEM parameter detector — pre-standard (round-3)
 * Kyber used where FIPS 203 ML-KEM is intended, and an ML-KEM/Kyber byte size
 * that names a different parameter set than the code advertises. Imports the
 * detector DIRECTLY so the test exercises exactly this surface.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { pqcParameterDetector } from "../src/detectors/pqc-parameter.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  if (!pqcParameterDetector.appliesTo(file)) return [];
  return pqcParameterDetector.detect({ file, content });
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

// --- Rule 1: pre-standard Kyber — positives ---------------------------------

test("Rust `pqc_kyber` crate is flagged as pre-standard Kyber (medium, kem, hndl false)", () => {
  const f = rule(run("Cargo.toml", 'pqc_kyber = "0.7"'), "pqc-prestandard-kem");
  assert.ok(f, "pqc_kyber flagged");
  assert.equal(f?.category, "kem");
  assert.equal(f?.severity, "medium");
  assert.equal(f?.hndl, false);
  assert.equal(f?.confidence, "low", "no FIPS-203/ML-KEM claim → low confidence");
  assert.match(f?.message ?? "", /pqc_kyber/);
});

test("`pqcrypto-kyber` dependency is flagged", () => {
  assert.ok(
    rule(run("requirements.txt", "pqcrypto-kyber==0.7.9"), "pqc-prestandard-kem"),
    "pqcrypto-kyber flagged",
  );
});

test("round-3 `Kyber768` parameter name is flagged", () => {
  const f = rule(run("kem.go", 'scheme := "Kyber768"'), "pqc-prestandard-kem");
  assert.ok(f, "Kyber768 flagged");
  assert.match(f?.message ?? "", /Kyber768/);
});

test("confidence is RAISED to high when a FIPS-203/ML-KEM/NIST claim is in the same file", () => {
  const src = ["// FIPS 203 compliant KEM (NIST ML-KEM)", "use pqc_kyber::keypair;"].join("\n");
  const f = rule(run("kem.rs", src), "pqc-prestandard-kem");
  assert.ok(f, "pqc_kyber flagged");
  assert.equal(f?.confidence, "high", "co-located FIPS-203/ML-KEM claim raises confidence");
  assert.match(f?.message ?? "", /despite a FIPS-203\/ML-KEM\/NIST claim/);
});

test("reference API `crypto_kem_kyber768_ref` is flagged", () => {
  assert.ok(
    rule(run("kem.c", "int r = crypto_kem_kyber768_ref_keypair(pk, sk);"), "pqc-prestandard-kem"),
    "reference API flagged",
  );
});

// --- Rule 1: pre-standard Kyber — negatives ---------------------------------

test("FIPS 203 `ML-KEM-768` alone is NOT flagged as pre-standard", () => {
  assert.deepEqual(run("kem.rs", 'let kem = "ML-KEM-768";'), []);
});

test("a file with no Kyber/ML-KEM mention is skipped wholesale (fast reject)", () => {
  assert.deepEqual(run("app.ts", "const size = 1184; // buffer"), []);
});

test("a commented-out `pqc_kyber` line is NOT flagged", () => {
  assert.deepEqual(run("kem.rs", '// pqc_kyber = "0.7"  (removed, migrated to ML-KEM)'), []);
});

test("prose docs mentioning Kyber768 are NOT flagged", () => {
  assert.deepEqual(run("MIGRATION.md", "We replaced Kyber768 with ML-KEM-768 in 2024."), []);
});

// --- Rule 2: size ↔ parameter-set mismatch — positives ----------------------

test("pk size 1184 (ML-KEM-768) while advertising ML-KEM-1024 is flagged (mismatch)", () => {
  const src = ["// ML-KEM-1024 key sizes", "const PUBLIC_KEY_BYTES = 1184;"].join("\n");
  const f = rule(run("kem.ts", src), "pqc-parameter-mismatch");
  assert.ok(f, "size/level mismatch flagged");
  assert.equal(f?.category, "kem");
  assert.equal(f?.severity, "medium");
  assert.equal(f?.confidence, "low", "mismatch rule is conservative / low confidence");
  assert.equal(f?.hndl, false);
  assert.match(f?.message ?? "", /1184.*ML-KEM-768.*ML-KEM-1024/);
});

test("sk size 3168 (ML-KEM-1024) while advertising Kyber-512 is flagged", () => {
  const src = "// Kyber-512 profile\nlet SECRET_KEY_BYTES = 3168;";
  assert.ok(rule(run("kem.rs", src), "pqc-parameter-mismatch"), "3168 vs Kyber-512 flagged");
});

// --- Rule 2: size ↔ parameter-set mismatch — negatives & gating -------------

test("correct pairing (1184 with ML-KEM-768) is NOT flagged", () => {
  const src = "// ML-KEM-768\nconst PUBLIC_KEY_BYTES = 1184;";
  assert.deepEqual(
    run("kem.ts", src).filter((f) => f.ruleId === "pqc-parameter-mismatch"),
    [],
  );
});

test("a multi-parameter file advertising BOTH 768 and 1024 is NOT flagged", () => {
  const src = [
    "// supports ML-KEM-768 and ML-KEM-1024",
    "const MLKEM768_PK = 1184;",
    "const MLKEM1024_PK = 1568;",
  ].join("\n");
  assert.deepEqual(
    run("kem.ts", src).filter((f) => f.ruleId === "pqc-parameter-mismatch"),
    [],
  );
});

test("a distinctive size with NO advertised parameter level is NOT flagged", () => {
  // Mentions Kyber (passes fast-reject) but never advertises a specific level,
  // so there is nothing to be inconsistent with.
  assert.deepEqual(
    run("kem.rs", "// Kyber KEM\nconst BYTES = 1184;").filter(
      (f) => f.ruleId === "pqc-parameter-mismatch",
    ),
    [],
  );
});

test("the size number inside a larger integer (11840) is NOT matched", () => {
  const src = "// ML-KEM-1024\nconst OFFSET = 11840;";
  assert.deepEqual(
    run("kem.ts", src).filter((f) => f.ruleId === "pqc-parameter-mismatch"),
    [],
  );
});
