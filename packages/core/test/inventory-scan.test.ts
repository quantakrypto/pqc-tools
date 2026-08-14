import { test } from "node:test";
import assert from "node:assert/strict";

import { inventoryFile, mergeAssets } from "../src/inventory-scan.js";

/**
 * The half of the inventory findings can never produce.
 *
 * Every finding detector fires on cryptography that is WRONG, so an inventory
 * built from findings can only describe problems. That made a repository which
 * had migrated to ML-KEM indistinguishable from one using no cryptography at
 * all: both showed an empty inventory and 100/100.
 */

test("records PQC usage, which no finding detector reports", () => {
  const assets = inventoryFile("src/kem.rs", `let (pk, sk) = ml_kem_768::keypair();`);
  const mlkem = assets.find((a) => a.algorithm === "ML-KEM");
  assert.ok(mlkem, "ML-KEM must appear in the inventory");
  assert.equal(mlkem.posture, "quantum-safe");
  assert.equal(mlkem.kind, "kem");
  assert.equal(mlkem.locations[0]?.file, "src/kem.rs");
});

/**
 * A Kyber768 build is NOT an ML-KEM-768 build: FIPS 203 changed the KDF and the
 * domain separation. Reporting them as one algorithm would let a pre-standard
 * build claim standards compliance.
 */
test("keeps pre-standard CRYSTALS separate from the FIPS names", () => {
  const assets = inventoryFile("a.rs", `use pqc_kyber::keypair; // Kyber768`);
  assert.ok(assets.some((a) => a.algorithm === "Kyber (pre-standard)"));
  assert.ok(!assets.some((a) => a.algorithm === "ML-KEM"));
});

test("names the hybrid, since the classical half is the point", () => {
  const assets = inventoryFile("tls.go", `curvePreferences: X25519MLKEM768`);
  const hybrid = assets.find((a) => a.algorithm.startsWith("X25519MLKEM768"));
  assert.ok(hybrid);
  assert.equal(hybrid.kind, "key-agreement");
});

/**
 * Symmetric is `not-quantum-relevant`, not `quantum-safe`. Grover halves the
 * effective key length, which matters at 128 bits and does not break 256;
 * calling it "safe" beside ML-KEM would flatten a real distinction.
 */
test("classifies symmetric and hash as not-quantum-relevant", () => {
  const assets = inventoryFile("a.js", `crypto.createCipheriv("aes-256-gcm", k, iv)`);
  const aes = assets.find((a) => a.algorithm === "AES-256");
  assert.ok(aes);
  assert.equal(aes.posture, "not-quantum-relevant");
});

/** Order is load-bearing: SHA-384 must not also be counted as a bare SHA-3. */
test("a longer name wins the position, so one match is not counted twice", () => {
  const assets = inventoryFile("a.py", `hashlib.sha384(b"x")`);
  assert.deepEqual(
    assets.map((a) => a.algorithm),
    ["SHA-2 (384/512)"],
  );

  const aes = inventoryFile("b.py", `AES256`);
  assert.deepEqual(
    aes.map((a) => a.algorithm),
    ["AES-256"],
    "AES-256 must not also register as AES-128 or a bare AES",
  );
});

test("counts every occurrence but keeps only a handful of example sites", () => {
  const content = Array.from({ length: 20 }, () => "ML-KEM-768").join("\n");
  const [asset] = inventoryFile("many.rs", content);
  assert.equal(asset?.count, 20, "the count is the scale");
  assert.ok(
    (asset?.locations.length ?? 0) <= 5,
    "the locations are evidence, not a concordance of every call site",
  );
});

test("a file with no cryptography contributes nothing", () => {
  assert.deepEqual(inventoryFile("readme.md", "This project is about widgets."), []);
});

test("mergeAssets sums counts across files and keeps one entry per algorithm", () => {
  const merged = mergeAssets([
    inventoryFile("a.rs", "ML-KEM-768"),
    inventoryFile("b.rs", "ML-KEM-1024"),
  ]);
  const mlkem = merged.find((a) => a.algorithm === "ML-KEM");
  assert.equal(mlkem?.count, 2);
  assert.equal(mlkem?.locations.length, 2);
});

/** Vulnerable first, then safe, then the rest: the reader's order of interest. */
test("mergeAssets orders by posture, then by how much there is", () => {
  const merged = mergeAssets([
    [
      {
        algorithm: "AES-256",
        kind: "symmetric",
        posture: "not-quantum-relevant",
        count: 9,
        locations: [],
      },
    ],
    [{ algorithm: "ML-KEM", kind: "kem", posture: "quantum-safe", count: 1, locations: [] }],
    [{ algorithm: "RSA", kind: "kem", posture: "quantum-vulnerable", count: 1, locations: [] }],
  ]);
  assert.deepEqual(
    merged.map((a) => a.algorithm),
    ["RSA", "ML-KEM", "AES-256"],
  );
});

/**
 * An algorithm named in KEY position is a field label, not a use of it.
 *
 * Found on the first real run: `.cargo_vcs_info.json` carries
 * `{"sha1": "<commit>"}` for the git revision, and the sweep read that as "this
 * project uses SHA-1". It does not. An inventory people cannot trust is worse
 * than no inventory, because a false entry costs a reader the time to disprove.
 */
test("a name in key position is metadata, not usage", () => {
  assert.deepEqual(inventoryFile(".cargo_vcs_info.json", `{"sha1": "9f2b1c"}`), []);
  assert.deepEqual(inventoryFile("a.yml", `sha1: 9f2b1c`), []);
  // In value or call position it is a real use and must still be recorded.
  assert.ok(inventoryFile("a.py", `hashlib.sha1(b"x")`).some((a) => a.algorithm === "SHA-1"));
  assert.ok(inventoryFile("a.json", `{"hash": "sha1"}`).some((a) => a.algorithm === "SHA-1"));
});
