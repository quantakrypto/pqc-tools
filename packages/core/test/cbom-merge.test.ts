/**
 * Tests for mergeCboms — combining code, infra, and live-endpoint CBOMs into one.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toCbom, mergeCboms, buildInventory } from "../src/index.js";
import type { Finding, ScanResult } from "../src/index.js";

const T = "2026-07-17T00:00:00.000Z";

function finding(
  part: Partial<Finding> & Pick<Finding, "ruleId" | "algorithm" | "category">,
): Finding {
  return {
    title: part.ruleId,
    severity: "high",
    confidence: "high",
    hndl: part.hndl ?? false,
    message: "x",
    location: part.location ?? { file: "f", line: 1 },
    ...part,
  } as Finding;
}

function result(root: string, findings: Finding[]): ScanResult {
  return {
    root,
    findings,
    filesScanned: 1,
    inventory: buildInventory(findings),
    startedAt: T,
    finishedAt: T,
    toolVersion: "test",
  };
}

test("mergeCboms unions components by bom-ref and merges occurrences", () => {
  // qScan plane: RSA kem + ECDSA signature.
  const a = toCbom(
    result("code", [
      finding({
        ruleId: "a-rsa",
        algorithm: "RSA",
        category: "kem",
        hndl: true,
        location: { file: "a.tf", line: 1 },
      }),
      finding({
        ruleId: "a-ec",
        algorithm: "ECDSA",
        category: "signature",
        location: { file: "b.tf", line: 2 },
      }),
    ]),
  );
  // qProbe plane: ECDSA signature (SAME asset as a-ec) + X25519 key-agree (new).
  const b = toCbom(
    result("endpoints", [
      finding({
        ruleId: "b-ec",
        algorithm: "ECDSA",
        category: "signature",
        location: { file: "h:443", line: 1 },
      }),
      finding({
        ruleId: "b-x",
        algorithm: "X25519",
        category: "key-exchange",
        hndl: true,
        location: { file: "h:443", line: 1 },
      }),
    ]),
  );

  const merged = mergeCboms([a, b]);
  assert.equal(merged.bomFormat, "CycloneDX");
  assert.equal(merged.specVersion, "1.6");
  // RSA|kem, ECDSA|signature, X25519|key-agree → 3 distinct components.
  assert.equal(merged.components.length, 3);

  // The ECDSA signature component (shared) carries occurrences from BOTH planes.
  const ecdsa = merged.components.find((c) => c.name.startsWith("ECDSA"))!;
  const occ = (ecdsa.evidence as { occurrences: { location: string }[] }).occurrences;
  const locs = occ.map((o) => o.location).sort();
  assert.deepEqual(locs, ["b.tf:2", "h:443:1"]);
});

test("mergeCboms OR-s the harvest-now-decrypt-later flag", () => {
  const safe = toCbom(
    result("x", [finding({ ruleId: "s", algorithm: "RSA", category: "kem", hndl: false })]),
  );
  const hndl = toCbom(
    result("y", [finding({ ruleId: "h", algorithm: "RSA", category: "kem", hndl: true })]),
  );
  const merged = mergeCboms([safe, hndl]);
  assert.equal(merged.components.length, 1);
  // The HNDL flag is OR-ed across the merged copies and lives in component properties.
  const hndlProp = merged.components[0].properties?.find(
    (p) => p.name === "quantakrypto:harvestNowDecryptLater",
  );
  assert.equal(hndlProp?.value, "true");
});

test("mergeCboms is deterministic", () => {
  const a = toCbom(result("a", [finding({ ruleId: "r", algorithm: "RSA", category: "kem" })]));
  const b = toCbom(
    result("b", [finding({ ruleId: "e", algorithm: "ECDSA", category: "signature" })]),
  );
  assert.deepEqual(mergeCboms([a, b]), mergeCboms([a, b]));
});

test("mergeCboms tolerates a CBOM with no components (legal, empty)", () => {
  const empty = { bomFormat: "CycloneDX", specVersion: "1.6" } as never;
  const a = toCbom(result("a", [finding({ ruleId: "r", algorithm: "RSA", category: "kem" })]));
  assert.doesNotThrow(() => mergeCboms([empty, a]));
  const merged = mergeCboms([empty, a]);
  assert.equal(merged.components.length, 1, "the empty CBOM contributes nothing");
});

test("mergeCboms tolerates a duplicate bom-ref whose copy lacks cryptoProperties", () => {
  const a = toCbom(result("a", [finding({ ruleId: "r", algorithm: "RSA", category: "kem" })]));
  const ref = a.components[0]["bom-ref"];
  // A hand-built external CBOM sharing the bom-ref but with no cryptoProperties.
  const ext = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [{ "bom-ref": ref, type: "cryptographic-asset", name: "ext" }],
  } as never;
  assert.doesNotThrow(() => mergeCboms([a, ext]));
});

test("mergeCboms serial reflects occurrence evidence, not just bom-refs", () => {
  const mk = (loc: string) =>
    toCbom(
      result("root", [
        finding({
          ruleId: "r",
          algorithm: "RSA",
          category: "kem",
          location: { file: loc, line: 1 },
        }),
      ]),
    );
  const s1 = mergeCboms([mk("a.ts")]).serialNumber;
  const s2 = mergeCboms([mk("b.ts")]).serialNumber;
  assert.notEqual(s1, s2, "same bom-ref, different occurrence → distinct serials");
});

test("toCbom serialNumber is content-addressed (not derived from finding COUNT)", () => {
  // Two scans with the SAME count of DIFFERENT findings must not collide.
  const one = toCbom(
    result("root", [
      finding({
        ruleId: "r",
        algorithm: "RSA",
        category: "kem",
        location: { file: "a.ts", line: 1 },
      }),
    ]),
  );
  const two = toCbom(
    result("root", [
      finding({
        ruleId: "e",
        algorithm: "ECDSA",
        category: "signature",
        location: { file: "b.ts", line: 1 },
      }),
    ]),
  );
  assert.notEqual(one.serialNumber, two.serialNumber);
});
