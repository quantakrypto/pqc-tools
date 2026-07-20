/**
 * Tests for the DetectorRegistry plugin point and the default registry.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DetectorRegistry, defaultRegistry, detectors } from "../src/index.js";
import { detectorScope } from "../src/registry.js";
import type { Detector } from "../src/index.js";

const fakeDetector: Detector = {
  id: "fake-detector",
  description: "test",
  scope: "source",
  language: "js",
  appliesTo: () => true,
  detect: () => [],
};

test("defaultRegistry contains the built-in detectors", () => {
  const ids = new Set(defaultRegistry.all().map((d) => d.id));
  for (const id of [
    "node-crypto",
    "webcrypto",
    "crypto-libs",
    "jwt-jose",
    "tls-config",
    "pem-material",
  ]) {
    assert.ok(ids.has(id), `default registry has ${id}`);
  }
  // The exported `detectors` array stays in sync with the registry.
  assert.deepEqual(
    defaultRegistry.all().map((d) => d.id),
    detectors.map((d) => d.id),
  );
});

test("register / get / has / all preserve order and uniqueness", () => {
  const r = new DetectorRegistry();
  r.register(fakeDetector);
  assert.equal(r.get("fake-detector"), fakeDetector);
  assert.ok(r.has("fake-detector"));
  assert.deepEqual(
    r.all().map((d) => d.id),
    ["fake-detector"],
  );
  assert.throws(() => r.register(fakeDetector), /duplicate detector id/);
});

test("detectorScope defaults to source when undeclared", () => {
  const noScope: Detector = { id: "x", description: "", appliesTo: () => true, detect: () => [] };
  assert.equal(detectorScope(noScope), "source");
  assert.equal(detectorScope({ ...noScope, scope: "config" }), "config");
});

test("clone produces an independent registry seeded with the same detectors", () => {
  const clone = defaultRegistry.clone();
  clone.register(fakeDetector);
  assert.ok(clone.has("fake-detector"));
  assert.ok(!defaultRegistry.has("fake-detector"), "original unchanged");
});

test("config-scope detectors are declared, not prefix-inferred", () => {
  const byId = new Map(defaultRegistry.all().map((d) => [d.id, d]));
  assert.equal(detectorScope(byId.get("pem-material")!), "config");
  assert.equal(detectorScope(byId.get("tls-config")!), "config");
  assert.equal(detectorScope(byId.get("ssh-cert")!), "config");
  assert.equal(detectorScope(byId.get("node-crypto")!), "source");
});

test("ruleCatalog is complete, unique, and well-formed", () => {
  const catalog = defaultRegistry.ruleCatalog();
  assert.ok(catalog.length >= 20, "catalog covers every built-in rule");

  // Ids are unique and whitespace-free; required fields are populated.
  const ids = new Set<string>();
  for (const r of catalog) {
    assert.equal(r.id, r.id.trim(), `${r.id} has no surrounding whitespace`);
    assert.ok(!ids.has(r.id), `${r.id} is unique`);
    ids.add(r.id);
    assert.ok(r.title.length > 0, `${r.id} has a title`);
    assert.ok(r.message.length > 0, `${r.id} has a message`);
    assert.ok(r.severity, `${r.id} has a severity`);
    assert.ok(r.category, `${r.id} has a category`);
  }

  // A representative sample of ids the language-pack / MCP work depends on.
  for (const id of [
    "node-crypto-keygen",
    "elliptic-ec",
    "jwt-classical-alg",
    "pem-rsa-private-key",
  ]) {
    assert.ok(ids.has(id), `catalog contains ${id}`);
  }
});

test("forRule resolves a rule to its declaring detector", () => {
  const forge = defaultRegistry.forRule("forge-rsa-keygen");
  assert.equal(forge?.detector.id, "crypto-libs");
  assert.equal(forge?.rule.algorithm, "RSA");

  const ecdh = defaultRegistry.forRule("node-crypto-ecdh");
  assert.equal(ecdh?.detector.id, "node-crypto");
  assert.equal(ecdh?.rule.algorithm, "ECDH");

  assert.equal(defaultRegistry.forRule("totally-made-up-rule"), undefined);
});

test("ruleCatalog throws on a duplicate rule id across detectors", () => {
  const dup: Detector = {
    id: "dup-detector",
    description: "test",
    rules: [
      {
        id: "node-crypto-keygen",
        title: "x",
        category: "kem",
        severity: "low",
        confidence: "low",
        hndl: false,
        message: "x",
      },
    ],
    appliesTo: () => true,
    detect: () => [],
  };
  const r = defaultRegistry.clone().register(dup);
  assert.throws(() => r.ruleCatalog(), /duplicate rule id/);
});

test("catalog invariant: hndl is consistent per (algorithm, category) — HNDL never under-reported", () => {
  // The load-bearing correctness property (audit P0-4): whether a finding is
  // harvest-now-decrypt-later exposed is determined by its (algorithm, category),
  // NOT by which language pack emitted it. A key-exchange/ECDH rule with hndl:false
  // silently under-reports quantum exposure. The `certificate` category is the sole
  // exception — it deliberately mixes decrypt-capable private-key MATERIAL (hndl:true)
  // with certs/public keys (hndl:false) — so it is excluded here.
  const catalog = defaultRegistry.ruleCatalog().filter((r) => r.category !== "certificate");
  const byKey = new Map<string, Map<boolean, string[]>>();
  for (const r of catalog) {
    const key = `${r.algorithm}|${r.category}`;
    if (!byKey.has(key)) byKey.set(key, new Map());
    const m = byKey.get(key)!;
    if (!m.has(r.hndl)) m.set(r.hndl, []);
    m.get(r.hndl)!.push(r.id);
  }
  const violations: string[] = [];
  for (const [key, m] of byKey) {
    if (m.size > 1) {
      const detail = [...m.entries()].map(([h, ids]) => `hndl=${h}: ${ids.join(", ")}`).join(" | ");
      violations.push(`${key} → ${detail}`);
    }
  }
  assert.deepEqual(
    violations,
    [],
    `hndl must be uniform per (algorithm, category):\n${violations.join("\n")}`,
  );
});
