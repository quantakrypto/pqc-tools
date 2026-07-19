/**
 * Tests for message-broker transport crypto detection (Kafka, MQTT).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { detectors } from "../src/index.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const det of detectors) {
    if (det.appliesTo(file)) out.push(...det.detect({ file, content }));
  }
  return out;
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("Kafka legacy ssl.protocol is flagged", () => {
  assert.ok(rule(run("server.properties", "ssl.protocol=TLSv1.1\n"), "mq-kafka-legacy-tls"));
});

test("Kafka ECDHE cipher is owned by source's tls-classical-kex (not duplicated by messaging)", () => {
  const fs = run("server.properties", "ssl.cipher.suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n");
  // messaging no longer emits a cipher rule for ECDHE — source.ts's token rule does.
  assert.equal(rule(fs, "mq-rsa-key-transport"), undefined);
  assert.ok(rule(fs, "tls-classical-kex"), "source's tls-classical-kex owns the ECDHE token");
});

test("Kafka STATIC-RSA (TLS_RSA_WITH_*) key-transport suite is flagged by messaging (unique to it)", () => {
  const f = rule(
    run("server.properties", "ssl.cipher.suites=TLS_RSA_WITH_AES_128_GCM_SHA256\n"),
    "mq-rsa-key-transport",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "kem");
  assert.equal(f?.hndl, true);
});

test("MQTT legacy tls_version is flagged", () => {
  assert.ok(rule(run("mosquitto.conf", "tls_version tlsv1\n"), "mq-mqtt-legacy-tls"));
});

test("a modern broker config (TLS 1.3) produces no mq- findings", () => {
  const clean = "ssl.protocol=TLSv1.3\nssl.enabled.protocols=TLSv1.3\n";
  assert.deepEqual(
    run("server.properties", clean).filter((f) => f.ruleId.startsWith("mq-")),
    [],
  );
});

test("a COMMENTED-OUT legacy directive is NOT flagged (broker configs ship examples)", () => {
  // mosquitto.conf / server.properties are full of commented example lines.
  assert.deepEqual(
    run("mosquitto.conf", "#tls_version tlsv1\n! ssl.protocol=TLSv1.1\n").filter((f) =>
      f.ruleId.startsWith("mq-"),
    ),
    [],
  );
  // An inline trailing comment does not disable the active directive before it.
  assert.ok(
    rule(run("server.properties", "ssl.protocol=TLSv1.1  # legacy\n"), "mq-kafka-legacy-tls"),
    "active directive with a trailing comment still fires",
  );
});
