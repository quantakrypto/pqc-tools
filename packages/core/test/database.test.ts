/**
 * Tests for database crypto detection — pgcrypto public-key encryption and weak
 * client TLS posture.
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

test("pgcrypto pgp_pub_encrypt in a .sql file is flagged as RSA KEM, HNDL", () => {
  const f = rule(
    run("schema.sql", "SELECT pgp_pub_encrypt('secret', dearmor(pubkey)) FROM t;"),
    "db-pgcrypto-pubkey",
  );
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "kem");
  assert.equal(f?.hndl, true);
});

test("weak sslmode=require is flagged (no cert verification)", () => {
  const f = rule(
    run(".env", "DATABASE_URL=postgres://u:p@db:5432/app?sslmode=require\n"),
    "db-weak-sslmode",
  );
  assert.equal(f?.category, "tls");
});

test("sslmode=verify-full is NOT flagged", () => {
  assert.deepEqual(
    run(".env", "DATABASE_URL=postgres://db/app?sslmode=verify-full\n").filter((f) =>
      f.ruleId.startsWith("db-"),
    ),
    [],
  );
});

test("pgcrypto text in a non-.sql file does NOT fire the pgcrypto rule", () => {
  assert.deepEqual(
    run("notes.md", "we use pgp_pub_encrypt in the db").filter(
      (f) => f.ruleId === "db-pgcrypto-pubkey",
    ),
    [],
  );
});

test("an sslmode example in markdown prose is NOT flagged", () => {
  assert.deepEqual(
    run("README.md", "Set `sslmode=require` in your connection string.").filter((f) =>
      f.ruleId.startsWith("db-"),
    ),
    [],
  );
});

test("sslmode=disable is NOT flagged (no TLS session, so no harvestable key exchange)", () => {
  assert.deepEqual(
    run(".env", "DATABASE_URL=postgres://u:p@db/app?sslmode=disable\n").filter((f) =>
      f.ruleId.startsWith("db-"),
    ),
    [],
  );
});

test("commented-out `# …sslmode=require` and `-- pgp_pub_encrypt` are NOT flagged", () => {
  assert.deepEqual(
    run(".env", "# DATABASE_URL=postgres://db/app?sslmode=require\n").filter((f) =>
      f.ruleId.startsWith("db-"),
    ),
    [],
  );
  assert.deepEqual(
    run("schema.sql", "-- SELECT pgp_pub_encrypt('x', k) -- example\n").filter((f) =>
      f.ruleId.startsWith("db-"),
    ),
    [],
  );
});

test("weak sslmode is caught across PGSSLMODE / MySQL ssl-mode / YAML forms", () => {
  assert.ok(rule(run(".env", "PGSSLMODE=require\n"), "db-weak-sslmode"), "PGSSLMODE env var");
  assert.ok(
    rule(run("my.cnf", "ssl-mode=PREFERRED\n"), "db-weak-sslmode"),
    "MySQL hyphenated ssl-mode=PREFERRED",
  );
  assert.ok(
    rule(run("database.yml", "  sslmode: require\n"), "db-weak-sslmode"),
    "Rails YAML sslmode: require",
  );
  assert.ok(
    rule(run("app.yml", "ssl_mode: require\n"), "db-weak-sslmode"),
    "underscore ssl_mode: require (gate and regex agree)",
  );
  // verify-full (real verification) must NOT fire.
  assert.equal(rule(run(".env", "PGSSLMODE=verify-full\n"), "db-weak-sslmode"), undefined);
});

test("a `; sslmode=require` ini comment is NOT flagged", () => {
  assert.deepEqual(
    run("db.ini", "; sslmode=require\n").filter((f) => f.ruleId.startsWith("db-")),
    [],
  );
});
