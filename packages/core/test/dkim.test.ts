/**
 * Tests for DKIM classical email-signing detection — published DNS TXT key
 * records (RFC 6376), Ed25519 records (RFC 8463), OpenDKIM signer config, and
 * captured `DKIM-Signature:` header fields. Imports the detector directly so the
 * gating/marker/comment-masking behaviour is exercised in isolation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { dkimDetector } from "../src/detectors/dkim.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  return dkimDetector.appliesTo(file) ? dkimDetector.detect({ file, content }) : [];
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("published RSA DKIM TXT record (k=rsa) classifies as RSA, signature, hndl:false", () => {
  const content =
    'sel1._domainkey.example.com. IN TXT ( "v=DKIM1; k=rsa; ' +
    'p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3example" )';
  const f = rule(run("example.com.zone", content), "dkim-rsa-key");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("published Ed25519 DKIM TXT record (k=ed25519) classifies as EdDSA, signature, hndl:false", () => {
  const content =
    'brisbane._domainkey.example.com. IN TXT ( "v=DKIM1; k=ed25519; ' +
    'p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" )';
  const f = rule(run("example.com.zone", content), "dkim-ed25519-key");
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
});

test("OpenDKIM `SigningAlgorithm rsa-sha256` classifies as RSA", () => {
  const content = ["# opendkim.conf", "Domain example.com", "SigningAlgorithm rsa-sha256"].join(
    "\n",
  );
  const f = rule(run("opendkim.conf", content), "dkim-rsa-key");
  assert.equal(f?.algorithm, "RSA");
  assert.equal(f?.hndl, false);
});

test("captured DKIM-Signature header `a=ed25519-sha256` classifies as EdDSA", () => {
  const content = [
    "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;",
    "  d=example.com; s=brisbane; t=1706000000;",
    "  h=from:to:subject:date; bh=...; b=...",
  ].join("\n");
  const f = rule(run("captured-header.txt", content), "dkim-ed25519-key");
  assert.equal(f?.algorithm, "EdDSA");
});

test("legacy DKIM-Signature `a=rsa-sha1` still classifies as RSA", () => {
  const content = "DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=old; b=...";
  const f = rule(run("legacy.txt", content), "dkim-rsa-key");
  assert.equal(f?.algorithm, "RSA");
});

test("prose .md mentioning `k=rsa` is NOT flagged (gated out of config extensions)", () => {
  const prose =
    "## DKIM setup\n\nPublish a TXT record like `v=DKIM1; k=rsa; p=...` at the selector.";
  assert.deepEqual(run("docs/dkim-guide.md", prose), []);
});

test("a COMMENTED-OUT DKIM record does NOT fire (comment masking)", () => {
  const content = [
    "; old key, rotated out — do not use:",
    '; sel0._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGfOLD"',
  ].join("\n");
  assert.deepEqual(run("example.com.zone", content), []);
});

test("non-DKIM .conf with no marker produces no findings (fast-reject gate)", () => {
  const content = [
    "# unrelated app config",
    "retries = 3",
    "algorithm = round-robin",
    "a=b; k=v",
  ].join("\n");
  assert.deepEqual(run("app.conf", content), []);
});

test("a bare `k=rsa` in unrelated config/text is NOT flagged (marker is not self-satisfying)", () => {
  // `k=rsa` is what the RSA rule matches, so it must NOT double as its own marker,
  // or any `.txt`/`.conf` mentioning it in passing would false-positive.
  assert.deepEqual(run("notes.txt", "reminder: set k=rsa for the legacy widget importer"), []);
  assert.deepEqual(run("kv.conf", "partition_key=rsa\nsort=asc"), []);
});
