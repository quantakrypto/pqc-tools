import assert from "node:assert/strict";
import { test } from "node:test";

import { assertCheckConfig, isCheckId, normalizeProbeTarget, parseChecks } from "../src/checks.js";
import { dispatchAskedFor, splitPatterns } from "../src/main.js";

/**
 * The `checks` input is what collapses three workflow files into one. Its
 * contract has to be exact: a silently-dropped check would report a clean run
 * for something that never happened, which is the failure mode this whole
 * change exists to remove.
 */

test("defaults to scan, so a v1 workflow keeps working untouched", () => {
  assert.deepEqual(parseChecks(""), ["scan"]);
  assert.deepEqual(parseChecks("   "), ["scan"]);
});

test("accepts any subset, comma- or space-separated, in any case", () => {
  assert.deepEqual(parseChecks("scan"), ["scan"]);
  assert.deepEqual(parseChecks("scan,probe"), ["scan", "probe"]);
  assert.deepEqual(parseChecks("scan conformance probe"), ["scan", "conformance", "probe"]);
  assert.deepEqual(parseChecks("PROBE, Scan"), ["probe", "scan"]);
  assert.deepEqual(parseChecks("scan, ,probe,"), ["scan", "probe"]);
});

test("covers all seven useful combinations as plain subsets", () => {
  const combos = [
    ["scan"],
    ["conformance"],
    ["probe"],
    ["scan", "conformance"],
    ["scan", "probe"],
    ["conformance", "probe"],
    ["scan", "conformance", "probe"],
  ];
  for (const combo of combos) {
    assert.deepEqual(parseChecks(combo.join(",")), combo, combo.join(","));
  }
});

test("de-duplicates while preserving order", () => {
  assert.deepEqual(parseChecks("probe,scan,probe"), ["probe", "scan"]);
});

test("throws on an unknown check rather than ignoring it", () => {
  // Dropping a typo would report a clean run for a check that never ran.
  assert.throws(() => parseChecks("scan,prboe"), /unknown check "prboe"/);
  assert.throws(() => parseChecks("sieve"), /unknown check "sieve"/);
});

test("isCheckId narrows only the three real checks", () => {
  assert.ok(isCheckId("scan"));
  assert.ok(isCheckId("conformance"));
  assert.ok(isCheckId("probe"));
  assert.ok(!isCheckId("expert"));
  assert.ok(!isCheckId(""));
});

/**
 * Config is validated before any check runs, so a three-check workflow does not
 * spend two minutes scanning and then die on a missing probe target.
 */
test("requires the config each selected check needs, and names the input", () => {
  assert.throws(
    () => assertCheckConfig(["probe"], { probeTarget: "", conformanceImpl: "" }),
    /probe-target/,
  );
  assert.throws(
    () => assertCheckConfig(["conformance"], { probeTarget: "", conformanceImpl: "  " }),
    /conformance-impl/,
  );
  // Both missing: both named, in one message, so it takes one round trip to fix.
  assert.throws(
    () => assertCheckConfig(["probe", "conformance"], { probeTarget: "", conformanceImpl: "" }),
    /probe-target.*conformance-impl/s,
  );
});

test("does not require config for checks that were not selected", () => {
  assert.doesNotThrow(() => assertCheckConfig(["scan"], { probeTarget: "", conformanceImpl: "" }));
});

test("normalizes a probe target to a bare host", () => {
  assert.equal(normalizeProbeTarget("https://leonacosta.com"), "leonacosta.com");
  assert.equal(normalizeProbeTarget("api.example.com"), "api.example.com");
  assert.equal(normalizeProbeTarget("https://api.example.com:8443/v1?x=1#t"), "api.example.com");
  // Credentials must not survive into a committed workflow or an attestation.
  assert.equal(normalizeProbeTarget("https://user:secret@api.example.com/p"), "api.example.com");
  assert.equal(normalizeProbeTarget("https://[2001:db8::1]:443/"), "2001:db8::1");
  assert.equal(normalizeProbeTarget("  example.com  "), "example.com");
  assert.equal(normalizeProbeTarget(""), "");
});

/**
 * One audit run id belongs to one check. A workflow set to run all three still
 * receives a single dispatch naming one of them, so only that check may post
 * against the id — otherwise the last result would overwrite the one the
 * dashboard actually asked for.
 */
test("only the dispatched check reports against the run id", () => {
  assert.ok(dispatchAskedFor("quantakrypto-scan", "scan"));
  assert.ok(dispatchAskedFor("quantakrypto-conformance", "conformance"));
  assert.ok(dispatchAskedFor("quantakrypto-probe", "probe"));

  assert.ok(!dispatchAskedFor("quantakrypto-scan", "probe"));
  assert.ok(!dispatchAskedFor("quantakrypto-probe", "conformance"));
});

test("an unrecognised or absent dispatch reports nothing", () => {
  for (const check of ["scan", "conformance", "probe"] as const) {
    assert.ok(!dispatchAskedFor(null, check));
    assert.ok(!dispatchAskedFor("", check));
    assert.ok(!dispatchAskedFor("some-other-event", check));
  }
});

/**
 * The CLI has --ignore and --include; the action had neither, so a repository
 * with content, fixtures or docs that DESCRIBE cryptography had no way to
 * exclude them. Our own website proved it: two of its four high findings were
 * marketing copy about RSA and HSMs. A baseline is the wrong tool for that — it
 * records them as known debt rather than as not-code.
 */
test("pattern lists accept commas, newlines, and the mix of both YAML encourages", () => {
  assert.deepEqual(splitPatterns("src/content"), ["src/content"]);
  assert.deepEqual(splitPatterns("a,b"), ["a", "b"]);
  assert.deepEqual(splitPatterns("a\nb"), ["a", "b"]);
  assert.deepEqual(splitPatterns("a, b\nc"), ["a", "b", "c"]);
});

test("pattern lists tolerate the whitespace a block scalar leaves behind", () => {
  assert.deepEqual(splitPatterns("  a  ,\n  b  \n"), ["a", "b"]);
  assert.deepEqual(splitPatterns("a,,b"), ["a", "b"]);
});

test("an unset pattern list is empty, not a pattern matching everything", () => {
  // [] must mean "no restriction"; [""] would restrict the walk to nothing.
  assert.deepEqual(splitPatterns(""), []);
  assert.deepEqual(splitPatterns("   "), []);
  assert.deepEqual(splitPatterns(",\n,"), []);
});
