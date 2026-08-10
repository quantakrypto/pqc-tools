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

test("reduces an explicitly-written URL to the host qProbe takes", () => {
  assert.equal(normalizeProbeTarget("https://leonacosta.com"), "leonacosta.com");
  assert.equal(normalizeProbeTarget("https://api.example.com/v1?x=1#t"), "api.example.com");
  // A non-default port is meaningful to qProbe, so it survives.
  assert.equal(normalizeProbeTarget("https://api.example.com:8443/v1"), "api.example.com:8443");
  // IPv6 keeps its brackets when a port follows, or qProbe reads the whole
  // thing as one host on the default port.
  assert.equal(normalizeProbeTarget("https://[2001:db8::1]:8443/"), "[2001:db8::1]:8443");
  assert.equal(normalizeProbeTarget("https://[2001:db8::1]/"), "2001:db8::1");
  assert.equal(normalizeProbeTarget("  https://example.com  "), "example.com");
});

test("leaves anything that is not a plain URL for parseTarget to judge", () => {
  for (const raw of ["api.example.com", "api.example.com:8443", "  example.com  ", ""]) {
    assert.equal(normalizeProbeTarget(raw), raw.trim(), raw);
  }
});

/**
 * The rule that makes this safe to call at all.
 *
 * `i-own-this` attests to the target as written in the committed workflow, so
 * the host a reviewer reads has to be the host that gets probed. An earlier
 * version normalised EVERYTHING by prepending a scheme, which turned
 * `our-api.example.com@evil.test` into `evil.test`: a probe of someone else's
 * endpoint under a manufactured attestation, invisible in review.
 *
 * Both forms now come out unchanged, so parseTarget refuses them and says why.
 */
test("never resolves userinfo into a different host", () => {
  for (const hostile of [
    "our-api.example.com@evil.test",
    "https://our-api.example.com@evil.test",
    "https://user:secret@evil.test/p",
  ]) {
    assert.equal(normalizeProbeTarget(hostile), hostile, hostile);
    assert.ok(!normalizeProbeTarget(hostile).startsWith("evil.test"), hostile);
  }
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

/**
 * The wiring, not just the helper.
 *
 * `normalizeProbeTarget` was exported, documented in both action.yml files, and
 * covered by these tests, while nothing called it. A URL therefore reached
 * qProbe raw and was refused, and the legacy workflow reported that as a bare
 * "Check produced no valid report". Every one of those tests passed throughout.
 *
 * So this asserts the path an operator actually takes: a URL in `probe-target`
 * must not fail with a target error. It reaches the network, which is why the
 * assertion is on what the failure ISN'T.
 */
test("a URL in probe-target gets past target parsing", async () => {
  const { runProbeCheck } = await import("../src/extra-checks.js");
  const viaUrl = await runProbeCheck("https://example.invalid", true);
  const viaHost = await runProbeCheck("example.invalid", true);
  for (const r of [viaUrl, viaHost]) {
    assert.doesNotMatch(r.summary, /takes a host, not a URL/);
    assert.doesNotMatch(r.summary, /CIDR/);
  }
});

test("a hostile target is still refused, URL-shaped or not", async () => {
  const { runProbeCheck } = await import("../src/extra-checks.js");
  for (const hostile of [
    "our-api.example.com@evil.test",
    "https://our-api.example.com@evil.test",
  ]) {
    const r = await runProbeCheck(hostile, true);
    assert.equal(r.status, "failed", hostile);
    assert.match(r.summary, /qProbe did not produce a result/, hostile);
  }
});
