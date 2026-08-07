import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTarget, TargetError } from "../src/target.js";

test("parses host, host:port, and bracketed IPv6", () => {
  assert.deepEqual(parseTarget("example.com", 443), { host: "example.com", port: 443 });
  assert.deepEqual(parseTarget("example.com:8443", 443), { host: "example.com", port: 8443 });
  assert.deepEqual(parseTarget("[::1]:22", 443), { host: "::1", port: 22 });
  assert.deepEqual(parseTarget("git.example.com", 22), { host: "git.example.com", port: 22 });
});

test("refuses CIDR blocks, ranges, wildcards, and lists (a security control)", () => {
  assert.throws(() => parseTarget("10.0.0.0/24", 443), TargetError);
  assert.throws(() => parseTarget("10.0.0.1-50", 443), TargetError);
  assert.throws(() => parseTarget("*.example.com", 443), TargetError);
  assert.throws(() => parseTarget("a.com,b.com", 443), TargetError);
  assert.throws(() => parseTarget("", 443), TargetError);
});

test("rejects invalid ports", () => {
  assert.throws(() => parseTarget("h:0", 443), TargetError);
  assert.throws(() => parseTarget("h:99999", 443), TargetError);
  assert.throws(() => parseTarget("h:notaport", 443), TargetError);
});

/**
 * A probe run failed with `refusing CIDR block "https://leonacosta.com"`. The
 * slash check ran first, so every URL was reported as a range sweep — an error
 * describing a mistake the operator had not made, and one that gave no hint
 * about the fix. URLs are still refused (a target is one named host), but for
 * the right reason and with the host to use.
 */
test("refuses a URL as a URL, not as a CIDR block, and names the host to use", () => {
  assert.throws(
    () => parseTarget("https://leonacosta.com", 443),
    (err: Error) => {
      assert.ok(err instanceof TargetError);
      assert.match(err.message, /not a URL/);
      assert.doesNotMatch(err.message, /CIDR/);
      assert.match(err.message, /Try: leonacosta\.com/);
      return true;
    },
  );
});

test("refuses a bare path as a path, while a real CIDR is still a CIDR", () => {
  assert.throws(
    () => parseTarget("example.com/blog", 443),
    (err: Error) => {
      assert.match(err.message, /path/);
      assert.match(err.message, /Try: example\.com/);
      return true;
    },
  );
  // The security control this sits next to must not have been weakened.
  assert.throws(
    () => parseTarget("10.0.0.0/24", 443),
    (err: Error) => {
      assert.match(err.message, /CIDR block/);
      return true;
    },
  );
});

/**
 * `--i-own-this` is an ownership attestation, so a target that reads as one host
 * and connects to another cannot be accepted. The suggestion deliberately names
 * the host that WOULD have been probed, which is the useful thing to see.
 */
test("refuses credentials in a target and reveals the host they resolve to", () => {
  assert.throws(
    () => parseTarget("mine.com@theirs.com", 443),
    (err: Error) => {
      assert.match(err.message, /credentials/);
      assert.match(err.message, /Try: theirs\.com/);
      return true;
    },
  );
});

test("every scheme is refused, not just https", () => {
  for (const target of [
    "ssh://git.example.com",
    "ldaps://dir.example.com:636",
    "HTTP://example.com",
  ]) {
    assert.throws(() => parseTarget(target, 443), TargetError, target);
  }
});

test("still accepts the plain forms the refusals sit around", () => {
  assert.deepEqual(parseTarget("example.com", 443), { host: "example.com", port: 443 });
  assert.deepEqual(parseTarget("api.example.com:8443", 443), {
    host: "api.example.com",
    port: 8443,
  });
  assert.deepEqual(parseTarget("[2001:db8::1]:443", 443), { host: "2001:db8::1", port: 443 });
});
