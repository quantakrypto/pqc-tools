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
