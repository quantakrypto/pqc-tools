// Property-based fuzzing of qProbe's untrusted-input parsers. These consume raw
// bytes from remote TLS/SSH endpoints and cert chains, so robustness against
// hostile/malformed input is a security property. Satisfies the OpenSSF
// Scorecard fuzzing criterion (fast-check is a dev dependency only).
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { readServerHello, parseRecords } from "../src/clienthello.js";
import { parseKexinit } from "../src/ssh.js";
import { decodeOid } from "../src/x509.js";

const bytes = fc.uint8Array({ maxLength: 4096 }).map((a) => Buffer.from(a));
const RUNS = { numRuns: 5000 };

test("readServerHello: safe wrapper never throws on arbitrary bytes", () => {
  fc.assert(
    fc.property(bytes, (buf) => {
      readServerHello(buf);
    }),
    RUNS,
  );
});

test("parseRecords: never throws on arbitrary bytes", () => {
  fc.assert(
    fc.property(bytes, (buf) => {
      parseRecords(buf);
    }),
    RUNS,
  );
});

test("decodeOid: total function, returns a string, never throws", () => {
  fc.assert(
    fc.property(bytes, (buf) => {
      assert.equal(typeof decodeOid(buf), "string");
    }),
    RUNS,
  );
});

test("parseKexinit: only throws RangeError (no unchecked crash)", () => {
  fc.assert(
    fc.property(bytes, (buf) => {
      try {
        parseKexinit(buf);
      } catch (err) {
        assert.ok(err instanceof RangeError, `unexpected ${(err as Error)?.constructor?.name}`);
      }
    }),
    RUNS,
  );
});
