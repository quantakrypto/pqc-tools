// Property-based fuzzing of Sieve's untrusted-input decoder. Sieve drives a
// system-under-test and parses whatever JSON it writes back, so decodeResponse
// must reject any malformed line with the typed ProtocolError, never crash with
// a raw exception. Satisfies the OpenSSF Scorecard fuzzing criterion.
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { decodeResponse, ProtocolError } from "../src/protocol.js";

const lines = fc.oneof(
  fc.string({ maxLength: 8192 }),
  fc.object().map((o) => JSON.stringify(o)),
  fc.json(),
);

test("decodeResponse: rejects any bad line with ProtocolError, never a raw crash", () => {
  fc.assert(
    fc.property(lines, (line) => {
      try {
        decodeResponse(line);
      } catch (err) {
        assert.ok(err instanceof ProtocolError, `unexpected ${(err as Error)?.constructor?.name}`);
      }
    }),
    { numRuns: 8000 },
  );
});
