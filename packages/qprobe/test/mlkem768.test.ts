/**
 * Tests for the ML-KEM-768 encapsulation-key ENCODING used to build a well-formed
 * X25519MLKEM768 key_share (no full keygen — see mlkem768.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  byteEncode12,
  byteDecode12,
  wellFormedMlKem768Ek,
  ML_KEM_768_EK_BYTES,
  ML_KEM_Q,
} from "../src/mlkem768.js";

test("byteEncode12 / byteDecode12 round-trip 256 in-range coefficients", () => {
  const coeffs = Array.from({ length: 256 }, (_, i) => (i * 13 + 7) % ML_KEM_Q);
  const encoded = byteEncode12(coeffs);
  assert.equal(encoded.length, 384);
  assert.deepEqual(byteDecode12(encoded), coeffs);
});

test("byteEncode12 masks to 12 bits and rejects the wrong count", () => {
  assert.throws(() => byteEncode12(new Array(255).fill(0)), RangeError);
  // Boundary values encode losslessly.
  const edge = Array.from({ length: 256 }, (_, i) => (i % 2 === 0 ? 0 : ML_KEM_Q - 1));
  assert.deepEqual(byteDecode12(byteEncode12(edge)), edge);
});

test("wellFormedMlKem768Ek is 1184 bytes with every coefficient in [0, q)", () => {
  const ek = wellFormedMlKem768Ek();
  assert.equal(ek.length, ML_KEM_768_EK_BYTES);
  assert.equal(ek.length, 1184);
  // The first 3*384 bytes are ByteEncode₁₂ of k=3 polynomials; check each decodes in range.
  for (let p = 0; p < 3; p++) {
    const poly = byteDecode12(ek.subarray(p * 384, p * 384 + 384));
    assert.ok(
      poly.every((c) => c >= 0 && c < ML_KEM_Q),
      "coefficients must be in [0, q) to pass the encaps modulus check",
    );
  }
});

test("two encapsulation keys differ (randomised)", () => {
  assert.notEqual(wellFormedMlKem768Ek().toString("hex"), wellFormedMlKem768Ek().toString("hex"));
});
