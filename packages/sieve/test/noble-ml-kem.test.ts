/**
 * Pinned regression guard for the FIPS 203 §7.2 encapsulation-key ("modulus")
 * check, run against a KNOWN version of a real, audited implementation:
 * `@noble/post-quantum` (pinned to an exact version in the root devDependencies).
 *
 * Backstory: Sieve's `encaps-ek-coeff-out-of-range` check once surfaced a genuine
 * §7.2 deviation in `@noble/post-quantum` — ML-KEM `encapsulate` in 0.5.x accepted
 * an encapsulation key with a coefficient ≥ q = 3329, which a conformant Encaps
 * must reject. The maintainers fixed it in 0.6.0 (2026-03-31) by adding the mod-q
 * reduction in the d=12 ByteDecode12 path; 0.6.0+ reject it. See
 * docs/validation/sieve-real-impl.md.
 *
 * The lesson that motivated this file: a conformance finding must be re-verified
 * against the *pinned, current* release, not whatever happened to be installed. So
 * this test asserts the exact behavior of the version we pin — it fails loudly if a
 * dependency bump changes it, forcing the doc/claim to be re-checked rather than
 * drifting silently.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

const Q = 3329;

/** Force coefficient 0 of the encapsulation key out of range (to 0xFFF = 4095). */
function corruptFirstCoefficient(ek: Uint8Array): Uint8Array {
  const bad = Uint8Array.from(ek);
  // 12-bit packing: coeff0 = byte0 | ((byte1 & 0x0f) << 8). Set it to 4095 ≥ q.
  bad[0] = 0xff;
  bad[1] = (bad[1] as number) | 0x0f;
  return bad;
}

test("@noble/post-quantum ML-KEM-768: a valid encapsulation key encapsulates (control)", () => {
  const { publicKey } = ml_kem768.keygen();
  assert.equal(publicKey.length, 1184, "ML-KEM-768 ek must be 1184 bytes (FIPS 203)");
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  assert.equal(cipherText.length, 1088);
  assert.equal(sharedSecret.length, 32);
});

test("@noble/post-quantum ML-KEM-768: rejects an out-of-range encapsulation key (FIPS 203 §7.2)", () => {
  const { publicKey } = ml_kem768.keygen();
  const bad = corruptFirstCoefficient(publicKey);

  // Sanity: the corruption really is out of range.
  const coeff0 = (bad[0] as number) | (((bad[1] as number) & 0x0f) << 8);
  assert.ok(coeff0 >= Q, `test setup: coeff0 ${coeff0} should be ≥ q=${Q}`);

  // The pinned version (0.6.0+) performs the §7.2 modulus check and MUST reject.
  // If this ever throws differently or (worse) does NOT throw, a dependency change
  // regressed the check — re-verify and update docs/validation/sieve-real-impl.md.
  assert.throws(
    () => ml_kem768.encapsulate(bad),
    /modulus/i,
    "pinned @noble/post-quantum must reject an out-of-range ek (§7.2 modulus check)",
  );
});
