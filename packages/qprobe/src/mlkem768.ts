/**
 * Minimal ML-KEM-768 (FIPS 203) encapsulation-key ENCODING — just enough to put a
 * WELL-FORMED encapsulation key into a TLS X25519MLKEM768 key_share so that a
 * server which supports the hybrid group selects it directly (rather than only via
 * a HelloRetryRequest, which misses servers that support-but-don't-prefer it).
 *
 * qProbe never completes the handshake, so it does NOT need real ML-KEM key
 * generation (no NTT, matrix A, or CBD sampling). It only needs bytes the server's
 * ML-KEM.Encaps input check accepts — a `ByteEncode₁₂` of coefficients in `[0, q)`
 * plus a 32-byte ρ. FIPS 203 §7.2's "modulus check" (ByteEncode(ByteDecode(ek))==ek)
 * passes for any in-range coefficients, so a random valid-range vector is accepted.
 * The value is throwaway; we discard the (uncomputable-by-us) shared secret.
 *
 * Pure and unit-tested (encode/decode round-trip, length, in-range).
 */
import { randomBytes } from "node:crypto";

export const ML_KEM_Q = 3329;
const N = 256; // coefficients per polynomial
const K = 3; // ML-KEM-768 rank
/** Encoded encapsulation-key length: 384·k bytes of ByteEncode₁₂ + 32-byte ρ. */
export const ML_KEM_768_EK_BYTES = 384 * K + 32; // 1184

/** ByteEncode₁₂: pack 256 12-bit coefficients (each in [0, q)) into 384 bytes. */
export function byteEncode12(coeffs: readonly number[]): Buffer {
  if (coeffs.length !== N) throw new RangeError(`byteEncode12 expects ${N} coefficients`);
  const out = Buffer.alloc((N * 12) / 8); // 384
  for (let i = 0, o = 0; i < N; i += 2, o += 3) {
    const a = coeffs[i] & 0xfff;
    const b = coeffs[i + 1] & 0xfff;
    out[o] = a & 0xff;
    out[o + 1] = (a >> 8) | ((b & 0x0f) << 4);
    out[o + 2] = b >> 4;
  }
  return out;
}

/** ByteDecode₁₂: inverse of {@link byteEncode12} (for tests). */
export function byteDecode12(bytes: Buffer): number[] {
  if (bytes.length !== 384) throw new RangeError("byteDecode12 expects 384 bytes");
  const out: number[] = new Array(N);
  for (let i = 0, o = 0; i < N; i += 2, o += 3) {
    out[i] = bytes[o] | ((bytes[o + 1] & 0x0f) << 8);
    out[i + 1] = (bytes[o + 1] >> 4) | (bytes[o + 2] << 4);
  }
  return out;
}

/** A random polynomial with all coefficients uniform in [0, q) (throwaway probe key). */
function randomInRangePoly(): number[] {
  // Rejection sampling from 16-bit draws to avoid modulo bias. The key is a
  // throwaway (never used for real security), but a security tool should not
  // ship biased "randomness" even here.
  const MAX = Math.floor(0x10000 / ML_KEM_Q) * ML_KEM_Q;
  const poly: number[] = new Array(N);
  let pool = randomBytes(N * 4);
  let off = 0;
  for (let i = 0; i < N; i++) {
    let v: number;
    do {
      if (off + 2 > pool.length) {
        pool = randomBytes(N * 4);
        off = 0;
      }
      v = pool.readUInt16BE(off);
      off += 2;
    } while (v >= MAX);
    poly[i] = v % ML_KEM_Q;
  }
  return poly;
}

/**
 * Build a WELL-FORMED ML-KEM-768 encapsulation key (1184 bytes): `ByteEncode₁₂` of
 * a random in-range `t̂` (k=3 polynomials) followed by a 32-byte ρ. Accepted by a
 * FIPS 203 encaps input check; the corresponding secret is not recoverable by us
 * (and is not needed — we only observe which group the server selects).
 */
export function wellFormedMlKem768Ek(): Buffer {
  const parts: Buffer[] = [];
  for (let i = 0; i < K; i++) parts.push(byteEncode12(randomInRangePoly()));
  parts.push(randomBytes(32)); // ρ
  return Buffer.concat(parts);
}
