/**
 * A REAL Sieve system-under-test (SUT) backed by @noble/post-quantum — an
 * audited, pure-JS implementation of ML-KEM / ML-DSA / SLH-DSA.
 *
 * This is VALIDATION-ONLY tooling. It lives outside the npm workspaces and is
 * never published, so the @qproof/* packages stay zero-dependency. Its purpose
 * is to prove that Sieve's conformance battery drives a real implementation and
 * agrees with it (and that a deliberately broken variant fails).
 *
 * Wire protocol: newline-delimited JSON on stdin/stdout, one request/response
 * per line, byte fields base64-encoded. See packages/sieve/PROTOCOL.md.
 *
 * Fault injection (to demonstrate Sieve catches a bad impl):
 *   SUT_BREAK=bad-roundtrip   decaps returns a wrong (but valid-length) secret
 *   SUT_BREAK=verify-true     verify always returns true
 *   SUT_BREAK=accept-garbage  swallow length errors and return zeros
 */
import { createInterface } from "node:readline";
import * as mlkem from "@noble/post-quantum/ml-kem";
import * as mldsa from "@noble/post-quantum/ml-dsa";
import * as slhdsa from "@noble/post-quantum/slh-dsa";

// Read from argv first: Sieve scrubs the SUT's environment (a security feature),
// so faults must be injected as a command argument, not an env var.
const BREAK = process.argv[2] ?? process.env.SUT_BREAK ?? "";

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

/** Resolve the @noble algorithm object from a Sieve family + param-set id. */
function resolveAlg(family, param) {
  if (family === "ml-kem") return mlkem["ml_kem" + param.split("-").pop()];
  if (family === "ml-dsa") return mldsa["ml_dsa" + param.split("-").pop()];
  if (family === "slh-dsa") return slhdsa[param.replace(/-/g, "_")];
  return undefined;
}

function handle(req) {
  const { id, family, param, op } = req;
  const alg = resolveAlg(family, param);
  if (!alg)
    return { id, ok: false, code: "unsupported", message: `no impl for ${family}/${param}` };

  switch (op) {
    case "keygen": {
      // Honor a provided seed when valid; otherwise generate randomly. Never
      // fail keygen on a seed-length quirk.
      let kp;
      try {
        kp = req.seed ? alg.keygen(unb64(req.seed)) : alg.keygen();
      } catch {
        kp = alg.keygen();
      }
      return { id, ok: true, pk: b64(kp.publicKey), sk: b64(kp.secretKey) };
    }
    case "encaps": {
      // @noble validates the encapsulation key (FIPS 203 input checks) and
      // throws on malformed/out-of-range input — surfaced as a clean error.
      const out = req.coins
        ? alg.encapsulate(unb64(req.pk), unb64(req.coins))
        : alg.encapsulate(unb64(req.pk));
      return { id, ok: true, ct: b64(out.cipherText), ss: b64(out.sharedSecret) };
    }
    case "decaps": {
      let ss = alg.decapsulate(unb64(req.ct), unb64(req.sk));
      if (BREAK === "bad-roundtrip") ss = new Uint8Array(ss.length); // wrong secret
      return { id, ok: true, ss: b64(ss) };
    }
    case "sign": {
      const sig = alg.sign(unb64(req.sk), unb64(req.msg));
      return { id, ok: true, sig: b64(sig) };
    }
    case "verify": {
      const valid =
        BREAK === "verify-true" ? true : alg.verify(unb64(req.pk), unb64(req.msg), unb64(req.sig));
      return { id, ok: true, valid };
    }
    default:
      return { id, ok: false, code: "unsupported", message: `unknown op ${op}` };
  }
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let req;
  try {
    req = JSON.parse(trimmed);
  } catch {
    return; // ignore unparseable input
  }
  let res;
  try {
    res = handle(req);
  } catch (err) {
    if (BREAK === "accept-garbage") {
      // A non-conformant impl that swallows invalid input instead of rejecting.
      res = { id: req.id, ok: true, ss: b64(new Uint8Array(32)), valid: true };
    } else {
      res = { id: req.id, ok: false, code: "error", message: String(err?.message ?? err) };
    }
  }
  process.stdout.write(JSON.stringify(res) + "\n");
});
