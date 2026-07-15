# End-to-end: migrating to a real PQC library with liboqs / OQS

**quantakrypto does not implement post-quantum cryptography — and that is by
design.** It is the *scanner*, the *CI gate*, and the *conformance harness* that
you wrap around a real PQC library. [liboqs](https://github.com/open-quantum-safe/liboqs)
(and its language bindings and the OpenSSL `oqs-provider`) is the implementation.
They compose; they do not compete.

| Concern | Tool |
|---------|------|
| *Where is my classical, quantum-vulnerable crypto?* | `@quantakrypto/qscan` |
| *Did new classical crypto land in this PR?* | `@quantakrypto/action` (CI gate) |
| *What do I migrate each finding to, and in what order?* | `qscan --tier`, MCP `plan_migration`, `qremediate` |
| *The actual ML-KEM / ML-DSA / X25519MLKEM768 primitives* | **liboqs / OQS** |
| *Does my chosen PQC implementation actually match FIPS 203/204/205?* | `@quantakrypto/sieve` |

This walkthrough runs the full loop on a small key-agreement example:
**scan → migrate (with liboqs) → verify (with sieve) → gate**.

---

## Step 1 — scan: find the classical key agreement

`handshake.mjs`, before migration, does a classical X25519 ECDH:

```js
import { generateKeyPairSync, diffieHellman } from "node:crypto";

// Classical X25519 key agreement — modern, but broken by Shor's algorithm.
const alice = generateKeyPairSync("x25519");
const bob = generateKeyPairSync("x25519");
const shared = diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });
```

qScan flags it as harvest-now-decrypt-later exposed:

```bash
$ npx @quantakrypto/qscan handshake.mjs
  high   node-crypto-keygen  handshake.mjs:4
         Generates a classical X25519 key pair, which is not quantum-safe.
         → hybrid X25519MLKEM768 (ML-KEM-768)
```

The remediation is explicit: don't *drop* X25519, **hybridize** it — combine it
with ML-KEM-768 so the handshake is safe even if one primitive falls.

---

## Step 2 — migrate: hybrid X25519 + ML-KEM-768 via liboqs

Install a liboqs binding (examples: [`liboqs-node`](https://github.com/open-quantum-safe/liboqs-node)
for Node, [`oqs`](https://github.com/open-quantum-safe/liboqs-python) for Python,
or the OpenSSL [`oqs-provider`](https://github.com/open-quantum-safe/oqs-provider)).
`handshake.mjs`, after migration, derives the session key from **both** secrets:

```js
import { generateKeyPairSync, diffieHellman, hkdfSync } from "node:crypto";
import oqs from "liboqs-node"; // the real PQC primitives live here, not in quantakrypto

// Classical half: X25519 (kept on purpose — this is a *hybrid*).
const aliceX = generateKeyPairSync("x25519");
const bobX = generateKeyPairSync("x25519");
const ecdhSecret = diffieHellman({ privateKey: aliceX.privateKey, publicKey: bobX.publicKey });

// Post-quantum half: ML-KEM-768 (FIPS 203) from liboqs.
const kem = new oqs.KeyEncapsulation("ML-KEM-768");
const bobKemPk = kem.generateKeypair();
const { ciphertext, sharedSecret: kemSecret } = kem.encapsulate(bobKemPk);

// The hybrid session key binds BOTH secrets — an attacker must break both.
const sessionKey = hkdfSync("sha256", Buffer.concat([ecdhSecret, kemSecret]), "", "x25519mlkem768", 32);
```

This is exactly the construction the [TLS hybrid draft](https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/)
and CNSA 2.0 point at. quantakrypto told you *what* and *why*; liboqs supplies
the *how*.

> **On the residual X25519 finding:** a hybrid deliberately keeps X25519, so
> qScan will still report it — correctly. That is not a false positive: it is the
> classical half you chose to retain. Acknowledge it with a baseline
> (`qscan --write-baseline quantakrypto.baseline.json`) so CI treats the reviewed
> hybrid as the accepted state and only *new* classical crypto fails the build.

---

## Step 3 — verify: conformance-test the ML-KEM-768 implementation with sieve

A migration is only as good as the primitive under it. Wrap your liboqs-backed
ML-KEM in a tiny [sieve adapter](../../packages/sieve/PROTOCOL.md) (newline-delimited
JSON on stdin/stdout, byte fields base64) and run the battery:

```bash
$ npx @quantakrypto/sieve --impl "node ./ml-kem-adapter.mjs" --param ml-kem-768 --iterations 64
  ✓ key sizes match FIPS 203 Table 2 (pk 1184, sk 2400, ct 1088, ss 32)
  ✓ round-trip: encapsulate → decapsulate recovers the shared secret
  ✓ NIST ACVP known-answer vectors pass
  overallVerdict: PASS
```

Sieve never fabricates KAT values and can't implement ML-KEM itself — it only
checks *your* implementation against the standard's fixed sizes and the public
NIST vectors. If liboqs is wired up wrong (truncated ciphertext, wrong parameter
set), sieve catches it here, before it ships.

The adapter is ~30 lines — see [`packages/sieve/examples/mock-sut.ts`](../../packages/sieve/examples/mock-sut.ts)
for the protocol shape; swap the mock's fake bytes for real `liboqs-node` calls.

---

## Step 4 — gate: keep classical crypto from creeping back

Add the Action so the next PR that introduces classical key agreement fails,
while the baselined hybrid stays green:

```yaml
- uses: quantakrypto/pqc-tools/packages/action@v1
  with:
    path: "."
    severity-threshold: "high"
    baseline: "quantakrypto.baseline.json"
```

The full loop: **quantakrypto finds and gates the classical crypto, liboqs
implements the post-quantum replacement, and sieve proves the replacement is
correct.** That is the intended way to use these tools together.
