/**
 * Tests for the smart-contract / blockchain source detector (Solidity, Move,
 * Cairo) — classical on-chain signature verification (secp256k1 ECDSA on the EVM,
 * Ed25519 / secp256k1 on Move, STARK-curve ECDSA on Cairo). The detector is
 * imported DIRECTLY (it is not yet wired into the registry / DetectorLanguage
 * union); tsx type-strips at run time, so `language: "solidity"` runs regardless.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { solidityDetector } from "../src/detectors/solidity.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  return solidityDetector.appliesTo(file) ? solidityDetector.detect({ file, content }) : [];
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("Solidity ecrecover → ECDSA (secp256k1), signature, hndl:false", () => {
  const f = rule(
    run("Verifier.sol", "address signer = ecrecover(hash, v, r, s);"),
    "sol-ecrecover",
  );
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  assert.equal(f?.severity, "high");
});

test("Solidity OpenZeppelin ECDSA.recover / SignatureChecker / import all fire sol-ecrecover", () => {
  assert.ok(rule(run("A.sol", "address s = ECDSA.recover(hash, sig);"), "sol-ecrecover"));
  assert.ok(rule(run("A.sol", "(address s, ) = ECDSA.tryRecover(hash, sig);"), "sol-ecrecover"));
  assert.ok(
    rule(
      run("A.sol", "bool ok = SignatureChecker.isValidSignatureNow(signer, hash, sig);"),
      "sol-ecrecover",
    ),
  );
  assert.ok(
    rule(
      run("A.sol", 'import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";'),
      "sol-ecrecover",
    ),
  );
  assert.ok(
    rule(
      run("A.sol", 'import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";'),
      "sol-ecrecover",
    ),
  );
  // Solady utils/ECDSA.sol import.
  assert.ok(rule(run("A.sol", 'import {ECDSA} from "solady/utils/ECDSA.sol";'), "sol-ecrecover"));
});

test("Move ed25519 verification → EdDSA, signature, hndl:false", () => {
  const f = rule(
    run("auth.move", "let ok = ed25519::signature_verify_strict(&sig, &pk, msg);"),
    "sol-ed25519",
  );
  assert.equal(f?.algorithm, "EdDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  // Sui's ed25519::ed25519_verify form is matched via the bare token too.
  assert.ok(
    rule(run("auth.move", "let ok = ed25519::ed25519_verify(&sig, &pk, msg);"), "sol-ed25519"),
  );
});

test("Move ecdsa_k1 secp256k1 verification → ECDSA, signature, hndl:false", () => {
  const f = rule(
    run("k1.move", "let ok = ecdsa_k1::secp256k1_verify(&sig, &pk, msg, 1);"),
    "sol-secp256k1-verify",
  );
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  assert.ok(
    rule(
      run("k1.move", "let pk = ecdsa_k1::secp256k1_ecrecover(&sig, msg, 1);"),
      "sol-secp256k1-verify",
    ),
  );
  // The bare `ecrecover(` EVM token must NOT fire on `secp256k1_ecrecover`.
  assert.equal(
    rule(run("k1.move", "let pk = ecdsa_k1::secp256k1_ecrecover(&sig, msg, 1);"), "sol-ecrecover"),
    undefined,
  );
});

test("Cairo check_ecdsa_signature → ECDSA (STARK curve), signature, hndl:false", () => {
  const f = rule(
    run("sig.cairo", "check_ecdsa_signature(message_hash, public_key, sig_r, sig_s);"),
    "cairo-ecdsa",
  );
  assert.equal(f?.algorithm, "ECDSA");
  assert.equal(f?.category, "signature");
  assert.equal(f?.hndl, false);
  // Qualified `ecdsa::check_ecdsa_signature(` form fires too.
  assert.ok(rule(run("sig.cairo", "ecdsa::check_ecdsa_signature(h, pk, r, s);"), "cairo-ecdsa"));
});

test("a .sol with only a keccak256 hash and no signature verification → nothing", () => {
  assert.deepEqual(run("Hash.sol", "bytes32 h = keccak256(abi.encodePacked(a, b));"), []);
});

test("commented-out ecrecover is suppressed (line and block comments)", () => {
  assert.deepEqual(run("A.sol", "// address s = ecrecover(hash, v, r, s);"), []);
  assert.deepEqual(run("A.sol", "/* address s = ecrecover(hash, v, r, s); */"), []);
  // But the live call still fires.
  assert.ok(rule(run("A.sol", "address s = ecrecover(hash, v, r, s);"), "sol-ecrecover"));
});

test("non-smart-contract files (.ts / .rs) are NOT scanned by this detector", () => {
  assert.deepEqual(run("a.ts", "const s = ecrecover(hash, v, r, s);"), []);
  assert.deepEqual(run("a.rs", "let s = ed25519_verify(&sig, &pk, msg);"), []);
});
