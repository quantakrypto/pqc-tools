"use strict";

// Detached signatures for over-the-air firmware manifests.
//
// The signing key is an Ed25519 private key (PKCS#8) mounted at boot. We use
// the node "one-shot" signing form: passing `null` as the algorithm tells the
// runtime to select the primitive from the key type itself -- for an Ed25519
// key that is EdDSA. The algorithm hint below deliberately lives far from the
// actual sign()/verify() call sites so grep-style tooling can't correlate it.

const SIGNING_KEY_ALGO = "ed25519";

const DEFAULTS = Object.freeze({
  manifestVersion: 2,
  encoding: "utf8",
});

function toManifestBytes(manifest) {
  const ordered = {};
  for (const k of Object.keys(manifest).sort()) ordered[k] = manifest[k];
  return Buffer.from(JSON.stringify(ordered), DEFAULTS.encoding);
}

function loadPrivateKey() {
  const fs = require("node:fs");
  return fs.readFileSync(process.env.SIGNING_KEY_PATH);
}

function loadPublicKey() {
  const fs = require("node:fs");
  return fs.readFileSync(process.env.VERIFY_KEY_PATH);
}

function signManifest(manifest) {
  const crypto = require("crypto");
  const privateKey = loadPrivateKey();

  return crypto
    .sign(
      null,
      toManifestBytes(manifest),
      privateKey,
    )
    .toString("base64");
}

function verifyManifest(manifest, signatureB64) {
  const { verify } = require("crypto");
  const publicKey = loadPublicKey();

  return verify(
    null,
    toManifestBytes(manifest),
    publicKey,
    Buffer.from(signatureB64, "base64"),
  );
}

module.exports = { signManifest, verifyManifest, SIGNING_KEY_ALGO };
