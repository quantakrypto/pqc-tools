package main

// Parity fixture for the additive go.ts rules: exactly one call per newly-added
// rule (verify/decrypt inverses, classic crypto/elliptic ECDH, and Go TLS
// misconfig). None of these lines may match a pre-existing go-crypto rule
// (rsa/ecdsa/ed25519 Sign|Encrypt|GenerateKey, or ecdh.* curve construction).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
)

func verifyAndDecrypt(
	rsaPriv *rsa.PrivateKey, rsaPub *rsa.PublicKey,
	ecPub *ecdsa.PublicKey, edPub ed25519.PublicKey,
	ciphertext, digest, sig []byte,
) {
	// go-rsa-decrypt (RSA, kem, hndl) — inverse of rsa.EncryptOAEP.
	_, _ = rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, ciphertext, nil)
	// go-rsa-verify (RSA, signature) — inverse of rsa.SignPSS.
	_ = rsa.VerifyPSS(rsaPub, 0, digest, sig, nil)
	// go-ecdsa-verify (ECDSA, signature) — inverse of ecdsa.SignASN1.
	_ = ecdsa.VerifyASN1(ecPub, digest, sig)
	// go-ed25519-verify (EdDSA, signature) — inverse of ed25519.Sign.
	_ = ed25519.Verify(edPub, digest, sig)
}

func classicKeyAgreement() {
	// go-ecdh-classic (ECDH, key-exchange, hndl) — pre-1.20 crypto/elliptic path,
	// distinct from crypto/ecdh curve construction.
	priv, x, y, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	_, _, _ = priv, x, y
}

func legacyTLS() *tls.Config {
	return &tls.Config{
		// go-tls-insecure-skip-verify — disables certificate verification.
		InsecureSkipVerify: true,
		// go-tls-legacy-version — pins a deprecated TLS floor.
		MinVersion: tls.VersionTLS10,
	}
}
