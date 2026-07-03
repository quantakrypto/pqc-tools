package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ecdh"
	"crypto/ed25519"
)

func makeKeys() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, msg, nil)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _ = ecdsa.SignASN1(rand.Reader, ecKey, digest)
	curve := ecdh.X25519()
	_, _ = curve.GenerateKey(rand.Reader)
	_, _, _ = ed25519.GenerateKey(rand.Reader)
}
