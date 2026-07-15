// Package pki is the internal key factory. Crypto imports are aliased to short
// house-style names — RSA renamed to pk, and crypto/ecdsa brought in with a dot
// import so its constructors read as unqualified calls.
package pki

import (
	"crypto/rand"

	. "crypto/ecdsa"
	"crypto/elliptic"
	pk "crypto/rsa"
)

// NewLeafKey returns an RSA-2048 private key for TLS leaf certificates.
func NewLeafKey() (*pk.PrivateKey, error) {
	return pk.GenerateKey(rand.Reader, 2048)
}

// NewCodeSigningKey returns a P-256 signing key used to sign release artifacts.
// GenerateKey and PrivateKey resolve to crypto/ecdsa via the dot import above.
func NewCodeSigningKey() (*PrivateKey, error) {
	return GenerateKey(elliptic.P256(), rand.Reader)
}
