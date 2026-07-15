// Package handshake negotiates the transport-layer shared secret. It supports
// an X25519 fast path, an X448 high-security profile (via cloudflare/circl), and
// a NIST P-256 fallback using the modern crypto/ecdh interface.
package handshake

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/cloudflare/circl/dh/x448"
)

// x25519Ephemeral generates an ephemeral X25519 key for the Noise-style
// handshake.
func x25519Ephemeral() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// x448Ephemeral generates an ephemeral X448 key for the high-security profile.
func x448Ephemeral() (pub, priv x448.Key, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	x448.KeyGen(&pub, &priv)
	return
}

// p256Shared performs an ECDH key agreement on NIST P-256 and returns the raw
// shared secret.
func p256Shared(peer *ecdh.PublicKey) ([]byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(peer)
}
