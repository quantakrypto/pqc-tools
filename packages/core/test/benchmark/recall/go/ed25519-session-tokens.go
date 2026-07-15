// Package session mints and signs short-lived session tokens using an Ed25519
// key pair held in memory for the lifetime of the process.
package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

// TokenIssuer signs opaque session tokens.
type TokenIssuer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewTokenIssuer generates the Ed25519 key pair backing this issuer.
func NewTokenIssuer() (*TokenIssuer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &TokenIssuer{pub: pub, priv: priv}, nil
}

// Issue signs the marshalled claims and returns a base64url token body with the
// detached signature appended.
func (t *TokenIssuer) Issue(claims []byte) string {
	sig := ed25519.Sign(t.priv, claims)
	return base64.RawURLEncoding.EncodeToString(append(claims, sig...))
}
