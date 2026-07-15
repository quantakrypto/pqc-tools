// Package signing implements request authentication for the outbound webhook
// client. Every request body is signed with an ECDSA P-384 key so that
// receivers can verify authenticity against our published public key.
package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
)

// Signer wraps the private key used to authenticate outbound requests.
type Signer struct {
	key *ecdsa.PrivateKey
}

// NewSigner provisions a signer backed by a freshly generated P-384 key.
func NewSigner() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key}, nil
}

// SignBody returns an ASN.1/DER-encoded ECDSA signature over the canonical JSON
// encoding of the request body.
func (s *Signer) SignBody(body any) ([]byte, error) {
	canonical, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	digest := sha512.Sum384(canonical)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}
