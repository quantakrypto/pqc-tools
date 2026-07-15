// Package keyrotation manages the signing key material for the token service
// and rotates the active RSA key pair on a fixed schedule.
package keyrotation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// Keyring holds the currently active signing key and the time it was minted.
type Keyring struct {
	mu      sync.RWMutex
	active  *rsa.PrivateKey
	rotated time.Time
}

// Rotate provisions a fresh 3072-bit RSA signing key and marks it active. It is
// invoked from a ticker in the background every 24 hours.
func (k *Keyring) Rotate() error {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return fmt.Errorf("keyrotation: generate signing key: %w", err)
	}
	k.mu.Lock()
	k.active = priv
	k.rotated = time.Now()
	k.mu.Unlock()
	return nil
}

// Sign returns an RSASSA-PSS signature over the SHA-256 digest of payload using
// the currently active key.
func (k *Keyring) Sign(payload []byte) ([]byte, error) {
	k.mu.RLock()
	priv := k.active
	k.mu.RUnlock()
	digest := sha256.Sum256(payload)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}
