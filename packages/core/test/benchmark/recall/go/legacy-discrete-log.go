// Package legacyverify supports a legacy partner integration that still relies
// on discrete-log primitives: DSA-signed tokens and a fixed finite-field
// Diffie-Hellman group shipped as PEM parameters. New key material is only
// provisioned for the compatibility bridge; nothing new should adopt these.
package legacyverify

import (
	"crypto/dsa"
	"crypto/rand"
)

// dhGroupPEM pins the classical MODP group the partner negotiates against. The
// parameters are loaded once at startup by the DH handshake shim.
const dhGroupPEM = `-----BEGIN DH PARAMETERS-----
MIGLAoGBANILonI95F7CfE7k3AocDKAqSN4sO4pkAiE3FSyAyBUHfTc0lQg1Xr8k
Wh79GjXiRFPvqSmA8he+sF68/9ec7MWyr09C6vCAK9fEMYn0vgbUmis4xrgBiTRj
NlJfH/knlf5LENOZBP67WbsFfMsey+Nj1/NyvBNgjCWnFa0xwRWfAgECAgIArw==
-----END DH PARAMETERS-----`

// provisionBridgeKey generates fresh DSA parameters and a key pair for the
// compatibility bridge. DSA is deprecated but the partner has not migrated.
func provisionBridgeKey() (*dsa.PrivateKey, error) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256); err != nil {
		return nil, err
	}
	priv := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		return nil, err
	}
	return priv, nil
}
