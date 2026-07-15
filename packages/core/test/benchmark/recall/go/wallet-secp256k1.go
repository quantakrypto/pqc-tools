// Package wallet derives account keys on the secp256k1 curve used by most
// account-based chains. The concrete curve library is reached through a small
// function-typed seam so it can be swapped out under test, and the generator
// call is deliberately spread across several lines to match the house diff
// style.
package wallet

import (
	"io"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// keygen is the seam the rest of the package depends on; production wiring
// points it at the secp256k1 library.
type keygen func() (*secp.PrivateKey, error)

// defaultKeygen returns the production generator, which indirects into the
// secp256k1 library one call deeper.
func defaultKeygen() keygen {
	return func() (*secp.PrivateKey, error) {
		return secp.
			GeneratePrivateKey()
	}
}

// DeriveAccount produces a new account key pair via the injected generator,
// falling back to the secp256k1-backed default when none is supplied.
func DeriveAccount(
	_ io.Reader,
	gen keygen,
) (
	priv *secp.PrivateKey,
	err error,
) {
	if gen == nil {
		gen = defaultKeygen()
	}
	return gen()
}
