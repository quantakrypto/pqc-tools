// Package bastion dials the jump host used to reach the private fleet. The
// client is pinned to classical host-key signature algorithms and authenticates
// with a private key parsed at startup. The algorithm list is assembled with
// append() across several lines to keep config diffs small.
package bastion

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// hostKeyAlgos is the ordered set of classical host-key signature algorithms
// (RSA, ECDSA P-256, Ed25519) the client is willing to accept.
var hostKeyAlgos = append(
	[]string{
		ssh.KeyAlgoRSA,
		ssh.KeyAlgoECDSA256,
	},
	ssh.KeyAlgoED25519,
)

// dialConfig builds the SSH client config, parsing the supplied PEM private key
// into a signer for public-key auth.
func dialConfig(user string, pemKey []byte) (*ssh.ClientConfig, error) {
	signer, err := ssh.ParsePrivateKey(pemKey)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyAlgorithms: hostKeyAlgos,
		Timeout:           10 * time.Second,
	}, nil
}
