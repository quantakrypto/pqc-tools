// Package gateway builds the TLS server configuration for the public API edge.
// The profile is deliberately conservative but entirely classical: a TLS 1.2
// floor with ECDHE-RSA / ECDHE-ECDSA suites and the NIST curves for key
// agreement.
package gateway

import "crypto/tls"

// serverTLSConfig returns the hardened-yet-classical edge listener config.
func serverTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.X25519,
		},
	}
}
