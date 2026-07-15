package keys

import (
	"crypto/x509"
	"encoding/pem"
)

// The x509 PEM/DER key + certificate layer — parses classical asymmetric key
// material without ever naming rsa/ecdsa. Real-world miss (golang-jwt *_utils.go).

func loadRSA(der []byte) (interface{}, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

func loadEC(der []byte) (interface{}, error) {
	return x509.ParseECPrivateKey(der)
}

func loadCert(der []byte) (interface{}, error) {
	return x509.ParseCertificate(der)
}

func loadPKIX(block *pem.Block) (interface{}, error) {
	return x509.ParsePKIXPublicKey(block.Bytes)
}
