// Package auth issues and validates API bearer tokens as RS256-signed JWTs
// using github.com/golang-jwt/jwt. RS256 is RSASSA-PKCS1-v1_5 over SHA-256, so
// the token's authenticity rests on an RSA private key.
package auth

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueToken signs a one-hour bearer token for subject using the RS256 method.
func IssueToken(subject string, key *rsa.PrivateKey) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    "api.internal",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(key)
}
