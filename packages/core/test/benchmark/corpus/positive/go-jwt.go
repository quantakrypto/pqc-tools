package main

import "github.com/golang-jwt/jwt/v5"

// A quoted classical JWS alg token in Go was previously invisible — the jwt-jose
// detector was gated to JS/TS + Python. `HS256` (HMAC) stays correctly unflagged.
func sign() jwt.SigningMethod {
	return jwt.GetSigningMethod("RS256")
}
