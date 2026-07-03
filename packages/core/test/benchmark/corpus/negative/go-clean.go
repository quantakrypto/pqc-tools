package main

// This file mentions rsa and ecdsa in comments but calls neither.
import "fmt"

func rsaSummary(ecData string) string {
	// historically used ecdsa.GenerateKey here, now removed
	algorithms := []string{"HS256"}
	return fmt.Sprintf("ec metrics: %s %v", ecData, algorithms)
}
