package auth

import "testing"

// The golang-jwt SigningMethod* identifiers appear ONLY inside error-message
// string literals here — prose, not usage. The code-only string guard must drop
// them, so this file has zero findings. (Real usage would be `jwt.SigningMethodRS256`.)
func checkMessages(t *testing.T) {
	t.Error("SigningMethodPS256 should accept an auto salt length")
	t.Error("Sign by SigningMethodRS256 should have been accepted")
	t.Logf("expected SigningMethodES256 verification to fail")
}
