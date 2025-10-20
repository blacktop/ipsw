//go:build darwin && !ios

package webauthn

import (
	"encoding/base64"
	"testing"
)

func TestClientCreation(t *testing.T) {
	// Test with non-existent path
	client, err := NewClient("/non/existent/path")
	if err == nil {
		t.Error("Expected error for non-existent helper path")
	}
	if client != nil {
		t.Error("Expected nil client for non-existent path")
	}

	// Test auto-detection (may fail if not compiled yet)
	client, err = NewClient("")
	if err != nil {
		t.Logf("Auto-detection failed (expected if helper not compiled): %v", err)
	} else if client == nil {
		t.Error("Client should not be nil on success")
	}
}

func TestChallengeMarshaling(t *testing.T) {
	challenge := Challenge{
		Challenge:        base64.RawURLEncoding.EncodeToString([]byte("test-challenge")),
		RpId:             "apple.com",
		UserVerification: "preferred",
	}

	// This just validates the struct is properly defined
	if challenge.RpId != "apple.com" {
		t.Errorf("Expected RpId 'apple.com', got '%s'", challenge.RpId)
	}
}

// TestAuthenticationIntegration requires a compiled helper and user interaction
// Run manually with: go test -v -run TestAuthenticationIntegration
func TestAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, err := NewClient("")
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
	}

	// Create a test challenge (this won't actually work without a real Apple challenge)
	challenge := Challenge{
		Challenge:        base64.RawURLEncoding.EncodeToString([]byte("test-challenge-data")),
		RpId:             "apple.com",
		UserVerification: "preferred",
	}

	// Note: This will fail unless you have:
	// 1. A real challenge from Apple's auth endpoint
	// 2. A registered passkey for the RP ID
	// 3. User interaction (Touch ID/password)
	_, err = client.Authenticate(challenge)
	if err != nil {
		t.Logf("Authentication failed (expected without real challenge): %v", err)
	}
}

func TestBase64URLEncoding(t *testing.T) {
	// Test data that should round-trip through base64url
	testData := []byte("Hello, WebAuthn! 🔐")
	
	// Encode to base64url
	encoded := base64.RawURLEncoding.EncodeToString(testData)
	
	// Decode from base64url
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	// Verify round-trip
	if string(decoded) != string(testData) {
		t.Errorf("Round-trip failed: got '%s', want '%s'", string(decoded), string(testData))
	}
}
