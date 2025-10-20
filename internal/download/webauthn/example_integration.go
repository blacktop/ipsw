//go:build ignore
// +build ignore

// Example: How to integrate WebAuthn into dev_portal.go
//
// This file shows the key changes needed to add passkey support
// to the existing Apple Developer Portal authentication flow.
//
// NOTE: This is an example/documentation file and is not compiled.

package example

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download/webauthn"
)

// STEP 1: Add WebAuthn response types to dev_portal.go
// Add this near the other response structs (around line 200)

type webAuthnChallengeResponse struct {
	Challenge        string                      `json:"challenge,omitempty"`
	RpId             string                      `json:"rpId,omitempty"`
	Timeout          int                         `json:"timeout,omitempty"`
	AllowCredentials []webAuthnCredential        `json:"allowCredentials,omitempty"`
	UserVerification string                      `json:"userVerification,omitempty"`
	Extensions       map[string]json.RawMessage  `json:"extensions,omitempty"`
}

type webAuthnCredential struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// STEP 2: Modify signIn() to detect and handle WebAuthn challenges
// Insert this code in dev_portal.go after the initial login POST (around line 750)

func (dp *DevPortal) signInWithWebAuthnSupport(username, password string) error {
	// ... existing hashcash and POST request code ...

	response, err := dp.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Login: (%d):\n%s\n", response.StatusCode, string(body))

	// NEW: Check for WebAuthn challenge in response
	if response.StatusCode == 200 {
		var authResp map[string]interface{}
		if err := json.Unmarshal(body, &authResp); err == nil {
			// Check if response contains WebAuthn challenge
			if challengeData, ok := authResp["webauthn"].(map[string]interface{}); ok {
				log.Info("🔐 Apple requires passkey authentication")
				
				// Try WebAuthn first, fallback to 2FA if it fails
				if err := dp.handleWebAuthnChallenge(challengeData); err != nil {
					log.Warnf("Passkey authentication failed: %v", err)
					log.Info("Falling back to 2FA...")
					// Continue to existing 2FA code below
				} else {
					// WebAuthn succeeded
					return dp.storeSession()
				}
			}
		}
	}

	// ... existing SRP and 2FA code continues here ...

	if response.StatusCode == 409 {
		// ... existing 2FA handling ...
	}

	return nil
}

// STEP 3: Add WebAuthn handler methods
// Add these new methods to dev_portal.go

func (dp *DevPortal) handleWebAuthnChallenge(challengeData map[string]interface{}) error {
	// Only available on macOS
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("WebAuthn passkey authentication only supported on macOS")
	}

	// Parse challenge
	var challenge webAuthnChallengeResponse
	chalJSON, err := json.Marshal(challengeData)
	if err != nil {
		return fmt.Errorf("failed to marshal challenge: %w", err)
	}
	if err := json.Unmarshal(chalJSON, &challenge); err != nil {
		return fmt.Errorf("failed to parse challenge: %w", err)
	}

	// Create WebAuthn client
	client, err := webauthn.NewClient("")
	if err != nil {
		return fmt.Errorf("WebAuthn client unavailable: %w", err)
	}

	// Convert to internal format
	webauthnChallenge := webauthn.AppleWebAuthnChallenge{
		Challenge:        challenge.Challenge,
		RpId:             challenge.RpId,
		Timeout:          challenge.Timeout,
		UserVerification: challenge.UserVerification,
	}

	// Convert credentials
	for _, cred := range challenge.AllowCredentials {
		webauthnChallenge.AllowCredentials = append(webauthnChallenge.AllowCredentials,
			webauthn.AppleAllowedCredential{
				Type:       cred.Type,
				ID:         cred.ID,
				Transports: cred.Transports,
			})
	}

	// Perform authentication
	log.Info("Requesting passkey authentication (Touch ID)...")
	assertion, err := webauthn.HandleAppleWebAuthn(client, webauthnChallenge)
	if err != nil {
		return fmt.Errorf("passkey authentication failed: %w", err)
	}

	// Send assertion back to Apple
	return dp.sendWebAuthnAssertion(assertion)
}

func (dp *DevPortal) sendWebAuthnAssertion(assertion *webauthn.AppleWebAuthnResponse) error {
	// Marshal the assertion
	data, err := json.Marshal(assertion)
	if err != nil {
		return fmt.Errorf("failed to marshal assertion: %w", err)
	}

	// Send to Apple's verification endpoint
	req, err := http.NewRequest("POST", completeURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	dp.updateRequestHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := dp.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send assertion: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	respBody, _ := io.ReadAll(resp.Body)
	log.Debugf("POST WebAuthn Assertion: (%d):\n%s\n", resp.StatusCode, string(respBody))

	if resp.StatusCode != 200 {
		return fmt.Errorf("assertion verification failed: status %d: %s", resp.StatusCode, string(respBody))
	}

	// Update session from response headers
	dp.config.SessionID = resp.Header.Get("X-Apple-Id-Session-Id")
	dp.config.SCNT = resp.Header.Get("Scnt")

	log.Info("✅ Passkey authentication successful")
	return nil
}

// STEP 4: Optional - Add proactive WebAuthn check in Login()
// This could be added to the Login() method to try passkeys first

func (dp *DevPortal) tryPasskeyFirst(username string) bool {
	// Only on macOS
	if runtime.GOOS != "darwin" {
		return false
	}

	// Check if passkey helper is available
	if _, err := webauthn.NewClient(""); err != nil {
		log.Debug("Passkey helper not available")
		return false
	}

	// Could probe Apple's endpoint to see if passkey is available
	// for this account (implementation left as exercise)
	
	log.Info("🔑 Passkey authentication available for this device")
	return true
}

// USAGE EXAMPLE:
//
// In cmd/ipsw/cmd/download/download_dev.go, the flow becomes:
//
// 1. User runs: ipsw download dev --os
// 2. Login() checks for saved credentials
// 3. If on macOS, tryPasskeyFirst() checks availability
// 4. POST to Apple's login endpoint
// 5. Apple responds with either:
//    a) WebAuthn challenge → handleWebAuthnChallenge() → Touch ID
//    b) 2FA required → existing code → SMS/device code
// 6. Session established, downloads proceed

// TESTING:
//
// Test the implementation:
//   go run ./cmd/ipsw download dev --os -v
//
// Expected flow:
//   1. "🔐 Apple requires passkey authentication"
//   2. macOS shows Touch ID prompt
//   3. "✅ Passkey authentication successful"
//   4. Downloads begin

// FALLBACK STRATEGY:
//
// If passkey fails for any reason:
//   - User cancellation → Prompt for 2FA
//   - No passkey registered → Fall back to password + 2FA
//   - Helper not found → Fall back to password + 2FA
//   - macOS too old → Fall back to password + 2FA
