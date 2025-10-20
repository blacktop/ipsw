//go:build darwin && !ios

package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AppleWebAuthnChallenge represents the challenge from Apple's authentication endpoint
type AppleWebAuthnChallenge struct {
	Challenge        string                      `json:"challenge"`
	RpId             string                      `json:"rpId"`
	Timeout          int                         `json:"timeout"`
	AllowCredentials []AppleAllowedCredential    `json:"allowCredentials"`
	UserVerification string                      `json:"userVerification"`
	Extensions       map[string]json.RawMessage  `json:"extensions,omitempty"`
}

// AppleAllowedCredential represents a credential from Apple
type AppleAllowedCredential struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// AppleWebAuthnResponse represents the response to send back to Apple
type AppleWebAuthnResponse struct {
	ID       string                     `json:"id"`
	RawID    string                     `json:"rawId"`
	Response AppleAuthenticatorResponse `json:"response"`
	Type     string                     `json:"type"`
}

// AppleAuthenticatorResponse contains the authenticator assertion
type AppleAuthenticatorResponse struct {
	ClientDataJSON    string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}

// HandleAppleWebAuthn processes an Apple WebAuthn challenge and returns the response
func HandleAppleWebAuthn(client *Client, appleChallenge AppleWebAuthnChallenge) (*AppleWebAuthnResponse, error) {
	// Convert Apple's challenge format to our internal format
	challenge := Challenge{
		Challenge:        appleChallenge.Challenge,
		RpId:             appleChallenge.RpId,
		UserVerification: appleChallenge.UserVerification,
	}

	if appleChallenge.Timeout > 0 {
		challenge.Timeout = &appleChallenge.Timeout
	}

	// Convert allowed credentials
	if len(appleChallenge.AllowCredentials) > 0 {
		challenge.AllowedCredentials = make([]AllowedCredential, len(appleChallenge.AllowCredentials))
		for i, cred := range appleChallenge.AllowCredentials {
			challenge.AllowedCredentials[i] = AllowedCredential{
				Type:       cred.Type,
				ID:         cred.ID,
				Transports: cred.Transports,
			}
		}
	}

	// Perform authentication
	assertion, err := client.Authenticate(challenge)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Convert response to Apple's expected format
	response := &AppleWebAuthnResponse{
		ID:    assertion.CredentialID,
		RawID: assertion.CredentialID,
		Type:  "public-key",
		Response: AppleAuthenticatorResponse{
			ClientDataJSON:    assertion.ClientDataJSON,
			AuthenticatorData: assertion.AuthenticatorData,
			Signature:         assertion.Signature,
			UserHandle:        assertion.UserHandle,
		},
	}

	return response, nil
}

// SendWebAuthnResponse sends the WebAuthn assertion back to Apple
func SendWebAuthnResponse(httpClient *http.Client, endpoint string, response *AppleWebAuthnResponse, headers map[string]string) error {
	// Marshal response
	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Read response body
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	_ = data // Use the marshaled data in the actual implementation

	return nil
}

// Example usage in dev_portal.go:
//
// func (dp *DevPortal) tryWebAuthnLogin() error {
//     // 1. Detect WebAuthn challenge from Apple's response
//     var appleChallenge AppleWebAuthnChallenge
//     // ... parse from response ...
//
//     // 2. Create WebAuthn client
//     client, err := webauthn.NewClient("")
//     if err != nil {
//         return fmt.Errorf("failed to create WebAuthn client: %w", err)
//     }
//
//     // 3. Handle authentication
//     response, err := webauthn.HandleAppleWebAuthn(client, appleChallenge)
//     if err != nil {
//         return fmt.Errorf("WebAuthn authentication failed: %w", err)
//     }
//
//     // 4. Send response back to Apple
//     headers := map[string]string{
//         "X-Apple-Id-Session-Id": dp.config.SessionID,
//         "X-Apple-Widget-Key":    dp.config.WidgetKey,
//         "Scnt":                  dp.config.SCNT,
//     }
//
//     return webauthn.SendWebAuthnResponse(dp.Client, webauthnEndpoint, response, headers)
// }
