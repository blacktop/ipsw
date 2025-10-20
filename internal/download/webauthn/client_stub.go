//go:build !darwin || ios

package webauthn

import "fmt"

// Challenge represents a WebAuthn authentication challenge
type Challenge struct {
	Challenge          string              `json:"challenge"`
	RpId               string              `json:"rpId"`
	Timeout            *int                `json:"timeout,omitempty"`
	UserVerification   string              `json:"userVerification,omitempty"`
	AllowedCredentials []AllowedCredential `json:"allowedCredentials,omitempty"`
}

// AllowedCredential represents a credential descriptor
type AllowedCredential struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// AssertionResponse represents the result of a WebAuthn assertion
type AssertionResponse struct {
	CredentialID      string  `json:"credentialId"`
	AuthenticatorData string  `json:"authenticatorData"`
	ClientDataJSON    string  `json:"clientDataJSON"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle,omitempty"`
}

// Client provides WebAuthn passkey authentication (stub for non-macOS)
type Client struct{}

// NewClient creates a new WebAuthn client (not supported on this platform)
func NewClient(helperPath string) (*Client, error) {
	return nil, fmt.Errorf("WebAuthn passkey authentication is only supported on macOS")
}

// Authenticate performs WebAuthn authentication (not supported on this platform)
func (c *Client) Authenticate(challenge Challenge) (*AssertionResponse, error) {
	return nil, fmt.Errorf("WebAuthn passkey authentication is only supported on macOS")
}
