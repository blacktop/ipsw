//go:build darwin && !ios

package webauthn

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Challenge represents a WebAuthn authentication challenge
type Challenge struct {
	Challenge          string              `json:"challenge"`
	RpId               string              `json:"rpId"`
	Timeout            *int                `json:"timeout,omitempty"`
	UserVerification   string              `json:"userVerification,omitempty"` // required, preferred, discouraged
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

// ErrorResponse represents an error from the passkey helper
type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// Client provides WebAuthn passkey authentication using macOS native APIs
type Client struct {
	helperPath string
}

// NewClient creates a new WebAuthn client
// If helperPath is empty, it will look for the compiled helper binary
func NewClient(helperPath string) (*Client, error) {
	if helperPath == "" {
		// Try to find the helper in common locations
		locations := []string{
			"./passkey_helper",
			"./internal/download/webauthn/passkey_helper/passkey_helper",
			"/usr/local/bin/passkey_helper",
		}

		for _, loc := range locations {
			if _, err := os.Stat(loc); err == nil {
				helperPath = loc
				break
			}
		}

		if helperPath == "" {
			return nil, fmt.Errorf("passkey_helper binary not found; please compile it first")
		}
	}

	absPath, err := filepath.Abs(helperPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve helper path: %w", err)
	}

	// Verify the helper exists and is executable
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("helper binary not found at %s: %w", absPath, err)
	}

	return &Client{helperPath: absPath}, nil
}

// Authenticate performs WebAuthn authentication using macOS passkeys
func (c *Client) Authenticate(challenge Challenge) (*AssertionResponse, error) {
	// Encode challenge as JSON
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge: %w", err)
	}

	// Execute Swift helper
	cmd := exec.Command(c.helperPath, string(challengeJSON))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try to parse error response
		var errResp ErrorResponse
		if jsonErr := json.Unmarshal(output, &errResp); jsonErr == nil {
			return nil, fmt.Errorf("authentication failed: %s (code: %d)", errResp.Error, errResp.Code)
		}
		return nil, fmt.Errorf("helper execution failed: %w\nOutput: %s", err, string(output))
	}

	// Parse response
	var response AssertionResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w\nOutput: %s", err, string(output))
	}

	return &response, nil
}

// CompileHelper compiles the Swift helper binary
// This is a convenience function for development
func CompileHelper(srcPath, outPath string) error {
	if srcPath == "" {
		srcPath = filepath.Join("internal", "download", "webauthn", "passkey_helper", "main.swift")
	}
	if outPath == "" {
		outPath = filepath.Join("internal", "download", "webauthn", "passkey_helper", "passkey_helper")
	}

	// Compile Swift code
	cmd := exec.Command("swiftc",
		"-o", outPath,
		"-framework", "AuthenticationServices",
		"-framework", "Foundation",
		"-framework", "AppKit",
		srcPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compilation failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}
