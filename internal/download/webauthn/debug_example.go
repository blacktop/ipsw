//go:build ignore
// +build ignore

// Debug patch to add to dev_portal.go for WebAuthn challenge detection
// This shows how to temporarily instrument the code to see what Apple sends

package debug

// STEP 1: Add this function to dev_portal.go (temporarily for debugging)

func (dp *DevPortal) inspectAuthResponse(statusCode int, headers http.Header, body []byte) {
	log.Info("🔍 Inspecting authentication response...")
	log.Infof("Status Code: %d", statusCode)
	
	// Log relevant headers
	relevantHeaders := []string{
		"X-Apple-Id-Session-Id",
		"Scnt",
		"X-Apple-Widget-Key",
		"Content-Type",
		"X-Apple-Auth-Attributes",
	}
	
	for _, h := range relevantHeaders {
		if val := headers.Get(h); val != "" {
			log.Debugf("Header %s: %s", h, val)
		}
	}
	
	// Try to parse as JSON
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		log.Warnf("Response is not JSON: %v", err)
		return
	}
	
	// Check for WebAuthn indicators
	indicators := []struct{
		key string
		description string
	}{
		{"publicKeyCredentialRequestOptions", "WebAuthn challenge"},
		{"passkeyAuthentication", "Passkey auth flag"},
		{"authenticationType", "Auth type"},
		{"webAuthnOptions", "WebAuthn options (alternative)"},
		{"credentialRequestOptions", "Credential request (alternative)"},
		{"authType", "Authentication type"},
	}
	
	for _, ind := range indicators {
		if val, ok := jsonResp[ind.key]; ok {
			log.Infof("✅ Found %s: %s", ind.description, ind.key)
			
			// Pretty print the value
			if jsonBytes, err := json.MarshalIndent(val, "", "  "); err == nil {
				log.Infof("%s:\n%s", ind.key, string(jsonBytes))
			}
		}
	}
	
	// Check for service errors
	if errors, ok := jsonResp["serviceErrors"].([]interface{}); ok && len(errors) > 0 {
		log.Warnf("Service errors present: %+v", errors)
	}
	
	// Log full response in debug mode
	if viper.GetBool("verbose") {
		if prettyJSON, err := json.MarshalIndent(jsonResp, "", "  "); err == nil {
			log.Debugf("Full response:\n%s", string(prettyJSON))
		}
	}
}

// STEP 2: Add this call in signIn() right after reading the response body

func (dp *DevPortal) signIn(username, password string) error {
	// ... existing code ...
	
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Login: (%d):\n%s\n", response.StatusCode, string(body))
	
	// ADD THIS LINE TO DEBUG
	dp.inspectAuthResponse(response.StatusCode, response.Header, body)
	
	// ... rest of existing code ...
}

// STEP 3: Example output you might see

/*
Expected output when WebAuthn is available:

🔍 Inspecting authentication response...
Status Code: 412
Header X-Apple-Id-Session-Id: abc123...
Header Scnt: xyz789...
✅ Found WebAuthn challenge: publicKeyCredentialRequestOptions
publicKeyCredentialRequestOptions:
{
  "challenge": "rlHp7l62HW...",
  "rpId": "apple.com",
  "timeout": 60000,
  "userVerification": "preferred",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "credential_id_here",
      "transports": ["internal"]
    }
  ]
}
✅ Found Auth type: authType
authType: "hsa2"

*/

// STEP 4: Alternative - add middleware to log all HTTP traffic

type loggingTransport struct {
	transport http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Log request
	log.Debugf("→ %s %s", req.Method, req.URL)
	
	// Execute request
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	
	// Log response status
	log.Debugf("← %d %s", resp.StatusCode, req.URL)
	
	// For Apple auth endpoints, log the response body
	if strings.Contains(req.URL.String(), "idmsa.apple.com") {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		
		log.Debugf("Response body:\n%s", string(bodyBytes))
		
		// Check for WebAuthn
		if bytes.Contains(bodyBytes, []byte("publicKeyCredential")) ||
		   bytes.Contains(bodyBytes, []byte("passkey")) {
			log.Infof("🔑 WebAuthn/Passkey detected in response!")
		}
	}
	
	return resp, nil
}

// Add to client initialization:
func (dp *DevPortal) Init() error {
	// ... existing code ...
	
	// Wrap transport with logging (only in debug mode)
	if viper.GetBool("verbose") {
		dp.Client.Transport = &loggingTransport{
			transport: dp.Client.Transport,
		}
	}
	
	return nil
}

// PRACTICAL USAGE:

/*
1. Temporarily add inspectAuthResponse() to dev_portal.go

2. Add the call in signIn() after reading response body

3. Run ipsw with verbose logging:
   ipsw download dev --os -v

4. Look for output like:
   ✅ Found WebAuthn challenge: publicKeyCredentialRequestOptions
   
5. Copy the exact field names and structure Apple uses

6. Update the WebAuthn implementation with correct field names

7. Remove the debug code once you have the structure
*/
