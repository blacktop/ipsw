package appstore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blacktop/ipsw/internal/download"
)

type bundleIdPlatform string

const (
	IOS    bundleIdPlatform = "IOS"
	MAC_OS bundleIdPlatform = "MAC_OS"
)

type capabilityType string

const (
	ICLOUD                           capabilityType = "ICLOUD"
	IN_APP_PURCHASE                  capabilityType = "IN_APP_PURCHASE"
	GAME_CENTER                      capabilityType = "GAME_CENTER"
	PUSH_NOTIFICATIONS               capabilityType = "PUSH_NOTIFICATIONS"
	WALLET                           capabilityType = "WALLET"
	INTER_APP_AUDIO                  capabilityType = "INTER_APP_AUDIO"
	MAPS                             capabilityType = "MAPS"
	ASSOCIATED_DOMAINS               capabilityType = "ASSOCIATED_DOMAINS"
	PERSONAL_VPN                     capabilityType = "PERSONAL_VPN"
	APP_GROUPS                       capabilityType = "APP_GROUPS"
	HEALTHKIT                        capabilityType = "HEALTHKIT"
	HOMEKIT                          capabilityType = "HOMEKIT"
	WIRELESS_ACCESSORY_CONFIGURATION capabilityType = "WIRELESS_ACCESSORY_CONFIGURATION"
	APPLE_PAY                        capabilityType = "APPLE_PAY"
	DATA_PROTECTION                  capabilityType = "DATA_PROTECTION"
	SIRIKIT                          capabilityType = "SIRIKIT"
	NETWORK_EXTENSIONS               capabilityType = "NETWORK_EXTENSIONS"
	MULTIPATH                        capabilityType = "MULTIPATH"
	HOT_SPOT                         capabilityType = "HOT_SPOT"
	NFC_TAG_READING                  capabilityType = "NFC_TAG_READING"
	CLASSKIT                         capabilityType = "CLASSKIT"
	AUTOFILL_CREDENTIAL_PROVIDER     capabilityType = "AUTOFILL_CREDENTIAL_PROVIDER"
	ACCESS_WIFI_INFORMATION          capabilityType = "ACCESS_WIFI_INFORMATION"
	NETWORK_CUSTOM_PROTOCOL          capabilityType = "NETWORK_CUSTOM_PROTOCOL"
	COREMEDIA_HLS_LOW_LATENCY        capabilityType = "COREMEDIA_HLS_LOW_LATENCY"
	SYSTEM_EXTENSION_INSTALL         capabilityType = "SYSTEM_EXTENSION_INSTALL"
	USER_MANAGEMENT                  capabilityType = "USER_MANAGEMENT"
	APPLE_ID_AUTH                    capabilityType = "APPLE_ID_AUTH"
)

type capabilityKey string

const (
	ICLOUD_VERSION                   capabilityKey = "ICLOUD_VERSION"
	DATA_PROTECTION_PERMISSION_LEVEL capabilityKey = "DATA_PROTECTION_PERMISSION_LEVEL"
	APPLE_ID_AUTH_APP_CONSENT        capabilityKey = "APPLE_ID_AUTH_APP_CONSENT"
)

type capabilityOptionKey string

const (
	XCODE_5                         capabilityOptionKey = "XCODE_5"
	XCODE_6                         capabilityOptionKey = "XCODE_6"
	COMPLETE_PROTECTION             capabilityOptionKey = "COMPLETE_PROTECTION"
	PROTECTED_UNLESS_OPEN           capabilityOptionKey = "PROTECTED_UNLESS_OPEN"
	PROTECTED_UNTIL_FIRST_USER_AUTH capabilityOptionKey = "PROTECTED_UNTIL_FIRST_USER_AUTH"
	PRIMARY_APP_CONSENT             capabilityOptionKey = "PRIMARY_APP_CONSENT"
)

type CapabilityOption struct {
	Description      string              `json:"description"`
	Enabled          bool                `json:"enabled"`
	Default          bool                `json:"enabledByDefault"`
	Key              capabilityOptionKey `json:"key"`
	Name             string              `json:"name"`
	SupportsWildcard bool                `json:"supportsWildcard"`
}

type CapabilitySetting struct {
	AllowedInstances string             `json:"allowedInstances"` // ENTRY, SINGLE, MULTIPLE
	Description      string             `json:"description"`
	Enabled          bool               `json:"enabledByDefault"`
	Key              capabilityKey      `json:"key"`
	Name             string             `json:"name"`
	Options          []CapabilityOption `json:"options"`
	Visible          bool               `json:"visible"`
	MinInstances     int                `json:"minInstances"`
}

type BundleIdCapability struct {
	ID         string `json:"id"`
	Attributes struct {
		CapabilityType capabilityType      `json:"capabilityType"`
		Settings       []CapabilitySetting `json:"settings"`
	} `json:"attributes"`
	Links Links  `json:"links"`
	Type  string `json:"type"` // bundleIdCapabilities
}

type BundleIdCapabilitiesResponse struct {
	Data  []BundleIdCapability `json:"data"`
	Links Links                `json:"links"`
	Meta  Meta                 `json:"meta"`
}

type BundleID struct {
	ID         string `json:"id"`
	Type       string `json:"type"` // bundleIds
	Attributes struct {
		ID       string           `json:"identifier"`
		Name     string           `json:"name"`
		Platform bundleIdPlatform `json:"platform"`
		SeedID   string           `json:"seedId"`
	} `json:"attributes"`
	Relationships struct {
		Capabilities BundleIdCapabilitiesResponse `json:"bundleIdCapabilities"`
		Profiles     struct {
			Data []struct {
				ID   string `json:"id"`
				Type string `json:"type"` // profiles
			} `json:"data"`
			Meta  Meta  `json:"meta"`
			Links Links `json:"links"`
		} `json:"profiles"`
		App struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"` // apps
			} `json:"data"`
			Links Links `json:"links"`
		} `json:"app"`
	} `json:"relationships"`
	Links Links `json:"links"`
}

type BundleIdResponse struct {
	Data     BundleID `json:"data"`
	Links    Links    `json:"links"`
	Included any      `json:"included,omitempty"`
}

type BundleIdsResponse struct {
	Data     []BundleID `json:"data"`
	Links    Links      `json:"links"`
	Meta     Meta       `json:"meta"`
	Included any        `json:"included,omitempty"`
}

type BundleIdCreateRequest struct {
	Data struct {
		Type       string `json:"type"` // bundleIds
		Attributes struct {
			ID       string           `json:"identifier"`
			Name     string           `json:"name"`
			Platform bundleIdPlatform `json:"platform"`
			SeedID   string           `json:"seedId"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetBundleIDs returns a list bundle IDs that are registered to your team.
func (as *AppStore) GetBundleIDs() ([]BundleID, error) {
	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", bundleIDsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+as.token)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
	}

	var bundles BundleIdsResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundles); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return bundles.Data, nil
}

// GetBundleID returns information about a specific bundle ID.
func (as *AppStore) GetBundleID(id string) (*BundleID, error) {
	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", bundleIDsURL+"/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+as.token)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
	}

	var bundle BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bundle.Data, nil
}

// GetBundleIDApp returns the app information for a specific bundle ID.
func (as *AppStore) GetBundleIDApp(id string) (*AppResponse, error) {

	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", bundleIDsURL+"/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+as.token)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
	}

	var app AppResponse
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &app, nil
}

// GetBundleIDProfiles returns a list of all provisioning profiles for a specific bundle ID.
func (as *AppStore) GetBundleIDProfiles(id string) (*ProfileResponse, error) {
	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", bundleIDsURL+"/"+id+"/profiles", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+as.token)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
	}

	var profile ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &profile, nil
}

// GetBundleIDCapabilities returns a list of all capabilities for a specific bundle ID.
func (as *AppStore) GetBundleIDCapabilities(id string) (*BundleIdCapabilitiesResponse, error) {
	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", bundleIDsURL+"/"+id+"/bundleIdCapabilities", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+as.token)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
	}

	var caps BundleIdCapabilitiesResponse
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &caps, nil
}

// RegisterBundleID registers a new bundle ID for app development.
func (as *AppStore) RegisterBundleID(name, id string) (*BundleIdResponse, error) {
	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	var bundleIDCreateRequest BundleIdCreateRequest
	bundleIDCreateRequest.Data.Type = "bundleIds"
	bundleIDCreateRequest.Data.Attributes.Name = name
	bundleIDCreateRequest.Data.Attributes.ID = id
	bundleIDCreateRequest.Data.Attributes.Platform = IOS

	jsonStr, err := json.Marshal(&bundleIDCreateRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", bundleIDsURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+as.token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("%s", resp.Body)
	}

	var bidResp BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bidResp); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bidResp, nil
}

// DeleteBundleID deletes a bundle ID that is used for app development.
func (as *AppStore) DeleteBundleID(id string) (*BundleIdResponse, error) {
	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("DELETE", bundleIDsURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+as.token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(as.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: as.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		return nil, fmt.Errorf("%s", resp.Body)
	}

	var bidResp BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bidResp); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bidResp, nil
}
