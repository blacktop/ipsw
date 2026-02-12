package appstore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
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

type allowedInstanceType string

const (
	ENTRY    allowedInstanceType = "ENTRY"
	SINGLE   allowedInstanceType = "SINGLE"
	MULTIPLE allowedInstanceType = "MULTIPLE"
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
	AllowedInstances allowedInstanceType `json:"allowedInstances"`
	Description      string              `json:"description"`
	Enabled          bool                `json:"enabledByDefault"`
	Key              capabilityKey       `json:"key"`
	Name             string              `json:"name"`
	Options          []CapabilityOption  `json:"options"`
	Visible          bool                `json:"visible"`
	MinInstances     int                 `json:"minInstances"`
}

type BundleIdCapability struct {
	ID         string `json:"id"`
	Type       string `json:"type"` // bundleIdCapabilities
	Attributes struct {
		CapabilityType capabilityType      `json:"capabilityType"`
		Settings       []CapabilitySetting `json:"settings"`
	} `json:"attributes"`
	Links ResourceLinks `json:"links"`
}

type BundleIdCapabilitiesResponse struct {
	Data  []BundleIdCapability `json:"data"`
	Links Links                `json:"links"`
	Meta  Meta                 `json:"meta"`
}

type BundleIdCapabilityResponse struct {
	Data  BundleIdCapability `json:"data"`
	Links DocumentLinks      `json:"links"`
}

type BundleIDCapabilityCreateRequest struct {
	Data struct {
		Type       string `json:"type"` // bundleIdCapabilities
		Attributes struct {
			CapabilityType capabilityType      `json:"capabilityType"`
			Settings       []CapabilitySetting `json:"settings"`
		} `json:"attributes"`
		Relationships struct {
			BundleID struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"` // bundleIds
				} `json:"data"`
			} `json:"bundleId"`
		} `json:"relationships"`
	} `json:"data"`
}

// EnableCapability enables a capability for a bundle ID.. // TODO: finish this
func (as *AppStore) EnableCapability(id, ctype string) (*BundleIdCapability, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	var bundleIDCapabilityCreateRequest BundleIDCapabilityCreateRequest
	bundleIDCapabilityCreateRequest.Data.Type = "bundleIdCapabilities"
	bundleIDCapabilityCreateRequest.Data.Relationships.BundleID.Data.ID = id
	bundleIDCapabilityCreateRequest.Data.Relationships.BundleID.Data.Type = "bundleIds"
	bundleIDCapabilityCreateRequest.Data.Attributes.CapabilityType = capabilityType(ctype)
	bundleIDCapabilityCreateRequest.Data.Attributes.Settings = []CapabilitySetting{
		{
			AllowedInstances: SINGLE,
			Description:      "Access to CloudKit containers",
			Enabled:          true,
			Key:              ICLOUD_VERSION,
			Name:             "iCloud",
			Options: []CapabilityOption{
				{
					Description:      "Access to CloudKit containers",
					Enabled:          true,
					Default:          true,
					Key:              XCODE_5,
					Name:             "CloudKit",
					SupportsWildcard: false,
				},
			},
			Visible:      true,
			MinInstances: 1,
		},
	}

	jsonStr, err := json.Marshal(&bundleIDCapabilityCreateRequest)
	if err != nil {
		return nil, err
	}
	// os.WriteFile("req.json", jsonStr, 0644)
	req, err := http.NewRequest("POST", bundleIDCapabilitiesURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+as.token)
	req.Header.Set("Content-Type", "application/json")
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
		var eresp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&eresp); err != nil {
			return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
		}
		var errOut strings.Builder
		for idx, e := range eresp.Errors {
			errOut.WriteString(fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail))
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut.String())
	}

	var bcap BundleIdCapabilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&bcap); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bcap.Data, nil
}
