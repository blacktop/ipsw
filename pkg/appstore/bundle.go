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

type bundleIdPlatform string

const (
	IOS    bundleIdPlatform = "IOS"
	MAC_OS bundleIdPlatform = "MAC_OS"
)

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
	if err := as.createToken(defaultJWTLife); err != nil {
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

	var bundles BundleIdsResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundles); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return bundles.Data, nil
}

// GetBundleID returns information about a specific bundle ID.
func (as *AppStore) GetBundleID(id string) (*BundleID, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
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

	var bundle BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bundle.Data, nil
}

// GetBundleIDApp returns the app information for a specific bundle ID.
func (as *AppStore) GetBundleIDApp(id string) (*AppResponse, error) {

	if err := as.createToken(defaultJWTLife); err != nil {
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

	var app AppResponse
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &app, nil
}

// GetBundleIDProfiles returns a list of all provisioning profiles for a specific bundle ID.
func (as *AppStore) GetBundleIDProfiles(id string) (*ProfileResponse, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
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

	var profile ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &profile, nil
}

// GetBundleIDCapabilities returns a list of all capabilities for a specific bundle ID.
func (as *AppStore) GetBundleIDCapabilities(id string) (*BundleIdCapabilitiesResponse, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
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

	var caps BundleIdCapabilitiesResponse
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &caps, nil
}

// RegisterBundleID registers a new bundle ID for app development.
func (as *AppStore) RegisterBundleID(name, id string) (*BundleIdResponse, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
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

	var bidResp BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bidResp); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bidResp, nil
}

// DeleteBundleID deletes a bundle ID that is used for app development.
func (as *AppStore) DeleteBundleID(id string) (*BundleIdResponse, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
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

	var bidResp BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bidResp); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bidResp, nil
}
