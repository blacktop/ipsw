package appstore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/download"
)

type ProfileType string

const (
	IOS_APP_DEVELOPMENT          ProfileType = "IOS_APP_DEVELOPMENT"
	IOS_APP_STORE                ProfileType = "IOS_APP_STORE"
	IOS_APP_ADHOC                ProfileType = "IOS_APP_ADHOC"
	IOS_APP_INHOUSE              ProfileType = "IOS_APP_INHOUSE"
	MAC_APP_DEVELOPMENT          ProfileType = "MAC_APP_DEVELOPMENT"
	MAC_APP_STORE                ProfileType = "MAC_APP_STORE"
	MAC_APP_DIRECT               ProfileType = "MAC_APP_DIRECT"
	TVOS_APP_DEVELOPMENT         ProfileType = "TVOS_APP_DEVELOPMENT"
	TVOS_APP_STORE               ProfileType = "TVOS_APP_STORE"
	TVOS_APP_ADHOC               ProfileType = "TVOS_APP_ADHOC"
	TVOS_APP_INHOUSE             ProfileType = "TVOS_APP_INHOUSE"
	MAC_CATALYST_APP_DEVELOPMENT ProfileType = "MAC_CATALYST_APP_DEVELOPMENT"
	MAC_CATALYST_APP_STORE       ProfileType = "MAC_CATALYST_APP_STORE"
	MAC_CATALYST_APP_DIRECT      ProfileType = "MAC_CATALYST_APP_DIRECT"
)

var ProfileTypes = []string{
	string(IOS_APP_DEVELOPMENT),
	string(IOS_APP_STORE),
	string(IOS_APP_ADHOC),
	string(IOS_APP_INHOUSE),
	string(MAC_APP_DEVELOPMENT),
	string(MAC_APP_STORE),
	string(MAC_APP_DIRECT),
	string(TVOS_APP_DEVELOPMENT),
	string(TVOS_APP_STORE),
	string(TVOS_APP_ADHOC),
	string(TVOS_APP_INHOUSE),
	string(MAC_CATALYST_APP_DEVELOPMENT),
	string(MAC_CATALYST_APP_STORE),
	string(MAC_CATALYST_APP_DIRECT),
}

type ProfileState string

const (
	PS_ACTIVE  ProfileState = "ACTIVE"
	PS_INVALID ProfileState = "INVALID"
)

type Profile struct {
	ID         string      `json:"id"`
	Type       ProfileType `json:"type"` // profiles
	Attributes struct {
		Name           string           `json:"name"`
		CreatedDate    Date             `json:"createdDate"`
		ExpirationDate Date             `json:"expirationDate"`
		ProfileContent []byte           `json:"profileContent"`
		ProfileState   ProfileState     `json:"profileState"`
		ProfileType    ProfileType      `json:"profileType"`
		UUID           string           `json:"uuid"`
		Platform       BundleIdPlatform `json:"platform"`
		OfflineProfile bool             `json:"isOfflineProfile"`
	} `json:"attributes"`
	Relationships struct {
		BundleID struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"bundleId"`
		Certificates struct {
			Meta struct {
				Paging struct {
					Total int   `json:"total"`
					Limit int64 `json:"limit"`
				} `json:"paging"`
			} `json:"meta"`
			Data []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"certificates"`
		Devices struct {
			Meta struct {
				Paging struct {
					Total int   `json:"total"`
					Limit int64 `json:"limit"`
				} `json:"paging"`
			} `json:"meta"`
			Data []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"devices"`
	} `json:"relationships"`
	Links Links `json:"links"`
}

func (p Profile) IsInvalid() bool {
	return p.Attributes.ProfileState == "INVALID"
}
func (p Profile) IsExpired() bool {
	return time.Time(p.Attributes.ExpirationDate).Before(time.Now())
}

type Data struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

type ProfileCreateRequest struct {
	Data struct {
		Type       string `json:"type"` // profiles
		Attributes struct {
			Name           string      `json:"name"`
			ProfileType    ProfileType `json:"profileType"`
			TemplateName   string      `json:"templateName,omitempty"`
			OfflineProfile bool        `json:"isOfflineProfile,omitempty"`
		} `json:"attributes"`
		Relationships struct {
			BundleID struct {
				Data Data `json:"data"`
			} `json:"bundleId"`
			Certificates struct {
				Data []Data `json:"data"`
			} `json:"certificates"`
			Devices struct {
				Data []Data `json:"data"`
			} `json:"devices"`
		} `json:"relationships"`
	} `json:"data"`
}

type ProfileResponse struct {
	Data  Profile       `json:"data"`
	Links DocumentLinks `json:"links"`
}
type ProfilesResponse struct {
	Data  []Profile `json:"data"`
	Links Links     `json:"links"`
}

// GetProfiles returns a list provisioning profiles and download their data.
func (as *AppStore) GetProfiles() ([]Profile, error) {

	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", profilesURL, nil)
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
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var profiles ProfilesResponse
	if err := json.NewDecoder(resp.Body).Decode(&profiles); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return profiles.Data, nil
}

// GetProfile returns a provisioning profile and download their data.
func (as *AppStore) GetProfile(id string) (*Profile, error) {

	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", profilesURL+"/"+id, nil)
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
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var profile ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &profile.Data, nil
}

// GetProfileBundleID returns the bundle ID information for a specific provisioning profile.
func (as *AppStore) GetProfileBundleID(id string) (*BundleID, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", profilesURL+fmt.Sprintf("/%s/bundleId", id), nil)
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
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var bundle BundleIdResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &bundle.Data, nil
}

// GetProfileDevices returns a list of all devices for a specific provisioning profile
func (as *AppStore) GetProfileDevices(id string) ([]Device, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", profilesURL+fmt.Sprintf("/%s/devices", id), nil)
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
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var devices DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return devices.Data, nil
}

// GetProfileCerts returns a list of all certificates and their data for a specific provisioning profile.
func (as *AppStore) GetProfileCerts(id string) ([]Certificate, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", profilesURL+fmt.Sprintf("/%s/certificates", id), nil)
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
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var certs CertificatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return certs.Data, nil
}

// CreateProfile creates a new profile
func (as *AppStore) CreateProfile(name string, ptype string, bundleID string, cerIDs, devicesIDs []string, offline bool) (*ProfileResponse, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	var profileCreateRequest ProfileCreateRequest
	profileCreateRequest.Data.Type = "profiles"
	profileCreateRequest.Data.Attributes.Name = name
	profileCreateRequest.Data.Attributes.ProfileType = ProfileType(ptype)
	profileCreateRequest.Data.Attributes.OfflineProfile = offline
	profileCreateRequest.Data.Relationships.BundleID.Data.Type = "bundleIds"
	profileCreateRequest.Data.Relationships.BundleID.Data.ID = bundleID
	for _, cerID := range cerIDs {
		profileCreateRequest.Data.Relationships.Certificates.Data = append(profileCreateRequest.Data.Relationships.Certificates.Data, Data{
			ID:   cerID,
			Type: "certificates",
		})
	}
	for _, devicesID := range devicesIDs {
		profileCreateRequest.Data.Relationships.Devices.Data = append(profileCreateRequest.Data.Relationships.Devices.Data, Data{
			ID:   devicesID,
			Type: "devices",
		})
	}

	jsonStr, err := json.Marshal(&profileCreateRequest)
	if err != nil {
		return nil, err
	}
	// os.WriteFile("req.json", jsonStr, 0644)
	req, err := http.NewRequest("POST", profilesURL, bytes.NewBuffer(jsonStr))
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
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	var profileResponse ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profileResponse); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &profileResponse, nil
}

// DeleteProfile deletes a provisioning profile that is used for app development or distribution.
func (as *AppStore) DeleteProfile(id string) error {
	if err := as.createToken(defaultJWTLife); err != nil {
		return fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("DELETE", profilesURL+"/"+id, nil)
	if err != nil {
		return err
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
		return fmt.Errorf("failed to send http request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		var eresp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&eresp); err != nil {
			return fmt.Errorf("failed to JSON decode http response: %v", err)
		}
		var errOut string
		for idx, e := range eresp.Errors {
			errOut += fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail)
		}
		return fmt.Errorf("%s: %s", resp.Status, errOut)
	}

	return nil
}
