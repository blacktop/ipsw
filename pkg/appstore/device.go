package appstore

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
)

type Device struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		AddedDate   Date   `json:"addedDate"`
		Name        string `json:"name"`
		DeviceClass string `json:"deviceClass"`
		Model       string `json:"model"`
		Udid        string `json:"udid"`
		Platform    string `json:"platform"`
		Status      string `json:"status"`
	} `json:"attributes"`
	Links Links `json:"links"`
}

type DeviceResponse struct {
	Data  Device `json:"data"`
	Links Links  `json:"links"`
}

type DevicesResponse struct {
	Data  []Device `json:"data"`
	Links Links    `json:"links"`
	Meta  Meta     `json:"meta"`
}

// GetDevices returns a list devices registered to your team.
func (as *AppStore) GetDevices() ([]Device, error) {

	if err := as.createToken(); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	req, err := http.NewRequest("GET", devicesURL, nil)
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

	var devicesResponseList DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&devicesResponseList); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return devicesResponseList.Data, nil
}
