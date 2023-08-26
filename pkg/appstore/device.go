package appstore

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blacktop/ipsw/internal/download"
)

type DevicesData struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		AddedDate   string `json:"addedDate"`
		Name        string `json:"name"`
		DeviceClass string `json:"deviceClass"`
		Model       string `json:"model"`
		Udid        string `json:"udid"`
		Platform    string `json:"platform"`
		Status      string `json:"status"`
	} `json:"attributes"`
	Links Links `json:"links"`
}

type DevicesResponse struct {
	Data  DevicesData `json:"data"`
	Links Links       `json:"links"`
}

type DevicesResponseList struct {
	Data  []DevicesData `json:"data"`
	Links Links         `json:"links"`
	Meta  Meta          `json:"meta"`
}

// GetDevices returns a list devices registered to your team.
func (as *AppStore) GetDevices() ([]DevicesData, error) {

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
		return nil, fmt.Errorf("http request failed with status code: %d", resp.StatusCode)
	}

	var devicesResponseList DevicesResponseList
	if err := json.NewDecoder(resp.Body).Decode(&devicesResponseList); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return devicesResponseList.Data, nil
}
