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

type DeviceCreateRequest struct {
	Data struct {
		Type       string `json:"type"` // devices
		Attributes struct {
			Name        string           `json:"name"`
			DeviceClass string           `json:"deviceClass"`
			Model       string           `json:"model"`
			Udid        string           `json:"udid"`
			Platform    bundleIdPlatform `json:"platform"`
		} `json:"attributes"`
	} `json:"data"`
}

// GetDevices returns a list devices registered to your team.
func (as *AppStore) GetDevices() ([]Device, error) {

	if err := as.createToken(defaultJWTLife); err != nil {
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
		var errOut strings.Builder
		for idx, e := range eresp.Errors {
			errOut.WriteString(fmt.Sprintf("%s%s: %s (%s)\n", strings.Repeat("\t", idx), e.Code, e.Title, e.Detail))
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, errOut.String())
	}

	var devicesResponseList DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&devicesResponseList); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return devicesResponseList.Data, nil
}

// RegisterDevice registers a new device for app development.
func (as *AppStore) RegisterDevice(name, platform, udid string) (*Device, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	var deviceCreateRequest DeviceCreateRequest
	deviceCreateRequest.Data.Type = "devices"
	deviceCreateRequest.Data.Attributes.Name = name
	deviceCreateRequest.Data.Attributes.DeviceClass = "IPHONE"
	deviceCreateRequest.Data.Attributes.Model = "iPhone 15 Pro"
	deviceCreateRequest.Data.Attributes.Udid = udid
	deviceCreateRequest.Data.Attributes.Platform = bundleIdPlatform(platform)

	jsonStr, err := json.Marshal(&deviceCreateRequest)
	if err != nil {
		return nil, err
	}
	// os.WriteFile("req.json", jsonStr, 0644)
	req, err := http.NewRequest("POST", devicesURL, bytes.NewBuffer(jsonStr))
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

	var dev DeviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &dev.Data, nil
}

type DeviceUpdateRequest struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"` // devices
		Attributes struct {
			Name   string `json:"name"`
			Status string `json:"status"` // ENABLED, DISABLED
		} `json:"attributes"`
	} `json:"data"`
}

// ModifyDevice updates the name or status of a specific device.
func (as *AppStore) ModifyDevice(id, name, status string) (*Device, error) {
	if err := as.createToken(defaultJWTLife); err != nil {
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	var deviceUpdateRequest DeviceUpdateRequest
	deviceUpdateRequest.Data.ID = id
	deviceUpdateRequest.Data.Type = "devices"
	deviceUpdateRequest.Data.Attributes.Name = name
	deviceUpdateRequest.Data.Attributes.Status = status

	jsonStr, err := json.Marshal(&deviceUpdateRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PATCH", devicesURL+"/"+id, bytes.NewBuffer(jsonStr))
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

	var dev DeviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return nil, fmt.Errorf("failed to JSON decode http response: %v", err)
	}

	return &dev.Data, nil
}
