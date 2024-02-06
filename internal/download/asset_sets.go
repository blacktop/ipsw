package download

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/hashicorp/go-version"
)

const assetSetListURL = "https://gdmf.apple.com/v2/pmv"

type AssetSet struct {
	ProductVersion   string   `json:"ProductVersion,omitempty"`
	Build            string   `json:"Build,omitempty"`
	PostingDate      string   `json:"PostingDate,omitempty"`
	ExpirationDate   string   `json:"ExpirationDate,omitempty"`
	SupportedDevices []string `json:"SupportedDevices,omitempty"`
}

type AssetSets struct {
	PublicAssetSets map[string][]AssetSet `json:"PublicAssetSets,omitempty"`
	AssetSets       map[string][]AssetSet `json:"AssetSets,omitempty"`
}

// GetAssetSets queries and returns the asset sets
func GetAssetSets(proxy string, insecure bool) (*AssetSets, error) {
	var assets AssetSets

	req, err := http.NewRequest("GET", assetSetListURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	err = json.Unmarshal(body, &assets)
	if err != nil {
		return nil, err
	}

	return &assets, nil
}

// ForDevice returns the assets for a given device
func (a *AssetSets) ForDevice(device string) []AssetSet {
	var assets []AssetSet
	for _, as := range a.AssetSets {
		for _, asset := range as {
			if utils.StrSliceHas(asset.SupportedDevices, device) {
				assets = append(assets, asset)
			}
		}
	}
	return assets
}

// GetDevicesForVersion returns the supported devices for a given OS version
func (a *AssetSets) GetDevicesForVersion(version string, typ string) []string {
	for _, asset := range a.AssetSets[typ] {
		if asset.ProductVersion == version {
			sort.Strings(asset.SupportedDevices)
			return asset.SupportedDevices
		}
	}
	return nil
}

// GetDevicesForBuild returns the supported devices for a given build
func (a *AssetSets) GetDevicesForBuild(build string, typ string) []string {
	for _, asset := range a.AssetSets[typ] {
		if asset.Build == build {
			sort.Strings(asset.SupportedDevices)
			return asset.SupportedDevices
		}
	}
	return nil
}

// LatestVersion returns the newest released version for a given platform
func (a *AssetSets) LatestVersion(platform string) string {
	v, _ := a.latest(platform)
	return v
}

// LatestBuild returns the newest released build for a given platform
func (a *AssetSets) LatestBuild(platform string) string {
	_, b := a.latest(platform)
	return b
}

func (a *AssetSets) latest(platform string) (string, string) {
	var typ string
	var versionsRaw []string

	switch platform {
	case "accessory", "ios", "watchos", "audioos", "tvos":
		typ = "iOS"
	case "visionos":
		typ = "xrOS"
	case "recovery", "macos":
		typ = "macOS"
	}

	v2b := make(map[string]string)

	for _, asset := range a.PublicAssetSets[typ] {
		switch platform {
		case "accessory":
			fallthrough
		case "ios":
			if utils.StrSliceContains(asset.SupportedDevices, "iP") {
				v2b[asset.ProductVersion] = asset.Build
				versionsRaw = append(versionsRaw, asset.ProductVersion)
			}
		case "watchos":
			if utils.StrSliceContains(asset.SupportedDevices, "Watch") {
				v2b[asset.ProductVersion] = asset.Build
				versionsRaw = append(versionsRaw, asset.ProductVersion)
			}
		case "audioos":
			if utils.StrSliceContains(asset.SupportedDevices, "AudioAccessory") {
				v2b[asset.ProductVersion] = asset.Build
				versionsRaw = append(versionsRaw, asset.ProductVersion)
			}
		case "tvos":
			if utils.StrSliceContains(asset.SupportedDevices, "AppleTV") {
				v2b[asset.ProductVersion] = asset.Build
				versionsRaw = append(versionsRaw, asset.ProductVersion)
			}
		case "visionos":
			if utils.StrSliceContains(asset.SupportedDevices, "Reality") {
				v2b[asset.ProductVersion] = asset.Build
				versionsRaw = append(versionsRaw, asset.ProductVersion)
			}
		case "recovery":
			fallthrough
		case "macos":
			v2b[asset.ProductVersion] = asset.Build
			versionsRaw = append(versionsRaw, asset.ProductVersion)
		}
	}

	versions := make([]*version.Version, len(versionsRaw))

	for i, raw := range versionsRaw {
		v, err := version.NewVersion(raw)
		if err != nil {
			return "failed to get latest", "failed to get latest"
		}

		versions[i] = v
	}

	sort.Sort(version.Collection(versions))

	return versions[len(versions)-1].Original(), v2b[versions[len(versions)-1].Original()]
}
