package download

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"

	"github.com/hashicorp/go-version"
)

type asset struct {
	ProductVersion   string   `json:"ProductVersion,omitempty"`
	PostingDate      string   `json:"PostingDate,omitempty"`
	ExpirationDate   string   `json:"ExpirationDate,omitempty"`
	SupportedDevices []string `json:"SupportedDevices,omitempty"`
}

type AssetSets struct {
	PublicAssetSets map[string][]asset `json:"PublicAssetSets,omitempty"`
	AssetSets       map[string][]asset `json:"AssetSets,omitempty"`
}

// Latest returns the newest released version
func (a *AssetSets) Latest(typ string) string {
	var versionsRaw []string

	for _, asset := range a.PublicAssetSets[typ] {
		versionsRaw = append(versionsRaw, asset.ProductVersion)
	}

	versions := make([]*version.Version, len(versionsRaw))

	for i, raw := range versionsRaw {
		v, err := version.NewVersion(raw)
		if err != nil {
			return "failed to get latest version"
		}

		versions[i] = v
	}

	sort.Sort(version.Collection(versions))

	return versions[len(versions)-1].String()
}

// GetAssetSets queries and returns the asset sets
func GetAssetSets() (*AssetSets, error) {
	assets := AssetSets{}

	// &http.Client{
	// 	Jar: jar,
	// 	Transport: &http.Transport{
	// 		Proxy:           GetProxy(config.Proxy),
	// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
	// 	},
	// }

	res, err := http.Get("https://gdmf.apple.com/v2/pmv")
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status: %s", res.Status)
	}

	body, err := ioutil.ReadAll(res.Body)
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
