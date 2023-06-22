package download

import (
	"encoding/json"
	"io"
	"net/http"
)

// shout out to dhinakg for the KDK manifest ❤️
const kdkURL = "https://raw.githubusercontent.com/dortania/KdkSupportPkg/gh-pages/manifest.json"

// KDK is a Kernel Development Kit download object
type KDK struct {
	Build     string `json:"build,omitempty"`
	Date      string `json:"date,omitempty"`
	FileSize  int    `json:"fileSize,omitempty"`
	Md5Sum    string `json:"md5sum,omitempty"`
	Name      string `json:"name,omitempty"`
	Sha256Sum string `json:"sha256sum,omitempty"`
	URL       string `json:"url,omitempty"`
	Version   string `json:"version,omitempty"`
}

// ListKDKs returns a list of KDKs
func ListKDKs() ([]KDK, error) {
	resp, err := http.Get(kdkURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var kdks []KDK
	if err := json.Unmarshal(body, &kdks); err != nil {
		return nil, err
	}

	return kdks, nil
}
