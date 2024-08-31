package download

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// shout out to dhinakg for the KDK manifest ❤️
const kdkURL = "https://raw.githubusercontent.com/dortania/KdkSupportPkg/gh-pages/manifest.json"

type KDKDate time.Time

func (r *KDKDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" {
		return nil
	}
	t, err := time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		return err
	}
	*r = KDKDate(t)
	return nil
}
func (r KDKDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(r))
}
func (r KDKDate) Format(s string) string {
	t := time.Time(r)
	return t.Format(s)
}

// KDK is a Kernel Development Kit download object
type KDK struct {
	Build          string            `json:"build,omitempty"`
	Date           KDKDate           `json:"date,omitempty"`
	FileSize       int               `json:"fileSize,omitempty"`
	KernelVersions map[string]string `json:"kernel_versions"`
	Md5Sum         string            `json:"md5sum,omitempty"`
	Name           string            `json:"name,omitempty"`
	Seen           time.Time         `json:"seen,omitempty"`
	Sha256Sum      string            `json:"sha256sum,omitempty"`
	URL            string            `json:"url,omitempty"`
	Version        string            `json:"version,omitempty"`
}

type KDKs []KDK

func (ks KDKs) Len() int {
	return len(ks)
}

func (ks KDKs) Less(i, j int) bool {
	return time.Time(ks[i].Seen).After(time.Time((ks[j].Seen)))
}

func (ks KDKs) Swap(i, j int) {
	ks[i], ks[j] = ks[j], ks[i]
}

// ListKDKs returns a list of KDKs
func ListKDKs() (KDKs, error) {
	resp, err := http.Get(kdkURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var kdks KDKs
	if err := json.Unmarshal(body, &kdks); err != nil {
		return nil, err
	}

	return kdks, nil
}
