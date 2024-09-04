package download

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"

	"github.com/blacktop/ipsw/internal/utils"
)

const (
	ossURL         = "https://opensource.apple.com/plist/macos-%s.plist"
	ossDownloadURL = "https://opensource.apple.com/tarballs/%s/%s-%s.tar.gz"
)

type project struct {
	Version string `plist:"version,omitempty" json:"version,omitempty"`
	URL     string `plist:"url,omitempty" json:"url,omitempty"`
}

// Oss opensource.apple.com plist object
type Oss struct {
	Build    string             `plist:"build,omitempty" json:"build,omitempty"`
	Inherits string             `plist:"inherits,omitempty" json:"inherits,omitempty"`
	Projects map[string]project `plist:"projects,omitempty" json:"projects,omitempty"`
}

// Download downloads a file from product URL
func (p *project) Download() error {

	// proxy, insecure are null because we override the client below
	downloader := NewDownload("", false, false, false, false, false, false)

	destName := getDestName(p.URL, false)
	if _, err := os.Stat(destName); os.IsNotExist(err) {

		log.WithFields(log.Fields{
			"file": destName,
		}).Info("Downloading")

		// download file
		downloader.URL = p.URL
		downloader.DestName = destName

		err = downloader.Do()
		if err != nil {
			return fmt.Errorf("failed to download file: %v", err)
		}

	} else {
		log.Warnf("file already exists: %s", destName)
	}

	return nil
}

// NewOSS downloads and parses the opensource.apple.com plist
func NewOSS(macOSVersion, proxy string, insecure bool) (*Oss, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf(ossURL, macOSVersion), nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http GET request: %v", err)
	}
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to connect to URL: %s", resp.Status)
	}

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSS plist: %v", err)
	}

	var o Oss

	if err := plist.NewDecoder(bytes.NewReader(document)).Decode(&o); err != nil {
		return nil, fmt.Errorf("failed to decode OSS plist response: %v", err)
	}

	for key, val := range o.Projects {
		o.Projects[key] = project{
			Version: val.Version,
			URL:     fmt.Sprintf(ossDownloadURL, key, key, val.Version),
		}
	}

	return &o, nil
}
