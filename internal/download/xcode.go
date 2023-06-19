package download

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"time"

	"github.com/blacktop/go-plist"
)

const (
	dvtURL     = "https://devimages-cdn.apple.com/downloads/xcode/simulators/index2.dvtdownloadableindex"
	XcodeDlURL = "https://storage.googleapis.com/xcodes-cache"
)

type Downloadable struct {
	Authentication    string `plist:"authentication,omitempty"`
	Category          string `plist:"category,omitempty"`
	ContentType       string `plist:"contentType,omitempty"`
	DictionaryVersion int    `plist:"dictionaryVersion,omitempty"`
	FileSize          int64  `plist:"fileSize,omitempty"`
	HostRequirements  struct {
		ExcludedHostArchitectures []string `plist:"excludedHostArchitectures,omitempty"`
		MaxHostVersion            string   `plist:"maxHostVersion,omitempty"`
		MinHostVersion            string   `plist:"minHostVersion,omitempty"`
		MinXcodeVersion           string   `plist:"minXcodeVersion,omitempty"`
	} `plist:"hostRequirements,omitempty"`
	Identifier       string `plist:"identifier,omitempty"`
	Name             string `plist:"name,omitempty"`
	Platform         string `plist:"platform,omitempty"`
	SimulatorVersion struct {
		BuildUpdate string `plist:"buildUpdate,omitempty"`
		Version     string `plist:"version,omitempty"`
	} `plist:"simulatorVersion,omitempty"`
	Source  string `plist:"source,omitempty"`
	Version string `plist:"version,omitempty"`
}

// DVTDownloadable is the struct for the dvtdownloadableindex plist
type DVTDownloadable struct {
	Downloadables          []Downloadable `plist:"downloadables,omitempty"`
	SdkToSimulatorMappings []struct {
		SdkBuildUpdate       string `plist:"sdkBuildUpdate,omitempty"`
		SimulatorBuildUpdate string `plist:"simulatorBuildUpdate,omitempty"`
		SdkIdentifier        string `plist:"sdkIdentifier,omitempty"`
	} `plist:"sdkToSimulatorMappings,omitempty"`
	SdkToSeedMappings []struct {
		BuildUpdate string `plist:"buildUpdate,omitempty"`
		Platform    string `plist:"platform,omitempty"`
		SeedNumber  int    `plist:"seedNumber,omitempty"`
	} `plist:"sdkToSeedMappings,omitempty"`
	RefreshInterval int    `plist:"refreshInterval,omitempty"`
	Version         string `plist:"version,omitempty"`
}

// GetDVTDownloadableIndex returns the DVTDownloadableIndex plist
func GetDVTDownloadableIndex() (*DVTDownloadable, error) {

	resp, err := http.Get(dvtURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dvt DVTDownloadable
	if err := plist.NewDecoder(bytes.NewReader(body)).Decode(&dvt); err != nil {
		return nil, err
	}

	return &dvt, nil
}

type Contents struct {
	Key            string
	Generation     int64
	MetaGeneration int
	Size           int64
	ETag           string
	LastModified   time.Time
}

// ListObjectsOutput presents output for ListObjects.
type ListBucketResult struct {
	Name           string
	Contents       []*Contents
	IsTruncated    bool
	Prefix         string
	Marker         string
	MaxKeys        string
	NextMarker     string
	CommonPrefixes []string
}

func ListXCodes() (*ListBucketResult, error) {
	resp, err := http.Get(XcodeDlURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var out ListBucketResult
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, err
	}

	return &out, nil
}
