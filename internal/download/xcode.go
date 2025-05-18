package download

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
)

const (
	dvtURL           = "https://devimages-cdn.apple.com/downloads/xcode/simulators/index2.dvtdownloadableindex"
	XcodeDlURL       = "https://storage.googleapis.com/xcodes-cache"
	xcodeReleasesAPI = "https://xcodereleases.com/data.json"
)

var platforms = map[string]string{
	"macos":    "com.apple.platform.macosx",
	"ios":      "com.apple.platform.iphoneos",
	"tvos":     "com.apple.platform.appletvos",
	"watchos":  "com.apple.platform.watchos",
	"visionos": "com.apple.platform.xros",
}

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

	utils.Reverse(dvt.Downloadables)

	return &dvt, nil
}

func (d *DVTDownloadable) LookupBuild(version, platform string) (string, error) {
	platform, ok := platforms[platform]
	if !ok {
		return "", fmt.Errorf("platform not supported: %s", platform)
	}
	for _, dl := range d.Downloadables {
		if dl.SimulatorVersion.Version == version && dl.Platform == platform {
			log.WithField("name", dl.Name).Debug("Simulator")
			return dl.SimulatorVersion.BuildUpdate, nil
		}
	}
	return "", fmt.Errorf("build not found for: %s", version)
}

type Contents struct {
	Key            string
	Generation     int64
	MetaGeneration int
	Size           int64
	ETag           string
	LastModified   time.Time
}

type contents []*Contents

func (cs contents) Len() int {
	return len(cs)
}

func (cs contents) Less(i, j int) bool {
	return cs[i].LastModified.After(cs[j].LastModified)
}

func (cs contents) Swap(i, j int) {
	cs[i], cs[j] = cs[j], cs[i]
}

// ListObjectsOutput presents output for ListObjects.
type ListBucketResult struct {
	Name           string
	Contents       contents
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

	sort.Sort(out.Contents)

	return &out, nil
}

type XCodeRelease struct {
	Checksums struct {
		Sha1 string `json:"sha1"`
	} `json:"checksums"`
	Compilers struct {
		Clang []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"clang"`
		Gcc []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"gcc"`
		Llvm []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"llvm"`
		LlvmGcc []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"llvm_gcc"`
		Swift []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"swift"`
	} `json:"compilers"`
	Date struct {
		Day   int64 `json:"day"`
		Month int64 `json:"month"`
		Year  int64 `json:"year"`
	} `json:"date"`
	Links struct {
		Download struct {
			URL string `json:"url"`
		} `json:"download"`
		Notes struct {
			URL string `json:"url"`
		} `json:"notes"`
	} `json:"links"`
	Name     string `json:"name"`
	Requires string `json:"requires"`
	Sdks     struct {
		IOS []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"iOS"`
		MacOS []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"macOS"`
		TvOS []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"tvOS"`
		VisionOS []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"visionOS"`
		WatchOS []struct {
			Build   string `json:"build"`
			Number  string `json:"number"`
			Release struct {
				Release bool `json:"release"`
			} `json:"release"`
		} `json:"watchOS"`
	} `json:"sdks"`
	Version struct {
		Build   string `json:"build"`
		Number  string `json:"number"`
		Release struct {
			Beta    int64 `json:"beta"`
			Dp      int64 `json:"dp"`
			Gm      bool  `json:"gm"`
			GmSeed  int64 `json:"gmSeed"`
			Rc      int64 `json:"rc"`
			Release bool  `json:"release"`
		} `json:"release"`
	} `json:"version"`
}

// QueryXcodeReleasesAPI queries the xcodereleases.com API for the Xcode Name
func QueryXcodeReleasesAPI(name string) (string, error) {
	name = strings.Replace(name, "-", "_", -1)

	resp, err := http.Get(xcodeReleasesAPI)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var releases []XCodeRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return "", err
	}

	for _, r := range releases {
		if path.Base(r.Links.Download.URL) == name {
			return r.Checksums.Sha1, nil
		}
	}

	return "", fmt.Errorf("could not find xcode release: %s", name)
}
