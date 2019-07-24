package api

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"howett.net/plist"
)

const iTunesVersionURL = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version/"

// Identifier object
type Identifier string

// BuildNumber object
type BuildNumber string

// Build object
type Build struct {
	Identifier     string `json:"identifier,omitempty"`
	BuildVersion   string `json:"build_version,omitempty"`
	FirmwareURL    string `json:"firmware_url,omitempty"`
	FirmwareSHA1   string `json:"firmware_sha1,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
}

// IndividualBuild object
type IndividualBuild struct {
	BuildVersion     BuildNumber
	DocumentationURL string
	FirmwareURL      string
	FirmwareSHA1     string
	ProductVersion   string
}

// BuildInformation object
type BuildInformation struct {
	Restore              *IndividualBuild
	Update               *IndividualBuild
	SameAs               string
	OfferRestoreAsUpdate bool
}

// VersionWrapper object
type VersionWrapper struct {
	MobileDeviceSoftwareVersions map[Identifier]map[BuildNumber]*BuildInformation
}

// ITunesVersionMaster object
type ITunesVersionMaster struct {
	MobileDeviceSoftwareVersionsByVersion map[string]*VersionWrapper
}

// UniqueBuilds returns a slice with Builds with unique FirmwareURLs
func UniqueBuilds(b []Build) []Build {
	unique := make(map[string]bool, len(b))
	bs := make([]Build, len(unique))
	for _, elem := range b {
		if len(elem.FirmwareURL) != 0 {
			if !unique[elem.FirmwareURL] {
				bs = append(bs, elem)
				unique[elem.FirmwareURL] = true
			}
		}
	}

	return bs
}

// GetBuilds gets all the IndividualBuilds
func (vm *ITunesVersionMaster) GetBuilds() []Build {
	var b []Build
	for _, deviceSoftwareVersions := range vm.MobileDeviceSoftwareVersionsByVersion {
		for identifier, builds := range deviceSoftwareVersions.MobileDeviceSoftwareVersions {
			for _, build := range builds {
				if build.Restore != nil {
					if strings.Contains(build.Restore.FirmwareURL, "protected://") {
						continue
					}
					build := Build{
						Identifier:     string(identifier),
						BuildVersion:   string(build.Restore.BuildVersion),
						FirmwareURL:    build.Restore.FirmwareURL,
						FirmwareSHA1:   build.Restore.FirmwareSHA1,
						ProductVersion: build.Restore.ProductVersion,
					}
					b = append(b, build)
				}
			}
		}
	}

	return b
}

// GetBuildsForVersion gets all the IndividualBuilds that match supplied version
func (vm *ITunesVersionMaster) GetBuildsForVersion(version string) []Build {
	var builds []Build
	for _, build := range vm.GetBuilds() {
		if build.ProductVersion == version {
			builds = append(builds, build)
		}
	}
	return UniqueBuilds(builds)
}

// GetBuildsForBuildID gets all the IndividualBuilds that match supplied build ID
func (vm *ITunesVersionMaster) GetBuildsForBuildID(buildID string) []Build {
	var builds []Build
	for _, build := range vm.GetBuilds() {
		if build.BuildVersion == buildID {
			builds = append(builds, build)
		}
	}
	return UniqueBuilds(builds)
}

// GetLatestBuilds gets all the latest IndividualBuilds that match supplied build ID
func (vm *ITunesVersionMaster) GetLatestBuilds() ([]Build, error) {
	var builds []Build
	var versionsRaw []string

	for _, build := range vm.GetBuilds() {
		versionsRaw = append(versionsRaw, build.ProductVersion)
	}

	versions := make([]*version.Version, len(versionsRaw))

	for i, raw := range versionsRaw {
		v, err := version.NewVersion(raw)
		if err != nil {
			return nil, err
		}

		versions[i] = v
	}

	sort.Sort(version.Collection(versions))
	newestVersion := versions[len(versions)-1]
	utils.Indent(log.Debug, 1)(fmt.Sprintf("Latest iOS release found is: %s", newestVersion.String()))

	// check canijailbreak.com
	jbs, _ := GetJailbreaks()
	if iCan, index, err := jbs.CanIBreak(newestVersion.Original()); err != nil {
		log.Error(err.Error())
	} else {
		if iCan {
			log.WithField("url", jbs.Jailbreaks[index].URL).Warnf("Yo, this shiz is jail breakable via %s B!!!!", jbs.Jailbreaks[index].Name)
		} else {
			log.Warnf("Yo, ain't no one jailbreaking this shizz NOT even %s my dude!!!!", GetRandomResearcher())
		}
	}

	for _, build := range vm.GetBuilds() {
		if strings.EqualFold(build.ProductVersion, newestVersion.Original()) {
			builds = append(builds, build)
		}
	}
	return UniqueBuilds(builds), nil
}

// GetSoftwareURLFor gets the latest ipsw download URL for a device. i.e. "iPhone11,2"
func (vm *ITunesVersionMaster) GetSoftwareURLFor(device string) (string, error) {

	for _, deviceSoftwareVersions := range vm.MobileDeviceSoftwareVersionsByVersion {
		for identifier, builds := range deviceSoftwareVersions.MobileDeviceSoftwareVersions {
			if string(identifier) == device {
				for _, build := range builds {
					if build.Restore != nil {
						if strings.Contains(build.Restore.FirmwareURL, "protected://") {
							continue
						}
						return build.Restore.FirmwareURL, nil
					}
				}
			}
		}
	}

	return "", errors.Errorf("unable to find url for device: %s", device)
}

// GetSoftwareURLs gets all the ipsw URLs
func (vm *ITunesVersionMaster) GetSoftwareURLs() ([]string, error) {
	urls := []string{}
	for _, deviceSoftwareVersions := range vm.MobileDeviceSoftwareVersionsByVersion {
		for _, builds := range deviceSoftwareVersions.MobileDeviceSoftwareVersions {
			for _, build := range builds {
				if build.Restore != nil {
					// don't return protected ones if we can avoid it
					if strings.Contains(build.Restore.FirmwareURL, "protected://") {
						continue
					}
					// if build.Restore.ProductVersion == version {
					urls = append(urls, build.Restore.FirmwareURL)
					// }
				}
			}
		}
	}
	return utils.Unique(urls), nil
}

// GetSoftwareURLsForVersion gets all the ipsw URLs for an iOS version
func (vm *ITunesVersionMaster) GetSoftwareURLsForVersion(version string) ([]string, error) {
	var urls []string
	for _, build := range vm.GetBuilds() {
		if build.ProductVersion == version {
			urls = append(urls, build.FirmwareURL)
		}
	}
	return utils.Unique(urls), nil
}

// GetLatestSoftwareURLs gets all the latests ipsw URLs
func (vm *ITunesVersionMaster) GetLatestSoftwareURLs() ([]string, error) {
	var urls []string
	var versionsRaw []string

	for _, build := range vm.GetBuilds() {
		versionsRaw = append(versionsRaw, build.ProductVersion)
	}

	versions := make([]*version.Version, len(versionsRaw))

	for i, raw := range versionsRaw {
		v, err := version.NewVersion(raw)
		if err != nil {
			return nil, err
		}

		versions[i] = v
	}

	sort.Sort(version.Collection(versions))
	newestVersion := versions[len(versions)-1]

	for _, build := range vm.GetBuilds() {
		if build.ProductVersion == newestVersion.String() {
			urls = append(urls, build.FirmwareURL)
		}
	}

	return utils.Unique(urls), nil
}

// GetSoftwareURLsForBuildID gets all the ipsw URLs for an iOS Build ID
func (vm *ITunesVersionMaster) GetSoftwareURLsForBuildID(buildID string) ([]string, error) {
	var urls []string
	for _, build := range vm.GetBuilds() {
		if build.BuildVersion == buildID {
			urls = append(urls, build.FirmwareURL)
		}
	}
	return utils.Unique(urls), nil
}

// NewiTunesVersionMaster downloads and parses the itumes plist
func NewiTunesVersionMaster() (*ITunesVersionMaster, error) {
	resp, err := http.Get(iTunesVersionURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create http client")
	}

	document, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read plist")
	}

	vm := ITunesVersionMaster{}

	dec := plist.NewDecoder(bytes.NewReader(document))
	dec.Decode(&vm)

	return &vm, nil
}
