package download

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
)

const (
	macOSIpswURL     = "https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml"
	iBridgeOSURL     = "https://mesu.apple.com/assets/bridgeos/com_apple_bridgeOSIPSW/com_apple_bridgeOSIPSW.xml"
	iTunesVersionURL = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version/"
)

// Identifier object
type Identifier string

// BuildNumber object
type BuildNumber string

// Build object
type Build struct {
	Identifier   string `json:"identifier,omitempty"`
	BuildID      string `json:"build_version,omitempty"`
	URL          string `json:"firmware_url,omitempty"`
	FirmwareSHA1 string `json:"firmware_sha1,omitempty"`
	Version      string `json:"product_version,omitempty"`
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
		if len(elem.URL) != 0 {
			if !unique[elem.URL] {
				bs = append(bs, elem)
				unique[elem.URL] = true
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
						Identifier:   string(identifier),
						BuildID:      string(build.Restore.BuildVersion),
						URL:          build.Restore.FirmwareURL,
						FirmwareSHA1: build.Restore.FirmwareSHA1,
						Version:      build.Restore.ProductVersion,
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
		if build.Version == version {
			builds = append(builds, build)
		}
	}
	return UniqueBuilds(builds)
}

// GetBuildsForBuildID gets all the IndividualBuilds that match supplied build ID
func (vm *ITunesVersionMaster) GetBuildsForBuildID(buildID string) []Build {
	var builds []Build
	for _, build := range vm.GetBuilds() {
		if build.BuildID == buildID {
			builds = append(builds, build)
		}
	}
	return UniqueBuilds(builds)
}

// GetLatestBuilds gets all the latest IndividualBuilds that match supplied build ID
func (vm *ITunesVersionMaster) GetLatestBuilds(device string) ([]Build, error) {
	var builds []Build
	var versionsRaw []string

	for _, build := range vm.GetBuilds() {
		if len(device) > 0 {
			if strings.EqualFold(device, build.Identifier) {
				versionsRaw = append(versionsRaw, build.Version)
			}
		} else {
			versionsRaw = append(versionsRaw, build.Version)
		}

	}

	if len(versionsRaw) == 0 {
		return nil, fmt.Errorf("no versions found for device %s", device)
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

	// // check canijailbreak.com
	// jbs, _ := GetJailbreaks()
	// if iCan, index, err := jbs.CanIBreak(newestVersion.Original()); err != nil {
	// 	log.Error(err.Error())
	// } else {
	// 	if iCan {
	// 		utils.Indent(log.WithField("url", jbs.Jailbreaks[index].URL).Warn, 2)(fmt.Sprintf("Yo, this shiz is jail breakable via %s B!!!!", jbs.Jailbreaks[index].Name))
	// 		utils.Indent(log.Warn, 3)(jbs.Jailbreaks[index].Caveats)
	// 	} else {
	// 		utils.Indent(log.Warn, 2)(fmt.Sprintf("Yo, ain't no one jailbreaking this shizz NOT even %s my dude!!!!", GetRandomResearcher()))
	// 	}
	// }

	for _, build := range vm.GetBuilds() {
		if strings.EqualFold(build.Version, newestVersion.Original()) {
			if len(device) > 0 {
				if strings.EqualFold(device, build.Identifier) {
					builds = append(builds, build)
				}
			} else {
				builds = append(builds, build)
			}
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
		if build.Version == version {
			urls = append(urls, build.URL)
		}
	}
	return utils.Unique(urls), nil
}

// GetLatestSoftwareURLs gets all the latests ipsw URLs
func (vm *ITunesVersionMaster) GetLatestSoftwareURLs() ([]string, error) {
	var urls []string
	var versionsRaw []string

	for _, build := range vm.GetBuilds() {
		versionsRaw = append(versionsRaw, build.Version)
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
		if build.Version == newestVersion.String() {
			urls = append(urls, build.URL)
		}
	}

	return utils.Unique(urls), nil
}

// GetLatestVersion gets the latest iOS version
func (vm *ITunesVersionMaster) GetLatestVersion() (string, error) {
	var versionsRaw []string

	for _, build := range vm.GetBuilds() {
		versionsRaw = append(versionsRaw, build.Version)
	}

	versions := make([]*version.Version, len(versionsRaw))

	for i, raw := range versionsRaw {
		v, err := version.NewVersion(raw)
		if err != nil {
			return "", err
		}

		versions[i] = v
	}

	sort.Sort(version.Collection(versions))
	newestVersion := versions[len(versions)-1]

	return newestVersion.Original(), nil
}

// GetLatestBuild gets the latest iOS build
func (vm *ITunesVersionMaster) GetLatestBuild() (string, error) {
	version, err := vm.GetLatestVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get latest version: %s", err)
	}
	builds := UniqueBuilds(vm.GetBuildsForVersion(version))
	sort.Slice(builds, func(i, j int) bool {
		return builds[i].BuildID > builds[j].BuildID
	})
	return builds[0].BuildID, nil
}

// GetSoftwareURLsForBuildID gets all the ipsw URLs for an iOS Build ID
func (vm *ITunesVersionMaster) GetSoftwareURLsForBuildID(buildID string) ([]string, error) {
	var urls []string
	for _, build := range vm.GetBuilds() {
		if build.BuildID == buildID {
			urls = append(urls, build.URL)
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

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read plist")
	}

	vm := ITunesVersionMaster{}

	dec := plist.NewDecoder(bytes.NewReader(document))
	dec.Decode(&vm)

	return &vm, nil
}

// NewMacOsXML downloads and parses the macOS IPSW plist
func NewMacOsXML() (*ITunesVersionMaster, error) {
	resp, err := http.Get(macOSIpswURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create http client")
	}

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read plist")
	}

	vm := ITunesVersionMaster{}

	dec := plist.NewDecoder(bytes.NewReader(document))
	dec.Decode(&vm)

	return &vm, nil
}

// NewIBridgeXML downloads and parses the iBridge IPSW plist
func NewIBridgeXML() (*ITunesVersionMaster, error) {
	resp, err := http.Get(iBridgeOSURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create http client")
	}

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read plist")
	}

	vm := ITunesVersionMaster{}

	dec := plist.NewDecoder(bytes.NewReader(document))
	dec.Decode(&vm)

	return &vm, nil
}
