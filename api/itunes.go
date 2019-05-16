package api

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
	"howett.net/plist"
)

const iTunesVersionURL = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version/"

// Identifier object
type Identifier string

// BuildNumber object
type BuildNumber string

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

// GetSoftwareURLsForVersion gets all the ipsw URLs for an iOS version
func (vm *ITunesVersionMaster) GetSoftwareURLsForVersion(version string) ([]string, error) {
	urls := []string{}
	for _, deviceSoftwareVersions := range vm.MobileDeviceSoftwareVersionsByVersion {
		for _, builds := range deviceSoftwareVersions.MobileDeviceSoftwareVersions {
			for _, build := range builds {
				if build.Restore != nil {
					// don't return protected ones if we can avoid it
					if strings.Contains(build.Restore.FirmwareURL, "protected://") {
						continue
					}
					if build.Restore.ProductVersion == version {
						urls = append(urls, build.Restore.FirmwareURL)
					}
				}
			}
		}
	}
	return utils.Unique(urls), nil
}

// GetSoftwareURLsForBuildID gets all the ipsw URLs for an iOS Build ID
func (vm *ITunesVersionMaster) GetSoftwareURLsForBuildID(buildID string) ([]string, error) {
	urls := []string{}
	for _, deviceSoftwareVersions := range vm.MobileDeviceSoftwareVersionsByVersion {
		for _, builds := range deviceSoftwareVersions.MobileDeviceSoftwareVersions {
			for _, build := range builds {
				if build.Restore != nil {
					// don't return protected ones if we can avoid it
					if strings.Contains(build.Restore.FirmwareURL, "protected://") {
						continue
					}
					if string(build.Restore.BuildVersion) == buildID {
						urls = append(urls, build.Restore.FirmwareURL)
					}
				}
			}
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
