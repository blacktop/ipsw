package ipsw

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/download"
)

// GetLatestIosVersion returns the latest iOS version
func GetLatestIosVersion(proxy string, insecure bool) (string, error) {
	assets, err := download.GetAssetSets(proxy, insecure)
	if err != nil {
		return "", fmt.Errorf("failed to get asset latest version: %v", err)
	}
	return assets.LatestVersion("ios"), nil
}

// GetLatestIosBuild returns the latest iOS build
func GetLatestIosBuild() (string, error) { // TODO: add proxy and insecure support
	itunes, err := download.NewMacOsXML()
	if err != nil {
		return "", fmt.Errorf("failed to parse itunes XML: %v", err)
	}
	return itunes.GetLatestBuild()
}
