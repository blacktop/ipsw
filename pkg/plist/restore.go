package plist

import (
	"bytes"
	"fmt"

	"github.com/blacktop/go-plist"
)

// Restore is the Restore.plist object found in IPSWs/OTAs
type Restore struct {
	DeviceMap                     []restoreDeviceMap `plist:"DeviceMap,omitempty"`
	ProductBuildVersion           string             `plist:"ProductBuildVersion,omitempty"`
	ProductVersion                string             `plist:"ProductVersion,omitempty"`
	SupportedProductTypeIDs       map[string][]int   `plist:"SupportedProductTypeIDs,omitempty"`
	SupportedProductTypes         []string           `plist:"SupportedProductTypes,omitempty"`
	SystemRestoreImageFileSystems map[string]string  `plist:"SystemRestoreImageFileSystems,omitempty"`
}

type restoreDeviceMap struct {
	BDID        int
	BoardConfig string
	CPID        int
	Platform    string
	SCEP        int
	SDOM        int
}

// ParseRestore parses the Restore.plist
func ParseRestore(data []byte) (*Restore, error) {
	r := &Restore{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(r); err != nil {
		return nil, fmt.Errorf("failed to parse Restore.plist: %w", err)
	}
	return r, nil
}
