package plist

import (
	"bytes"
	"fmt"

	"github.com/blacktop/go-plist"
)

// Restore is the Restore.plist object found in IPSWs/OTAs
type Restore struct {
	DeviceClass                   string             `plist:"DeviceClass,omitempty"`
	FirmwareDirectory             string             `plist:"FirmwareDirectory,omitempty"`
	KernelCachesByPlatform        map[string]any     `plist:"KernelCachesByPlatform,omitempty"`
	DeviceMap                     []restoreDeviceMap `plist:"DeviceMap,omitempty"`
	ProductBuildVersion           string             `plist:"ProductBuildVersion,omitempty"`
	ProductType                   string             `plist:"ProductType,omitempty"`
	ProductVersion                string             `plist:"ProductVersion,omitempty"`
	RamDisksByPlatform            map[string]any     `plist:"RamDisksByPlatform,omitempty"`
	RestoreKernelCaches           map[string]any     `plist:"RestoreKernelCaches,omitempty"`
	RestoreRamDisks               map[string]any     `plist:"RestoreRamDisks,omitempty"`
	SupportedProductTypeIDs       map[string][]int   `plist:"SupportedProductTypeIDs,omitempty"`
	SupportedProductTypes         []string           `plist:"SupportedProductTypes,omitempty"`
	SystemRestoreImageFileSystems map[string]string  `plist:"SystemRestoreImageFileSystems,omitempty"`
	SystemRestoreImages           map[string]string  `plist:"SystemRestoreImages,omitempty"`
}

type restoreDeviceMap struct {
	BDID        int
	BoardConfig string
	CPID        int
	Platform    string
	SCEP        int
	SDOM        int
}

func (dm *restoreDeviceMap) String() string {
	var out string
	out += fmt.Sprintf("    BDID:        %d\n", dm.BDID)
	out += fmt.Sprintf("    BoardConfig: %s\n", dm.BoardConfig)
	out += fmt.Sprintf("    CPID:        %d\n", dm.CPID)
	out += fmt.Sprintf("    Platform:    %s\n", dm.Platform)
	out += fmt.Sprintf("    SCEP:        %d\n", dm.SCEP)
	out += fmt.Sprintf("    SDOM:        %d\n", dm.SDOM)
	return out
}

func (r *Restore) String() string {
	var out string
	out += "[Restore]\n"
	out += "=========\n"
	out += fmt.Sprintf("  ProductBuildVersion:   %s\n", r.ProductBuildVersion)
	out += fmt.Sprintf("  ProductVersion:        %s\n", r.ProductVersion)
	out += fmt.Sprintf("  SupportedProductTypes: %v\n", r.SupportedProductTypes)
	if len(r.DeviceMap) > 0 {
		out += "  DeviceMap:\n"
		for _, dm := range r.DeviceMap {
			out += fmt.Sprintf("   -\n%s", dm.String())
		}
	}
	if len(r.SystemRestoreImageFileSystems) > 0 {
		out += "  SystemRestoreImageFileSystems:\n"
		for k, v := range r.SystemRestoreImageFileSystems {
			out += fmt.Sprintf("   -\n    %s: %s\n", k, v)
		}
	}
	return out
}

// ParseRestore parses the Restore.plist
func ParseRestore(data []byte) (*Restore, error) {
	r := &Restore{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(r); err != nil {
		return nil, fmt.Errorf("failed to parse Restore.plist: %w", err)
	}
	return r, nil
}
