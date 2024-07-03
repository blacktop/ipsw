package plist

import (
	"bytes"
	"fmt"

	"github.com/blacktop/go-plist"
)

// SystemVersion is the SystemVersion.plist struct
type SystemVersion struct {
	BuildID             string `json:"build_id,omitempty"`
	ProductBuildVersion string `json:"product_build_version,omitempty"`
	ProductCopyright    string `json:"product_copyright,omitempty"`
	ProductName         string `json:"product_name,omitempty"`
	ProductVersion      string `json:"product_version,omitempty"`
	ReleaseType         string `json:"release_type,omitempty"`
	SystemImageID       string `json:"system_image_id,omitempty"`
}

func (sv *SystemVersion) String() string {
	var out string
	out += "[SystemVersion]\n"
	out += "===============\n"
	if len(sv.ProductName) > 0 {
		out += fmt.Sprintf("  ProductName:         %s\n", sv.ProductName)
	}
	if len(sv.ProductVersion) > 0 {
		out += fmt.Sprintf("  ProductVersion:      %s\n", sv.ProductVersion)
	}
	if len(sv.ProductBuildVersion) > 0 {
		out += fmt.Sprintf("  ProductBuildVersion: %s\n", sv.ProductBuildVersion)
	}
	if len(sv.BuildID) > 0 {
		out += fmt.Sprintf("  BuildID:             %s\n", sv.BuildID)
	}
	if len(sv.ReleaseType) > 0 {
		out += fmt.Sprintf("  ReleaseType:         %s\n", sv.ReleaseType)
	}
	if len(sv.SystemImageID) > 0 {
		out += fmt.Sprintf("  SystemImageID:       %s\n", sv.SystemImageID)
	}
	if len(sv.ProductCopyright) > 0 {
		out += fmt.Sprintf("  ProductCopyright:    %s\n", sv.ProductCopyright)
	}
	return out
}

// ParseSystemVersion parses the SystemVersion.plist
func ParseSystemVersion(data []byte) (*SystemVersion, error) {
	sv := &SystemVersion{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(sv); err != nil {
		return nil, fmt.Errorf("failed to parse SystemVersion.plist: %w", err)
	}
	return sv, nil
}
