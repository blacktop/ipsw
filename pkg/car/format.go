package car

//go:generate go tool stringer -type=renditionAttributeType,renditionLayoutType,resourceID,csiBitmapEncoding -output car_string.go

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

func (a *Asset) String() string {
	var out string
	out += "Asset\n" + "=====\n" // title
	out += "Header:\n"
	out += fmt.Sprintf(
		"  Version:             %s"+
			"  CoreUI Version:      %d\n"+
			"  Storage Version:     %d\n"+
			"  Storage Timestamp:   %s\n"+
			"  Rendition Count:     %d\n"+
			"  UUID:                %s\n"+
			"  Associated Checksum: %#x\n"+
			"  Schema Version:      %d\n"+
			"  ColorSpaceID:        %s\n"+
			"  Key Semantics:       %d\n",
		string(bytes.Trim(a.Header.MainVersionString[:], "\x00")),
		a.Header.CoreUiVersion,
		a.Header.StorageVersion,
		time.Unix(int64(a.Header.StorageTimestamp), 0).String(),
		a.Header.RenditionCount,
		a.Header.UUID.String(),
		a.Header.AssociatedChecksum,
		a.Header.SchemaVersion,
		a.Header.ColorSpaceID,
		a.Header.KeySemantics,
	)
	out += "Metadata:\n"
	out += fmt.Sprintf(
		"  Authoring Tool:      %s"+
			"  Thinning Args:       %s\n"+
			"  Deployment Platform: %s %s\n",
		string(bytes.Trim(a.Metadata.AuthoringTool[:], "\x00")),
		strings.ReplaceAll(string(bytes.Trim(a.Metadata.ThinningArguments[:], "\x00")), "<", "\n    <"),
		string(bytes.Trim(a.Metadata.DeploymentPlatform[:], "\x00")),
		string(bytes.Trim(a.Metadata.DeploymentPlatformVersion[:], "\x00")),
	)
	if len(a.KeyFormat) > 0 {
		out += "KeyFormats:\n"
		for _, k := range a.KeyFormat {
			out += fmt.Sprintf("  - %s\n", k)
		}
	}
	if len(a.AppearanceDB) > 0 {
		out += "Appearances:\n"
		for k, v := range a.AppearanceDB {
			out += fmt.Sprintf("  %s: %d\n", k, v)
		}
	}
	// if len(a.FacetKeyDB) > 0 {
	// 	out += "FacetKeys:\n"
	// 	for k, v := range a.FacetKeyDB {
	// 		out += fmt.Sprintf("  %s: %#v\n", k, v)
	// 		// out += fmt.Sprintf(
	// 		// 	"    "
	// 		// )
	// 	}
	// }
	if len(a.ColorDB) > 0 {
		out += "Colors:\n"
		for k, v := range a.ColorDB {
			if a.conf.Verbose {
				if tout, err := colorInTerminal(v); err == nil {
					out += fmt.Sprintf("- %s:\n  %s", k, tout)
				}
			} else {
				out += fmt.Sprintf("  %s: %#v\n", k, v)

			}
		}
	}
	if len(a.Localizations) > 0 {
		out += "Localizations:\n"
		for k, v := range a.Localizations {
			out += fmt.Sprintf("  %s: %d\n", k, v)
		}
	}
	if len(a.ImageDB) > 0 {
		out += "Assets:\n"
		for _, ass := range a.ImageDB {
			out += "-\n"
			var asset string
			switch t := ass.Asset.(type) {
			case csiColor:
				if a.conf.Verbose {
					if tout, err := t.ToTerminal(); err == nil {
						out += tout
					}
				}
				asset += fmt.Sprintf("Colorspace: %s\n", t.Info.ColorSpaceID())
				if len(t.Components) > 0 {
					asset += "Components:\n"
					for _, c := range t.Components {
						asset += fmt.Sprintf("  - %v\n", c)
					}
				}
			default:
			}
			var attrs string
			if len(ass.Attributes) > 0 {
				attrs += "Attributes:\n"
				for _, kf := range a.KeyFormat {
					if value, ok := ass.Attributes[kf.String()]; ok {
						attrs += fmt.Sprintf("  %-23s\t%d\n", kf.String()+":", value)
					}
				}
			}
			var rscs string
			if len(ass.Resources) > 0 {
				rscs += "Resources:\n"
				for _, rsc := range ass.Resources {
					rscs += fmt.Sprintf("  %s\n", rsc.ID)
				}
			}
			out += fmt.Sprintf(
				"Name: %s\n"+
					"Type: %s\n"+
					"Size: %s\n"+
					"%s%s%s",
				// "%s%s%s",
				ass.Name,
				ass.Type,
				humanize.Bytes(uint64(ass.Size)),
				asset,
				attrs,
				rscs,
			)
		}
	}
	return out
}
