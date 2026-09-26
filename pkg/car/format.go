package car

//go:generate go tool stringer -type=renditionAttributeType,renditionLayoutType,resourceID,compressionType -output=car_string.go .

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-termimg"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
)

var (
	colorTitle    = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorField    = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorSubField = color.New(color.Bold, color.FgHiCyan).SprintFunc()
)

func (a *Asset) String() string {
	var out strings.Builder
	out.WriteString(colorTitle("Asset\n") + "=====\n") // title
	out.WriteString(colorField("Header") + ":\n")
	out.WriteString(fmt.Sprintf(
		colorSubField("  Version")+":             %s\n"+
			colorSubField("  CoreUI Version")+":      %d\n"+
			colorSubField("  Storage Version")+":     %d\n"+
			colorSubField("  Storage Timestamp")+":   %s\n"+
			colorSubField("  Rendition Count")+":     %d\n"+
			colorSubField("  UUID")+":                %s\n"+
			colorSubField("  Associated Checksum")+": %#x\n"+
			colorSubField("  Schema Version")+":      %d\n"+
			colorSubField("  ColorSpaceID")+":        %s\n"+
			colorSubField("  Key Semantics")+":       %d\n",
		string(bytes.Trim(a.MainVersionString[:], "\x00")),
		a.CoreUiVersion,
		a.StorageVersion,
		time.Unix(int64(a.StorageTimestamp), 0).String(),
		a.RenditionCount,
		a.UUID.String(),
		a.AssociatedChecksum,
		a.SchemaVersion,
		a.ColorSpaceID,
		a.KeySemantics,
	))
	out.WriteString(colorField("Metadata") + ":\n")
	out.WriteString(fmt.Sprintf(
		"  Authoring Tool:      %s\n"+
			"  Thinning Args:       %s\n"+
			"  Deployment Platform: %s %s\n",
		string(bytes.Trim(a.Metadata.AuthoringTool[:], "\x00")),
		strings.ReplaceAll(string(bytes.Trim(a.Metadata.ThinningArguments[:], "\x00")), "<", "\n    <"),
		string(bytes.Trim(a.Metadata.DeploymentPlatform[:], "\x00")),
		string(bytes.Trim(a.Metadata.DeploymentPlatformVersion[:], "\x00")),
	))
	if len(a.KeyFormat) > 0 {
		out.WriteString(colorField("KeyFormats") + ":\n")
		for _, k := range a.KeyFormat {
			out.WriteString(fmt.Sprintf("  - %s\n", k))
		}
	}
	if len(a.AppearanceDB) > 0 {
		out.WriteString(colorField("Appearances") + ":\n")
		for k, v := range a.AppearanceDB {
			out.WriteString(fmt.Sprintf("  %s: %d\n", colorSubField(k), v))
		}
	}
	if len(a.ColorDB) > 0 {
		out.WriteString(colorField("Colors") + ":\n")
		for k, v := range a.ColorDB {
			if a.conf != nil && a.conf.Verbose {
				if tout, err := colorInTerminal(v); err == nil {
					out.WriteString(fmt.Sprintf("- %s:\n\n%s\n\n", k, tout))
				}
			} else {
				out.WriteString(fmt.Sprintf("  %s: %#v\n", colorSubField(k), v))

			}
		}
	}
	if len(a.Localizations) > 0 {
		out.WriteString(colorField("Localizations") + ":\n")
		for k, v := range a.Localizations {
			out.WriteString(fmt.Sprintf("  %s: %d\n", colorSubField(k), v))
		}
	}
	stats := a.Stats()
	out.WriteString(fmt.Sprintf("Inventory: %d total, %d selected, %d deferred, %d exported\n", stats.Total, stats.Selected, stats.Deferred, stats.Exported))
	if len(a.Diagnostics) > 0 {
		out.WriteString(colorField("Catalog diagnostics") + ":\n")
		for _, diagnostic := range a.Diagnostics {
			out.WriteString(fmt.Sprintf("  %s: %s\n", diagnostic.Block, diagnostic.Message))
		}
	}
	if len(a.ImageDB) > 0 {
		out.WriteString(fmt.Sprintf(colorTitle("Assets")+": (%d selected)\n", stats.Selected))
		for i, ass := range a.ImageDB {
			if !a.isSelected(i) {
				continue
			}
			out.WriteString(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴\n")
			var asset strings.Builder
			asset.WriteString(fmt.Sprintf("Key: %v\n", ass.Key))
			if ass.Deferred {
				asset.WriteString("Decoding: deferred\n")
			}
			if _, decoded := ass.Asset.(image.Image); !decoded && (ass.Width != 0 || ass.Height != 0) {
				asset.WriteString(fmt.Sprintf("Image Size: %dx%d\n", ass.Width, ass.Height))
			}
			if ass.Compression != "" {
				asset.WriteString(fmt.Sprintf("Compression: %s\n", ass.Compression))
			}
			if ass.Colorspace != "" {
				asset.WriteString(fmt.Sprintf("Color space: %s\n", ass.Colorspace))
			}
			if ass.Orientation != 0 {
				asset.WriteString(fmt.Sprintf("Orientation: %d\n", ass.Orientation))
			}
			for _, warning := range ass.Warnings {
				asset.WriteString(fmt.Sprintf("Warning: %s\n", warning))
			}
			switch t := ass.Asset.(type) {
			case nil:
			case csiColor:
				asset.WriteString(fmt.Sprintf(colorField("Colorspace")+": %s\n", t.Info.ColorSpaceID()))
				if len(t.Components) > 0 {
					asset.WriteString("  " + colorSubField("Components") + ":\n")
					for _, c := range t.Components {
						asset.WriteString(fmt.Sprintf("    - %v\n", c))
					}
					if a.conf != nil && a.conf.Verbose {
						if tout, err := t.ToTerminal(); err == nil {
							asset.WriteString(fmt.Sprintf(colorField("Color Preview")+":\n%s\n", tout))
						}
					}
				}
			case image.Image:
				asset.WriteString(fmt.Sprintf(colorField("Image Size")+": %dx%d\n", t.Bounds().Dx(), t.Bounds().Dy()))
				if a.conf != nil && a.conf.Verbose {
					if tout, err := termimg.New(t).Render(); err == nil {
						asset.WriteString(fmt.Sprintf("Image Preview:\n%s\n", tout))
					}
				}
			case csiMultisizeImageSet:
				asset.WriteString(colorField("MultiSized") + ":\n")
				for _, size := range t.ImageSizes {
					asset.WriteString(fmt.Sprintf("  - index %d: %dx%d\n", size.Index, size.Width, size.Height))
				}
			case []byte:
				// Raw data (PDF, JPEG, HEIF, etc.)
				asset.WriteString(fmt.Sprintf(colorField("Data Size")+": %s (%d bytes)\n", humanize.Bytes(uint64(len(t))), len(t)))
			default:
				log.Debugf("%s has unknown asset type: %T", ass.RenditionName, t)
			}
			for _, failure := range []struct {
				stage string
				err   error
			}{
				{"Decode", ass.DecodeError}, {"Reference", ass.ResolveError}, {"Export", ass.ExportError},
			} {
				if failure.err != nil {
					asset.WriteString(fmt.Sprintf("%s error: %v\n", failure.stage, failure.err))
				}
			}
			if ass.ExportPath != "" {
				asset.WriteString(fmt.Sprintf("Exported: %s\n", ass.ExportPath))
			}
			var attrs strings.Builder
			if len(ass.Attributes) > 0 {
				attrs.WriteString(colorField("Attributes") + ":\n")
				for _, kf := range a.KeyFormat {
					if value, ok := ass.Attributes[kf.String()]; ok {
						attrs.WriteString(fmt.Sprintf("  %s%d\n", colorSubField(fmt.Sprintf("%-20s", kf.String())), value))
					}
				}
			}
			var rscs strings.Builder
			if len(ass.Resources) > 0 {
				rscs.WriteString(colorField("Resources") + ":\n")
				for _, rsc := range ass.Resources {
					switch rsc.ID {
					case SliceID:
						var slice sliceResource
						if err := slice.UnmarshalBinary(rsc.Data); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: (%d)\n", colorSubField(rsc.ID), slice.NumSlices))
						for _, s := range slice.Slices {
							rscs.WriteString(fmt.Sprintf("    - pos(%03d,%03d) size(%03d,%03d)\n", s.X, s.Y, s.Width, s.Height))
						}
					case MetricsID:
						var metrics metricsResource
						if err := metrics.UnmarshalBinary(rsc.Data); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: (%d)\n", colorSubField(rsc.ID), metrics.NumMetrics))
						for _, m := range metrics.Metrics {
							rscs.WriteString(fmt.Sprintf("    - %s(%d,%d,%d,%d) %s(%03d,%03d)\n", colorField("insets"), m.LeftInset, m.TopInset, m.RightInset, m.BottomInset, colorField("size"), m.Width, m.Height))
						}
					case LayerReferenceID:
						layer := new(layerResource)
						if err := layer.UnmarshalBinary(rsc.Data); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: (%d):\n", colorSubField("Layers"), layer.NumLayers))
						for _, layer := range layer.Layers {
							rscs.WriteString(fmt.Sprintf("    %s(%03d,%03d) %s(%03d,%03d) %s=%d %s=%.2f\n",
								colorField("pos"), layer.Frame.X, layer.Frame.Y, colorField("size"), layer.Frame.Width, layer.Frame.Height, colorField("blend"), layer.BlendMode, colorField("opacity"), layer.Opacity))
							rscs.WriteString(fmt.Sprintf("    %s", utils.HexDump(layer.Data, 0)))
						}
					case InternalLinkID:
						var link csiInternalLinkData
						if err := link.UnmarshalBinary(bytes.NewReader(rsc.Data)); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: %s(%d,%d) %s(%d)\n", colorSubField(rsc.ID), colorSubField("frame"), link.Frame.X, link.Frame.Y, colorSubField("layout"), link.Layout))
						for _, ref := range link.Reference {
							rscs.WriteString(fmt.Sprintf("    %s: %d\n", colorSubField(renditionAttributeType(ref.Name)), ref.Value))
						}
					case CompositingOptionsID:
						var comp compositingResource
						if err := binary.Read(bytes.NewReader(rsc.Data), binary.LittleEndian, &comp); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s:\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s:\n    %s: %d\n    %s:   %.2f\n", colorSubField(rsc.ID), colorField("BlendMode"), comp.BlendMode, colorField("Opacity"), comp.Opacity))
					case MetaDataID:
						var meta metadataResource
						if err := meta.UnmarshalBinary(rsc.Data); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: %s\n", colorSubField(rsc.ID), bytes.Trim(meta.Data[:], "\x00")))
					case MetaDataEXIFOrientationID:
						var orient uint32
						if err := binary.Read(bytes.NewReader(rsc.Data), binary.LittleEndian, &orient); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: %d\n", colorSubField(rsc.ID), orient))
					case ImageRowBytesID:
						var rowBytes uint32
						if err := binary.Read(bytes.NewReader(rsc.Data), binary.LittleEndian, &rowBytes); err != nil {
							rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
							continue
						}
						rscs.WriteString(fmt.Sprintf("  %s: %s (%d)\n", colorSubField(rsc.ID), humanize.Bytes(uint64(rowBytes)), rowBytes))
					default:
						rscs.WriteString(fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0)))
					}
				}
			}
			var nameStr string
			if name := a.GetName(ass.ID()); len(name) > 0 {
				nameStr = colorField("Name") + fmt.Sprintf(": %s\n", name)
				if name != ass.RenditionName {
					nameStr += colorField("Rendition") + fmt.Sprintf(": %s\n", ass.RenditionName)
				}
			} else if len(ass.RenditionName) > 0 {
				nameStr = colorField("Rendition") + fmt.Sprintf(": %s\n", ass.RenditionName)
			}
			out.WriteString(fmt.Sprintf(
				"%s"+
					colorField("Type")+": %s\n"+
					colorField("Size")+": %s (%d)\n"+
					"%s%s%s",
				// "%s%s%s",
				nameStr,
				ass.Type,
				humanize.Bytes(uint64(ass.Size)), ass.Size,
				asset.String(),
				attrs.String(),
				rscs.String(),
			))
			out.WriteString(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴\n")
		}
	}
	return out.String()
}

// KeyFormatName converts renditionAttributeType to its Apple name
func (r renditionAttributeType) KeyFormatName() string {
	switch r {
	case ThemeLook:
		return "kCRThemeLookName"
	case Element:
		return "kCRThemeElementName"
	case Part:
		return "kCRThemePartName"
	case Size:
		return "kCRThemeSizeName"
	case Direction:
		return "kCRThemeDirectionName"
	case Placeholder:
		return "kCRThemePlaceholderName"
	case Value:
		return "kCRThemeValueName"
	case ThemeAppearance:
		return "kCRThemeAppearanceName"
	case Dimension1:
		return "kCRThemeDimension1Name"
	case Dimension2:
		return "kCRThemeDimension2Name"
	case State:
		return "kCRThemeStateName"
	case Layer:
		return "kCRThemeLayerName"
	case Scale:
		return "kCRThemeScaleName"
	case Localization:
		return "kCRThemeLocalizationName"
	case PresentationState:
		return "kCRThemePresentationStateName"
	case Idiom:
		return "kCRThemeIdiomName"
	case Subtype:
		return "kCRThemeSubtypeName"
	case Identifier:
		return "kCRThemeIdentifierName"
	case PreviousValue:
		return "kCRThemePreviousValueName"
	case PreviousState:
		return "kCRThemePreviousStateName"
	case HorizontalSizeClass:
		return "kCRThemeHorizontalSizeClassName"
	case VerticalSizeClass:
		return "kCRThemeVerticalSizeClassName"
	case MemoryLevelClass:
		return "kCRThemeMemoryLevelClassName"
	case GraphicsFeatureSetClass:
		return "kCRThemeGraphicsFeatureSetClassName"
	case DisplayGamut:
		return "kCRThemeDisplayGamutName"
	case DeploymentTarget:
		return "kCRThemeDeploymentTargetName"
	default:
		return fmt.Sprintf("renditionAttributeType(%d)", r)
	}
}

// ToJSON converts Asset to JSON format matching assetutil output
func (a *Asset) ToJSON() ([]byte, error) {
	output := []map[string]any{}

	// Add header information as first element
	header := map[string]any{
		"CoreUIVersion":      a.Header.CoreUiVersion,
		"StorageVersion":     a.Header.StorageVersion,
		"Timestamp":          a.Header.StorageTimestamp,
		"SchemaVersion":      a.Header.SchemaVersion,
		"MainVersion":        strings.TrimSpace(string(bytes.Trim(a.Header.MainVersionString[:], "\x00"))),
		"Authoring Tool":     strings.TrimSpace(string(bytes.Trim(a.Metadata.AuthoringTool[:], "\x00"))),
		"ThinningParameters": string(bytes.Trim(a.Metadata.ThinningArguments[:], "\x00")),
		"Platform":           string(bytes.Trim(a.Metadata.DeploymentPlatform[:], "\x00")),
		"PlatformVersion":    string(bytes.Trim(a.Metadata.DeploymentPlatformVersion[:], "\x00")),
	}

	// Add key format
	if len(a.KeyFormat) > 0 {
		keyFormats := []string{}
		for _, k := range a.KeyFormat {
			keyFormats = append(keyFormats, k.KeyFormatName())
		}
		header["Key Format"] = keyFormats
	}

	// Add appearances
	if len(a.AppearanceDB) > 0 {
		appearances := map[string]int{}
		for k, v := range a.AppearanceDB {
			appearances[k] = int(v)
		}
		header["Appearances"] = appearances
	}

	header["CatalogStats"] = a.Stats()
	if len(a.Diagnostics) > 0 {
		header["Diagnostics"] = a.Diagnostics
	}
	if len(a.UnknownBlocks) > 0 {
		blocks := make([]map[string]any, 0, len(a.UnknownBlocks))
		for _, block := range a.UnknownBlocks {
			blocks = append(blocks, map[string]any{"Name": block.Name, "Size": len(block.Data)})
		}
		header["UnknownBlocks"] = blocks
	}
	output = append(output, header)

	// Add selected renditions; CatalogStats retains the complete inventory count.
	for i, rend := range a.ImageDB {
		if !a.isSelected(i) {
			continue
		}
		rendition := map[string]any{
			"Name":        rend.RenditionName,
			"Type":        rend.Type,
			"Selected":    a.isSelected(i),
			"Deferred":    rend.Deferred,
			"PixelWidth":  rend.Width,
			"PixelHeight": rend.Height,
		}
		if format := strings.Trim(rend.PixelFormat, "\x00 "); format != "" {
			rendition["PixelFormat"] = format
		}
		if rend.Compression != "" {
			rendition["Compression"] = rend.Compression
		}
		if rend.Colorspace != "" {
			rendition["ColorSpace"] = rend.Colorspace
		}
		if rend.Scale != 0 {
			rendition["ScaleFactor"] = rend.Scale
		}
		if rend.Orientation != 0 {
			rendition["Orientation"] = rend.Orientation
		}
		if len(rend.Warnings) > 0 {
			rendition["Warnings"] = rend.Warnings
		}
		if len(rend.Resources) > 0 {
			resources := make([]map[string]any, 0, len(rend.Resources))
			for _, resource := range rend.Resources {
				resources = append(resources, map[string]any{"ID": uint32(resource.ID), "Name": resource.ID.String(), "Length": len(resource.Data)})
			}
			rendition["Resources"] = resources
		}

		if len(rend.Key) > 0 {
			rendition["RenditionKey"] = rend.Key
		}
		if rend.DecodeError != nil {
			rendition["DecodeError"] = rend.DecodeError.Error()
		}
		if rend.ResolveError != nil {
			rendition["ResolveError"] = rend.ResolveError.Error()
		}
		if rend.ExportError != nil {
			rendition["ExportError"] = rend.ExportError.Error()
		}
		if rend.ExportPath != "" {
			rendition["ExportPath"] = rend.ExportPath
		}
		if img, ok := rend.Asset.(image.Image); ok {
			rendition["PixelWidth"] = img.Bounds().Dx()
			rendition["PixelHeight"] = img.Bounds().Dy()
		}

		// Add attributes
		for _, kf := range a.KeyFormat {
			if value, ok := rend.Attributes[kf.String()]; ok {
				switch kf {
				case Scale:
					rendition["Scale"] = value
				case Idiom:
					rendition["Idiom"] = getIdiomName(value)
				case Subtype:
					if value > 0 {
						rendition["Subtype"] = value
					}
				case Identifier:
					if value > 0 {
						rendition["NameIdentifier"] = value
					}
				}
			}
		}

		if rend.Size > 0 {
			rendition["SizeOnDisk"] = rend.Size
		}

		output = append(output, rendition)
	}

	return json.MarshalIndent(output, "", "  ")
}

func getIdiomName(value uint16) string {
	switch coreThemeIdiom(value) {
	case Universal:
		return "universal"
	case Phone:
		return "phone"
	case Tablet:
		return "pad"
	case Desktop:
		return "desktop"
	case Tv:
		return "tv"
	case Car:
		return "car"
	case Watch:
		return "watch"
	case Marketing:
		return "marketing"
	default:
		return fmt.Sprintf("idiom_%d", value)
	}
}
