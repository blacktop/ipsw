package car

//go:generate go tool stringer -type=renditionAttributeType,renditionLayoutType,resourceID,csiBitmapEncoding -output car_string.go

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
	var out string
	out += colorTitle("Asset\n") + "=====\n" // title
	out += colorField("Header") + ":\n"
	out += fmt.Sprintf(
		colorSubField("  Version")+":             %s"+
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
	)
	out += colorField("Metadata") + ":\n"
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
		out += colorField("KeyFormats") + ":\n"
		for _, k := range a.KeyFormat {
			out += fmt.Sprintf("  - %s\n", k)
		}
	}
	if len(a.AppearanceDB) > 0 {
		out += colorField("Appearances") + ":\n"
		for k, v := range a.AppearanceDB {
			out += fmt.Sprintf("  %s: %d\n", colorSubField(k), v)
		}
	}
	if len(a.ColorDB) > 0 {
		out += colorField("Colors") + ":\n"
		for k, v := range a.ColorDB {
			if a.conf.Verbose {
				if tout, err := colorInTerminal(v); err == nil {
					out += fmt.Sprintf("- %s:\n\n%s\n\n", k, tout)
				}
			} else {
				out += fmt.Sprintf("  %s: %#v\n", colorSubField(k), v)

			}
		}
	}
	if len(a.Localizations) > 0 {
		out += colorField("Localizations") + ":\n"
		for k, v := range a.Localizations {
			out += fmt.Sprintf("  %s: %d\n", colorSubField(k), v)
		}
	}
	if len(a.ImageDB) > 0 {
		out += fmt.Sprintf(colorTitle("Assets")+": (%d)\n", len(a.ImageDB))
		for _, ass := range a.ImageDB {
			out += " ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴\n"
			var asset string
			switch t := ass.Asset.(type) {
			case csiColor:
				asset += fmt.Sprintf(colorField("Colorspace")+": %s\n", t.Info.ColorSpaceID())
				if len(t.Components) > 0 {
					asset += "  " + colorSubField("Components") + ":\n"
					for _, c := range t.Components {
						asset += fmt.Sprintf("    - %v\n", c)
					}
					if a.conf.Verbose {
						if tout, err := t.ToTerminal(); err == nil {
							asset += fmt.Sprintf(colorField("Color Preview")+":\n%s\n", tout)
						}
					}
				}
			case *BGRA:
				asset += fmt.Sprintf(colorField("Image Size")+": %dx%d\n", t.Rect.Max.X, t.Rect.Max.Y)
				if a.conf.Verbose {
					if tout, err := termimg.New(t).Render(); err == nil {
						asset += fmt.Sprintf("Image Preview:\n%s\n", tout)
					}
				}
			case *GA8:
				asset += fmt.Sprintf(colorField("Image Size")+": %dx%d\n", t.Rect.Max.X, t.Rect.Max.Y)
				if a.conf.Verbose {
					if tout, err := termimg.New(t).Render(); err == nil {
						asset += fmt.Sprintf("Image Preview:\n%s\n", tout)
					}
				}
			case *image.RGBA:
				asset += fmt.Sprintf(colorField("Image Size")+": %dx%d\n", t.Rect.Max.X, t.Rect.Max.Y)
				if a.conf.Verbose {
					if tout, err := termimg.New(t).Render(); err == nil {
						asset += fmt.Sprintf("Image Preview:\n%s\n", tout)
					}
				}
			case csiNamedGradient:
				asset += colorField("Gradient") + ":\n"
				for i := range t.ColorCount {
					asset += fmt.Sprintf("  - %s (%.3f, %.3f)\n", bytes.Trim(t.Stops[i].Name, "\x00"), float32(t.StartStops[i].Start), float32(t.StartStops[i].Stop))
				}
			case csiMultisizeImageSet:
				asset += colorField("MultiSized") + ":\n"
				for _, size := range t.ImageSizes {
					asset += fmt.Sprintf("  - index %d: %dx%d\n", size.Index, size.Width, size.Height)
				}
			default:
				log.Debugf("%s has unknown asset type: %T", ass.RenditionName, t)
			}
			var attrs string
			if len(ass.Attributes) > 0 {
				attrs += colorField("Attributes") + ":\n"
				for _, kf := range a.KeyFormat {
					if value, ok := ass.Attributes[kf.String()]; ok {
						attrs += fmt.Sprintf("  %s%d\n", colorSubField(fmt.Sprintf("%-20s", kf.String())), value)
					}
				}
			}
			var rscs string
			if len(ass.Resources) > 0 {
				rscs += colorField("Resources") + ":\n"
				for _, rsc := range ass.Resources {
					switch rsc.ID {
					case SliceID:
						var slice sliceResource
						if err := slice.UnmarshalBinary(rsc.Data); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: (%d)\n", colorSubField(rsc.ID), slice.NumSlices)
						for _, s := range slice.Slices {
							rscs += fmt.Sprintf("    - pos(%03d,%03d) size(%03d,%03d)\n", s.X, s.Y, s.Width, s.Height)
						}
					case MetricsID:
						var metrics metricsResource
						if err := metrics.UnmarshalBinary(rsc.Data); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: (%d)\n", colorSubField(rsc.ID), metrics.NumMetrics)
						for _, m := range metrics.Metrics {
							rscs += fmt.Sprintf("    - %s(%d,%d,%d,%d) %s(%03d,%03d)\n", colorField("insets"), m.LeftInset, m.TopInset, m.RightInset, m.BottomInset, colorField("size"), m.Width, m.Height)
						}
					case LayerReferenceID:
						layer := new(layerResource)
						if err := layer.UnmarshalBinary(rsc.Data); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: (%d):\n", colorSubField("Layers"), layer.NumLayers)
						for _, layer := range layer.Layers {
							rscs += fmt.Sprintf("    %s(%03d,%03d) %s(%03d,%03d) %s=%d %s=%.2f\n",
								colorField("pos"), layer.Frame.X, layer.Frame.Y, colorField("size"), layer.Frame.Width, layer.Frame.Height, colorField("blend"), layer.BlendMode, colorField("opacity"), layer.Opacity)
							rscs += fmt.Sprintf("    %s", utils.HexDump(layer.Data, 0))
						}
					case InternalLinkID:
						var link csiInternalLinkData
						if err := link.UnmarshalBinary(bytes.NewReader(rsc.Data)); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: %s(%d,%d) %s(%d)\n", colorSubField(rsc.ID), colorSubField("frame"), link.Frame.X, link.Frame.Y, colorSubField("layout"), link.Layout)
						for _, ref := range link.Reference {
							rscs += fmt.Sprintf("    %s: %d\n", colorSubField(renditionAttributeType(ref.Name)), ref.Value)
						}
					case CompositingOptionsID:
						var comp compositingResource
						if err := binary.Read(bytes.NewReader(rsc.Data), binary.LittleEndian, &comp); err != nil {
							rscs += fmt.Sprintf("  %s:\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s:\n    %s: %d\n    %s:   %.2f\n", colorSubField(rsc.ID), colorField("BlendMode"), comp.BlendMode, colorField("Opacity"), comp.Opacity)
					case MetaDataID:
						var meta metadataResource
						if err := meta.UnmarshalBinary(rsc.Data); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: %s\n", colorSubField(rsc.ID), bytes.Trim(meta.Data[:], "\x00"))
					case MetaDataEXIFOrientationID:
						var orient uint32
						if err := binary.Read(bytes.NewReader(rsc.Data), binary.LittleEndian, &orient); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: %d\n", colorSubField(rsc.ID), orient)
					case ImageRowBytesID:
						var rowBytes uint32
						if err := binary.Read(bytes.NewReader(rsc.Data), binary.LittleEndian, &rowBytes); err != nil {
							rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
						}
						rscs += fmt.Sprintf("  %s: %s (%d)\n", colorSubField(rsc.ID), humanize.Bytes(uint64(rowBytes)), rowBytes)
					default:
						rscs += fmt.Sprintf("  %s\n%s", colorSubField(rsc.ID), utils.HexDump(rsc.Data, 0))
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
			out += fmt.Sprintf(
				"%s"+
					colorField("Type")+": %s\n"+
					colorField("Size")+": %s (%d)\n"+
					"%s%s%s",
				// "%s%s%s",
				nameStr,
				ass.Type,
				humanize.Bytes(uint64(ass.Size)), ass.Size,
				asset,
				attrs,
				rscs,
			)
			out += " ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴\n"
		}
	}
	return out
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
	case placeholder:
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

	output = append(output, header)

	// Add renditions
	for _, rend := range a.ImageDB {
		rendition := map[string]any{
			"Name": rend.Name,
			"Type": rend.Type,
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
