package car

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image/color"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
	"github.com/blacktop/ipsw/pkg/car/internal/render"
)

// NOTES:
// - https://github.com/insidegui/AssetCatalogTinkerer
// - https://github.com/bartoszj/acextract
// - https://blog.timac.org/2018/1018-reverse-engineering-the-car-file-format/

type Config struct {
	Output  string
	Export  bool
	Verbose bool
	// MetadataOnly inventories renditions without decoding or exporting pixels.
	MetadataOnly     bool
	Query            *VariantQuery
	Render           bool
	Raw              bool
	ApplyOrientation bool
	ASTCDecoder      string
}

type Asset struct {
	Header
	Metadata  extendedMetadata
	KeyFormat []renditionAttributeType
	ImageDB   []Rendition
	ColorDB   map[string]color.RGBA
	// FontDB        map[string]Font
	// FontSizeDB    map[string]uint32
	// GlyphDB       map[string]Glyph
	// BezelDB       map[string]Bezel
	FacetKeyDB    map[string]renditionKeyToken
	BitmapKeyDB   map[any][]byte // Keys are inline uint32 bitmap identifiers.
	AppearanceDB  map[string]uint16
	Globals       []byte // bplist data
	Localizations map[string]uint32

	UnknownBlocks []OpaqueBlock
	Diagnostics   []CatalogDiagnostic

	conf               *Config
	selectionReady     bool
	retainedBlockBytes int
}

func (a *Asset) GetName(id uint16) string {
	var name string
	for k, v := range a.FacetKeyDB {
		for _, attr := range v.Attributes {
			if attr.Name == uint16(Identifier) && attr.Value == id && (name == "" || k < name) {
				name = k
			}
		}
	}
	return name
}

func (a *Asset) GetFaceKey(id uint16) (*renditionKeyToken, error) {
	for _, v := range a.FacetKeyDB {
		for _, attr := range v.Attributes {
			if attr.Name == 17 && attr.Value == id {
				return &v, nil
			}
		}
	}
	return nil, fmt.Errorf("could not find face key for id: %d", id)
}

type Header struct {
	Tag                [4]byte // 'CTAR'
	CoreUiVersion      uint32
	StorageVersion     uint32
	StorageTimestamp   uint32
	RenditionCount     uint32
	MainVersionString  [128]byte
	VersionString      [256]byte
	UUID               types.UUID
	AssociatedChecksum uint32
	SchemaVersion      uint32
	ColorSpaceID       colorSpaceID
	KeySemantics       uint32
}

type extendedMetadata struct {
	Tag                       [4]byte // 'META'
	ThinningArguments         [256]byte
	DeploymentPlatformVersion [256]byte
	DeploymentPlatform        [256]byte
	AuthoringTool             [256]byte
}

type renditionAttributeType uint32

const (
	ThemeLook renditionAttributeType = iota
	Element
	Part
	Size
	Direction
	Placeholder
	Value
	ThemeAppearance
	Dimension1
	Dimension2
	State
	Layer
	Scale
	Localization
	PresentationState
	Idiom
	Subtype
	Identifier
	PreviousValue
	PreviousState
	HorizontalSizeClass
	VerticalSizeClass
	MemoryLevelClass
	GraphicsFeatureSetClass
	DisplayGamut
	DeploymentTarget
	GlyphWeight
	GlyphSize
)

type RenditionKeyformat struct {
	Tag                           [4]byte // 'kfmt'
	Version                       uint32
	MaximumRenditionKeyTokenCount uint32
	RenditionKeyTokens            []renditionAttributeType
}

type systemColor struct {
	Version uint32 // 1
	Unknown uint32 // 0
	Color   struct {
		Blue  uint8
		Green uint8
		Red   uint8
		Alpha uint8
	}
}

type renditionLayoutType uint16

const (
	OnePart             renditionLayoutType = 0
	ThreePartHorizontal renditionLayoutType = 1
	ThreePartVertical   renditionLayoutType = 2
	NinePart            renditionLayoutType = 3
	TwelvePart          renditionLayoutType = 4
	ManyPart            renditionLayoutType = 5
	Gradient            renditionLayoutType = 6
	Effect              renditionLayoutType = 7
	Animation           renditionLayoutType = 8
	Vector              renditionLayoutType = 9

	IconImage renditionLayoutType = 12

	Unknown renditionLayoutType = 20

	RawData             renditionLayoutType = 1000
	ExternalLink        renditionLayoutType = 1001
	ImageStack          renditionLayoutType = 1002
	InternalLink        renditionLayoutType = 1003
	PackedImage         renditionLayoutType = 1004
	NamedContents       renditionLayoutType = 1005
	ThinningPlaceholder renditionLayoutType = 1006
	TextureRendition    renditionLayoutType = 1007
	TextureImage        renditionLayoutType = 1008
	Color               renditionLayoutType = 1009
	MultiSizeImageSet   renditionLayoutType = 1010
	ModelIOAsset        renditionLayoutType = 1011
	ModelMesh           renditionLayoutType = 1012
	RecognitionGroup    renditionLayoutType = 1013
	RecognitionObject   renditionLayoutType = 1014

	ModelIOSubmesh  renditionLayoutType = 1016
	VectorGlyph     renditionLayoutType = 1017
	SolidImageStack renditionLayoutType = 1018
	IconImageStack  renditionLayoutType = 1019
	IconGroup       renditionLayoutType = 1020
	NamedGradient   renditionLayoutType = 1021
)

type coreThemeIdiom uint32

const (
	Universal coreThemeIdiom = 0
	Phone     coreThemeIdiom = 1
	Tablet    coreThemeIdiom = 2
	Desktop   coreThemeIdiom = 3
	Tv        coreThemeIdiom = 4
	Car       coreThemeIdiom = 5
	Watch     coreThemeIdiom = 6
	Marketing coreThemeIdiom = 7
)

type renditionAttribute struct {
	Name  uint16
	Value uint16
}
type renditionKeyToken struct {
	CursorHotSpot struct {
		X uint16
		Y uint16
	}
	NumberOfAttributes uint16
	Attributes         []renditionAttribute
}

func (k *renditionKeyToken) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &k.CursorHotSpot); err != nil {
		return fmt.Errorf("failed to read rendition key token cursor hotspot: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &k.NumberOfAttributes); err != nil {
		return fmt.Errorf("failed to read rendition key token number of attributes: %v", err)
	}
	k.Attributes = make([]renditionAttribute, k.NumberOfAttributes)
	for i := range k.Attributes {
		if err := binary.Read(r, binary.LittleEndian, &k.Attributes[i]); err != nil {
			return fmt.Errorf("failed to read rendition key token attribute %d: %v", i, err)
		}
	}
	if r.Len() > 0 {
		return fmt.Errorf("failed to read entire rendition key token: %v", r.Len())
	}
	return nil
}

type Rendition struct {
	RenditionName string
	Type          string
	Colorspace    string
	Size          int
	Attributes    map[string]uint16
	Resources     []csiResource
	Asset         any
	// Key contains every RENDITIONS key value, including values beyond KEYFORMAT.
	Key          []uint16
	PixelFormat  string
	DecodeError  error
	ResolveError error
	ExportError  error
	ExportPath   string
	Width        uint32
	Height       uint32
	Scale        uint32 // CSI scale factor: 100 is 1x.
	Compression  string
	Orientation  uint32
	ColorSpace   colorSpaceID
	Selected     bool
	Deferred     bool
	Warnings     []string
	link         *csiInternalLinkData
	header       csiHeader
	payload      []byte
	rawCSI       []byte
}

func (r Rendition) ID() uint16 {
	if id, ok := r.Attributes[Identifier.String()]; ok {
		return id
	}
	return 0
}
func (r Rendition) Part() uint16 {
	if id, ok := r.Attributes[Part.String()]; ok {
		return id
	}
	return 0
}
func (r Rendition) Element() uint16 {
	if id, ok := r.Attributes[Element.String()]; ok {
		return id
	}
	return 0
}

func Parse(name string, conf *Config) (*Asset, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", name, err)
	}
	defer f.Close()

	fi, err := os.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %v", name, err)
	}
	modeTime := fi.ModTime().Local().Unix()

	if err := validateCatalogBOM(f, fi.Size()); err != nil {
		return nil, fmt.Errorf("invalid CAR BOM: %w", err)
	}
	bm, err := bom.New(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse BOM file: %v", err)
	}

	if conf == nil {
		conf = &Config{}
	}
	a := Asset{conf: conf}

	a.AppearanceDB = make(map[string]uint16)
	a.BitmapKeyDB = make(map[any][]byte)
	a.ColorDB = make(map[string]color.RGBA)
	a.Localizations = make(map[string]uint32)

	if a.conf.Verbose {
		log.WithField("name", name).Debug("Parsing BOM")
		utils.Indent(log.Debug, 2)("Blocks/Trees: " + strings.Join(bm.BlockNames(), ", "))
	}

	hasRenditions := false
	for _, v := range bm.Vars {
		switch v.Name {
		/**********
		 * BLOCKS *
		 **********/
		case "CARHEADER":
			br, err := bm.ReadBlock(v.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to read block %s: %v", v.Name, err)
			}
			if err := binary.Read(br, binary.LittleEndian, &a.Header); err != nil {
				return nil, fmt.Errorf("failed to read CAR header: %v", err)
			}
			if a.Tag != [4]byte{'R', 'A', 'T', 'C'} { // 'CTAR'
				return nil, fmt.Errorf("invalid CAR header tag: %s", a.Tag)
			}
			if a.StorageTimestamp == 0 {
				a.StorageTimestamp = uint32(modeTime) // use file modification time
			}
			// TODO: read tree ? (I see a 'tree' following this data, but that might be some other object's sub-tree)
		case "EXTENDED_METADATA":
			br, err := bm.ReadBlock(v.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to read block %s: %v", v.Name, err)
			}
			if err := binary.Read(br, binary.BigEndian, &a.Metadata); err != nil {
				return nil, fmt.Errorf("failed to read extended metadata: %v", err)
			}
			if a.Metadata.Tag != [4]byte{'M', 'E', 'T', 'A'} {
				return nil, fmt.Errorf("invalid extended metadata tag: %s", a.Metadata.Tag)
			}
		case "KEYFORMAT":
			if err := a.parseKeyFormat(bm); err != nil {
				return nil, fmt.Errorf("failed to parse KEYFORMAT block: %v", err)
			}
		case "CARGLOBALS":
			br, err := bm.ReadBlock(v.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to read block %s: %v", v.Name, err)
			}
			a.Globals, err = io.ReadAll(br)
			if err != nil {
				return nil, fmt.Errorf("failed to read CARGLOBALS data: %v", err)
			}
		case "KEYFORMATWORKAROUND":
			if err := a.parseKeyFormatWorkaround(bm); err != nil {
				return nil, fmt.Errorf("failed to parse KEYFORMATWORKAROUND block: %v", err)
			}
			if a.conf.Verbose {
				br, err := bm.ReadBlock(v.Name)
				if err != nil {
					log.Debugf("Failed to read KEYFORMATWORKAROUND block: %v", err)
				} else {
					data, err := io.ReadAll(br)
					if err != nil {
						log.Debugf("Failed to read KEYFORMATWORKAROUND data: %v", err)
					} else {
						log.Debugf("KEYFORMATWORKAROUND block found (%d bytes)", len(data))
						if len(data) <= 256 {
							log.Debugf("KEYFORMATWORKAROUND hex dump:\n%s", hex.Dump(data))
						}
					}
				}
			}
		case "EXTERNAL_KEYS", "BEZELS", "ELEMENT_INFO", "FONTS", "FONTSIZES", "GLYPHS", "PART_INFO":
			if err := a.retainBlock(bm, v.Name, "known optional block is not interpreted"); err != nil {
				return nil, err
			}
		/*********
		 * TREES *
		 *********/
		case "APPEARANCEKEYS":
			trees, err := bm.ReadTrees("APPEARANCEKEYS")
			if err != nil {
				return nil, fmt.Errorf("failed to read APPEARANCEKEYS tree: %v", err)
			}
			for _, tree := range trees {
				for _, item := range tree.Indices {
					key, err := io.ReadAll(item.KeyReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read key for APPEARANCEKEYS: %v", err)
					}
					var value uint16
					if err := binary.Read(item.ValueReader, binary.LittleEndian, &value); err != nil {
						return nil, fmt.Errorf("failed to read value for key %s: %v", string(key), err)
					}
					a.AppearanceDB[string(key)] = value
				}
			}
		case "BITMAPKEYS":
			trees, err := bm.ReadTrees("BITMAPKEYS")
			if err != nil {
				return nil, fmt.Errorf("failed to read BITMAPKEYS tree: %v", err)
			}
			for _, tree := range trees {
				for _, item := range tree.Indices {
					value, err := io.ReadAll(item.ValueReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read BITMAPKEYS value: %v", err)
					}
					if a.conf.Verbose {
						// Show the inline identifier, not bytes from an unrelated block.
						item.KeyReader = bytes.NewReader(binary.BigEndian.AppendUint32(nil, item.Key))
						item.ValueReader = bytes.NewReader(value)
						if err := dumpTreeIndice("BITMAPKEYS", item); err != nil {
							return nil, fmt.Errorf("failed to dump BITMAPKEYS tree indice: %v", err)
						}
					}
					// BITMAPKEYS stores IDs directly, including IDs below the BOM block count.
					a.BitmapKeyDB[item.Key] = value
				}
			}
		case "COLORS":
			ctrees, err := bm.ReadTrees("COLORS")
			if err != nil {
				return nil, fmt.Errorf("failed to read COLORS tree: %v", err)
			}
			for _, tree := range ctrees {
				for _, item := range tree.Indices {
					var key uint32 // always 0
					if err := binary.Read(item.KeyReader, binary.LittleEndian, &key); err != nil {
						return nil, fmt.Errorf("failed to read COLORS key: %v", err)
					}
					name, err := readString(item.KeyReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read COLORS name: %v", err)
					}
					var sc systemColor
					if err := binary.Read(item.ValueReader, binary.LittleEndian, &sc); err != nil {
						return nil, fmt.Errorf("failed to read COLORS system color: %v", err)
					}
					a.ColorDB[name] = color.RGBA{
						R: sc.Color.Red,
						G: sc.Color.Green,
						B: sc.Color.Blue,
						A: sc.Color.Alpha,
					}
				}
			}
		case "FACETKEYS":
			if err := a.parseFacetKeys(bm); err != nil {
				return nil, fmt.Errorf("failed to parse FACETKEYS trees: %v", err)
			}
		case "LOCALIZATIONKEYS":
			trees, err := bm.ReadTrees("LOCALIZATIONKEYS")
			if err != nil {
				return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS tree: %v", err)
			}
			for _, tree := range trees {
				for _, item := range tree.Indices {
					key, err := io.ReadAll(item.KeyReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS key: %v", err)
					}
					valueData, err := io.ReadAll(item.ValueReader)
					if err != nil {
						return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS value data: %v", err)
					}
					var value uint32
					switch len(valueData) {
					case 2:
						value = uint32(binary.LittleEndian.Uint16(valueData))
					case 4:
						value = binary.LittleEndian.Uint32(valueData)
					default:
						return nil, fmt.Errorf("failed to read LOCALIZATIONKEYS value: %v; data=\n%s", err, hex.Dump(valueData))
					}
					a.Localizations[string(key)] = uint32(value)
				}
			}
		case "RENDITIONS":
			hasRenditions = true
			if err := a.parseKeyFormat(bm); err != nil {
				return nil, fmt.Errorf("failed to parse asset KeyFormat %v", err)
			}
			rtrees, err := bm.ReadTrees("RENDITIONS")
			if err != nil {
				return nil, fmt.Errorf("failed to read 'RENDITIONS' trees: %v", err)
			}
			for _, tree := range rtrees {
				for _, item := range tree.Indices {
					keyData, err := compression.ReadLimited(item.KeyReader, 2*65536)
					if err != nil {
						return nil, fmt.Errorf("read rendition key: %w", err)
					}
					vdata, err := compression.ReadLimited(item.ValueReader, pixel.MaxBytes)
					if err != nil {
						return nil, fmt.Errorf("read rendition value: %w", err)
					}
					rend, err := a.parseRendition(keyData, vdata)
					if err != nil {
						return nil, err
					}
					a.ImageDB = append(a.ImageDB, *rend)
				}
			}
		default:
			if err := a.retainBlock(bm, v.Name, "unknown optional block retained"); err != nil {
				return nil, err
			}
		}
	}

	if a.Tag != [4]byte{'R', 'A', 'T', 'C'} {
		return nil, fmt.Errorf("missing CARHEADER")
	}
	if a.RenditionCount > 0 && !hasRenditions {
		return nil, fmt.Errorf("missing RENDITIONS tree for %d declared renditions", a.RenditionCount)
	}
	if err := a.selectRenditions(); err != nil {
		return nil, err
	}
	if !a.conf.MetadataOnly && !a.conf.Raw {
		for i := range a.ImageDB {
			if a.isSelected(i) {
				_ = a.ensureDecoded(i)
			}
		}
		if err := a.resolveReferences(); err != nil {
			return nil, err
		}
	}
	a.exportRenditions()
	return &a, nil
}

// parseRendition rejects corrupt key/header/resource framing. Payload failures remain
// on the rendition so callers can inspect the complete catalog and export other entries.
func (a *Asset) parseRendition(keyData, data []byte) (*Rendition, error) {
	if len(keyData) < len(a.KeyFormat)*2 || len(keyData)%2 != 0 {
		return nil, fmt.Errorf("rendition key has %d bytes for %d tokens", len(keyData), len(a.KeyFormat))
	}
	rend := &Rendition{Key: make([]uint16, len(keyData)/2), Attributes: make(map[string]uint16), Deferred: true, rawCSI: data}
	for i := range rend.Key {
		rend.Key[i] = binary.LittleEndian.Uint16(keyData[i*2:])
	}
	for i, attr := range a.KeyFormat {
		rend.Attributes[attr.String()] = rend.Key[i]
	}
	vr := bytes.NewReader(data)
	header, err := readCSIFileHeader(vr)
	if err != nil {
		return nil, fmt.Errorf("read rendition header: %w", err)
	}
	if uint64(header.ChainSize) > uint64(vr.Len()) {
		return nil, fmt.Errorf("rendition resource chain exceeds value")
	}
	resources := make([]byte, header.ChainSize)
	if _, err := io.ReadFull(vr, resources); err != nil {
		return nil, err
	}
	rr := bytes.NewReader(resources)
	for rr.Len() > 0 {
		var resource csiResource
		if err := binary.Read(rr, binary.LittleEndian, &resource.ID); err != nil {
			return nil, err
		}
		if err := binary.Read(rr, binary.LittleEndian, &resource.Length); err != nil {
			return nil, err
		}
		if uint64(resource.Length) > uint64(rr.Len()) {
			return nil, fmt.Errorf("rendition resource exceeds chain")
		}
		resource.Data = make([]byte, resource.Length)
		if _, err := io.ReadFull(rr, resource.Data); err != nil {
			return nil, err
		}
		rend.Resources = append(rend.Resources, resource)
	}
	rend.RenditionName = string(bytes.SplitN(header.Metadata.Name[:], []byte{0}, 2)[0])
	if rend.RenditionName == "" {
		rend.RenditionName = "CoreStructuredImage"
	}
	rend.Width, rend.Height, rend.Scale = header.Width, header.Height, header.ScaleFactor
	rend.ColorSpace = header.ColorSpace.ColorSpaceID()
	rend.Colorspace = rend.ColorSpace.String()
	rend.Type = header.Metadata.Layout.String()
	rend.PixelFormat = string(utils.ReverseBytes(header.PixelFormat[:]))
	rend.header = *header
	rend.Size = int(header.ImageIndex.AccumLength[len(header.ImageIndex.AccumLength)-1])
	// rawCSI owns the storage for deferred payloads, including unselected entries.
	rend.payload = data[len(data)-vr.Len():]
	rend.inspectPayload()
	if header.Metadata.Layout == InternalLink {
		// Link framing is metadata; resolving it may require decoding an atlas.
		// Invalid links remain per-rendition failures when decoding is requested.
		rend.DecodeError = a.decodeRendition(rend, *header, rend.payload)
	}
	return rend, nil
}

func (a *Asset) decodeRendition(rend *Rendition, header csiHeader, data []byte) error {
	// These layouts carry drawing instructions, even when the FourCC is ARGB.
	if unsupportedDrawingLayout(header.Metadata.Layout) {
		return fmt.Errorf("%w layout: %s", errUnsupportedRendition, header.Metadata.Layout)
	}
	if header.Metadata.Layout == InternalLink {
		var referenceData []byte
		found := false
		for _, resource := range rend.Resources {
			if resource.ID != InternalLinkID {
				continue
			}
			if found {
				return fmt.Errorf("duplicate internal reference resource")
			}
			found = true
			referenceData = resource.Data
		}
		// The usual INLK resource has no bitmap payload, even with an ARGB
		// pixel format. Retain support for a link stored directly in the payload.
		if !found {
			referenceData = data
		}
		var link csiInternalLinkData
		if err := link.UnmarshalBinary(bytes.NewReader(referenceData)); err != nil {
			return fmt.Errorf("read internal reference: %w", err)
		}
		rend.link = &link
		rend.Asset = link
		return nil
	}
	vr := bytes.NewReader(data)
	switch rend.PixelFormat {
	case PixFmtARGB, PixFmtARGB16, PixFmtRGB555, PixFmtGray, PixFmtGray16, PixFmtGrayscale:
		rend.Type = fmt.Sprintf("Image (%s)", header.Metadata.Layout)
		// CoreUI also stores HEIC containers inside raster renditions with HEVC encoding.
		if len(data) >= 12 && string(data[:4]) == "MLEC" && compressionType(binary.LittleEndian.Uint32(data[8:12])) == HEVC {
			rend.Type = "HEIF"
			rend.PixelFormat = PixFmtHEIF
			payload, err := decodeOriginalPayload(data, PixFmtHEIF)
			if err != nil {
				return err
			}
			return a.setOriginalPayload(rend, payload)
		}
		var rowBytes uint32
		for _, resource := range rend.Resources {
			if resource.ID == ImageRowBytesID {
				if len(resource.Data) < 4 {
					return fmt.Errorf("truncated image row bytes")
				}
				rowBytes = binary.LittleEndian.Uint32(resource.Data)
				break
			}
		}
		img, err := decodeImage(vr, header, a.conf, int(rowBytes))
		if errors.Is(err, errors.ErrUnsupported) {
			return fmt.Errorf("%w: %w", errUnsupportedRendition, err)
		}
		if err != nil {
			return err
		}
		rend.Asset = img
		if rend.PixelFormat == PixFmtARGB16 && (rend.ColorSpace == ExtendedSRGB || rend.ColorSpace == ExtendedLinear) {
			rend.Warnings = append(rend.Warnings, "PNG clamps extended-range samples to [0,1]; use raw CSI export to preserve the source")
		}
	case PixFmtPDF, PixFmtJPEG, PixFmtHEIF, PixFmtSVG, PixFmtWebP, PixFmtRawData:
		rend.Type = strings.TrimSpace(rend.PixelFormat)
		payload, err := decodeOriginalPayload(data, rend.PixelFormat)
		if err != nil {
			return err
		}
		return a.setOriginalPayload(rend, payload)
	case "\x00\x00\x00\x00":
		switch header.Metadata.Layout {
		case OnePart, ThreePartHorizontal, ThreePartVertical, NinePart, TwelvePart, ManyPart, Gradient, Effect, Animation, Vector, IconImage, RawData, ExternalLink, ImageStack:
			return fmt.Errorf("%w layout: %s", errUnsupportedRendition, header.Metadata.Layout)
		case PackedImage, NamedContents, ThinningPlaceholder, TextureRendition, TextureImage:
			return fmt.Errorf("%w layout: %s", errUnsupportedRendition, header.Metadata.Layout)
		case Color:
			var c csiColor
			if err := binary.Read(vr, binary.LittleEndian, &c.Signature); err != nil {
				return fmt.Errorf("failed to read rendition color signature: %v", err)
			}
			if err := binary.Read(vr, binary.LittleEndian, &c.Version); err != nil {
				return fmt.Errorf("failed to read rendition color version: %v", err)
			}
			if err := binary.Read(vr, binary.LittleEndian, &c.Info); err != nil {
				return fmt.Errorf("failed to read rendition color info: %v", err)
			}
			if err := binary.Read(vr, binary.LittleEndian, &c.NumberOfComponents); err != nil {
				return fmt.Errorf("failed to read rendition color number of components: %v", err)
			}
			if uint64(c.NumberOfComponents)*8 > uint64(vr.Len()) {
				return fmt.Errorf("color components exceed payload")
			}
			c.Components = make([]float64, c.NumberOfComponents)
			if err := binary.Read(vr, binary.LittleEndian, &c.Components); err != nil {
				return fmt.Errorf("failed to read rendition color components: %v", err)
			}
			if c.Info.ColorType() == SystemColorFollows {
				var sysc csiSystemColorName
				if err := binary.Read(vr, binary.LittleEndian, &sysc.Signature); err != nil {
					return fmt.Errorf("failed to read rendition system color signature: %v", err)
				}
				if err := binary.Read(vr, binary.LittleEndian, &sysc.Version); err != nil {
					return fmt.Errorf("failed to read rendition system color version: %v", err)
				}
				if err := binary.Read(vr, binary.LittleEndian, &sysc.Length); err != nil {
					return fmt.Errorf("failed to read rendition system color name length: %v", err)
				}
				if uint64(sysc.Length) > uint64(vr.Len()) {
					return fmt.Errorf("system color name exceeds payload")
				}
			}
			rend.Asset = c
		case MultiSizeImageSet:
			var msi csiMultisizeImageSet
			if err := binary.Read(vr, binary.LittleEndian, &msi.Signature); err != nil {
				return err
			}
			if err := binary.Read(vr, binary.LittleEndian, &msi.Version); err != nil {
				return err
			}
			if err := binary.Read(vr, binary.LittleEndian, &msi.NImageSizes); err != nil {
				return err
			}
			if uint64(msi.NImageSizes)*uint64(binary.Size(csiMultiImgSetImageSize{})) > uint64(vr.Len()) {
				return fmt.Errorf("image sizes exceed payload")
			}
			msi.ImageSizes = make([]csiMultiImgSetImageSize, msi.NImageSizes)
			if err := binary.Read(vr, binary.LittleEndian, &msi.ImageSizes); err != nil {
				return err
			}
			rend.Asset = msi
		case ModelIOAsset, ModelMesh, RecognitionGroup, RecognitionObject, ModelIOSubmesh, VectorGlyph, SolidImageStack, IconImageStack, IconGroup:
			return fmt.Errorf("%w layout: %s", errUnsupportedRendition, header.Metadata.Layout)

		default:
			return fmt.Errorf("%w layout: %d", errUnsupportedRendition, header.Metadata.Layout)
		}
	default:
		return fmt.Errorf("%w pixel format: %q", errUnsupportedRendition, rend.PixelFormat)
	}
	return nil
}

// setOriginalPayload keeps the original bytes unless rasterization is requested.
func (a *Asset) setOriginalPayload(rend *Rendition, data []byte) error {
	rend.Asset = data
	format := renderedPayloadFormat(data, rend.PixelFormat)
	if a.conf == nil || !a.conf.Render || !isRenderableFormat(format) {
		return nil
	}
	img, err := render.Decode(data, format, int(rend.Width), int(rend.Height))
	if err != nil {
		return err
	}
	rend.Asset = img
	rend.ColorSpace = SRGB
	rend.Colorspace = SRGB.String()
	return nil
}

func (a *Asset) parseFacetKeys(bm *bom.BOM) error {
	if a.FacetKeyDB != nil {
		return nil
	}

	a.FacetKeyDB = make(map[string]renditionKeyToken)

	ftree, err := bm.ReadTrees("FACETKEYS")
	if err != nil {
		return fmt.Errorf("failed to read 'FACETKEYS' tree: %v", err)
	}

	for _, tree := range ftree {
		for _, item := range tree.Indices {
			var token renditionKeyToken
			if err := binary.Read(item.ValueReader, binary.LittleEndian, &token.CursorHotSpot); err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' cursor hotspot: %v", err)
			}
			if err := binary.Read(item.ValueReader, binary.LittleEndian, &token.NumberOfAttributes); err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' number of attributes: %v", err)
			}
			token.Attributes = make([]renditionAttribute, token.NumberOfAttributes)
			if err := binary.Read(item.ValueReader, binary.LittleEndian, &token.Attributes); err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' attributes: %v", err)
			}
			name, err := io.ReadAll(item.KeyReader)
			if err != nil {
				return fmt.Errorf("failed to read 'FACETKEYS' name: %v", err)
			}
			a.FacetKeyDB[string(name)] = token
		}
	}

	return nil
}

func (a *Asset) parseKeyFormat(bm *bom.BOM) error {
	if a.KeyFormat != nil {
		return nil
	}
	br, err := bm.ReadBlock("KEYFORMAT")
	if err != nil {
		if workaroundErr := a.parseKeyFormatWorkaround(bm); workaroundErr != nil {
			return fmt.Errorf("failed to read block 'KEYFORMAT': %v; fallback 'KEYFORMATWORKAROUND' parse failed: %v", err, workaroundErr)
		}
		return nil
	}
	var keyfmt RenditionKeyformat
	if err := binary.Read(br, binary.LittleEndian, &keyfmt.Tag); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' tag: %v", err)
	}
	if keyfmt.Tag != [4]byte{'t', 'm', 'f', 'k'} { // 'kfmt'
		return fmt.Errorf("invalid 'KEYFORMAT' tag: %s", keyfmt.Tag)
	}
	if err := binary.Read(br, binary.LittleEndian, &keyfmt.Version); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' version: %v", err)
	}
	if err := binary.Read(br, binary.LittleEndian, &keyfmt.MaximumRenditionKeyTokenCount); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' maximum rendition key token count: %v", err)
	}
	if keyfmt.MaximumRenditionKeyTokenCount == 0 || keyfmt.MaximumRenditionKeyTokenCount > 65536 {
		return fmt.Errorf("invalid KEYFORMAT token count: %d", keyfmt.MaximumRenditionKeyTokenCount)
	}
	a.KeyFormat = make([]renditionAttributeType, keyfmt.MaximumRenditionKeyTokenCount)
	if err := binary.Read(br, binary.LittleEndian, &a.KeyFormat); err != nil {
		return fmt.Errorf("failed to read 'KEYFORMAT' rendition attribute types: %v", err)
	}
	return validateKeyFormat(a.KeyFormat)
}

func (a *Asset) parseKeyFormatWorkaround(bm *bom.BOM) error {
	if a.KeyFormat != nil {
		return nil
	}
	br, err := bm.ReadBlock("KEYFORMATWORKAROUND")
	if err != nil {
		return fmt.Errorf("failed to read block 'KEYFORMATWORKAROUND': %v", err)
	}

	var maxTokenCount uint32
	if err := binary.Read(br, binary.LittleEndian, &maxTokenCount); err != nil {
		return fmt.Errorf("failed to read KEYFORMATWORKAROUND max token count: %v", err)
	}
	if maxTokenCount == 0 {
		return nil
	}
	if maxTokenCount > 65536 {
		return fmt.Errorf("invalid KEYFORMATWORKAROUND token count: %d", maxTokenCount)
	}

	a.KeyFormat = make([]renditionAttributeType, maxTokenCount)
	if err := binary.Read(br, binary.LittleEndian, &a.KeyFormat); err != nil {
		return fmt.Errorf("failed to read KEYFORMATWORKAROUND rendition attribute types: %v", err)
	}
	return validateKeyFormat(a.KeyFormat)
}

// TODO: this is gross
func readCSIFileHeader(r io.Reader) (*csiHeader, error) {
	var c csiHeader
	if err := binary.Read(r, binary.BigEndian, &c.Signature); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader signature: %v", err)
	}
	if c.Signature != CsiFileSignature {
		return nil, fmt.Errorf("invalid csiHeader signature: %v", c.Signature)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Version); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader version: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Flags); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader flags: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Width); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader width: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Height); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader height: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ScaleFactor); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader ppi: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.PixelFormat); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader pixel format: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ColorSpace); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader color space: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.Metadata); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader metadata: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ChainSize); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader chain size: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &c.ImageIndex.Count); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader image index count: %v", err)
	}
	if c.ImageIndex.Count > 4096 {
		return nil, fmt.Errorf("image index count exceeds limit: %d", c.ImageIndex.Count)
	}
	c.ImageIndex.AccumLength = make([]uint32, c.ImageIndex.Count+1)
	if err := binary.Read(r, binary.LittleEndian, &c.ImageIndex.AccumLength); err != nil {
		return nil, fmt.Errorf("failed to read csiHeader image index accum lengths: %v", err)
	}
	return &c, nil
}

func readString(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		return strings.Trim(scanner.Text(), "\x00"), nil
	}
	return "", scanner.Err()
}

func dumpTreeIndice(block string, item bom.TreeIndex) error {
	keyData, err := io.ReadAll(item.KeyReader)
	if err != nil {
		return fmt.Errorf("failed to read %s key: %v", block, err)
	}
	println(block + " KEY")
	println(hex.Dump(keyData))

	valueData, err := io.ReadAll(item.ValueReader)
	if err != nil {
		return fmt.Errorf("failed to read %s value: %v", block, err)
	}
	println(block + " VALUE")
	println(hex.Dump(valueData))

	return nil
}
