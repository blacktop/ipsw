package car

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-termimg"
)

type CSISignature uint32

const (
	CsiFileSignature              CSISignature = 0x49535443 // "CTSI"
	CsiElementSignature           CSISignature = 0x4D4C4543 // "CELM"
	CsiBitmapChunkSignature       CSISignature = 0x4B434243 // "CBCK"
	CsiGradientSignature          CSISignature = 0x44415247 // "GRAD"
	CsiEffectDataSignature        CSISignature = 0x58465443 // "CTFX"
	CsiRawDataSignature           CSISignature = 0x44574152 // "RAWD"
	CsiExternalLinkSignature      CSISignature = 0x4B4C5845 // "EXLK"
	CsiInternalLinkSignature      CSISignature = 0x4B4C4E49 // "INLK"
	CsiTextureDataSignature       CSISignature = 0x52545854 // "TXTR"
	CsiColorSignature             CSISignature = 0x524C4F43 // "COLR"
	CsiMultisizeImageSetSignature CSISignature = 0x5349534D // "MSIS"
)

func (s CSISignature) String() string {
	switch s {
	case CsiFileSignature:
		return "FileSignature"
	case CsiElementSignature:
		return "ElementSignature"
	case CsiBitmapChunkSignature:
		return "BitmapChunkSignature"
	case CsiGradientSignature:
		return "GradientSignature"
	case CsiEffectDataSignature:
		return "EffectDataSignature"
	case CsiRawDataSignature:
		return "RawDataSignature"
	case CsiExternalLinkSignature:
		return "ExternalLinkSignature"
	case CsiInternalLinkSignature:
		return "InternalLinkSignature"
	case CsiTextureDataSignature:
		return "TextureDataSignature"
	case CsiColorSignature:
		return "ColorSignature"
	case CsiMultisizeImageSetSignature:
		return "MultisizeImageSetSignature"
	default:
		return fmt.Sprintf("unknown(%#x)", uint32(s))
	}
}

type renditionFlags uint32

func (f renditionFlags) IsVectorBased() bool {
	return types.ExtractBits(uint64(f), 0, 1) == 1
}
func (f renditionFlags) IsOpaque() bool {
	return types.ExtractBits(uint64(f), 1, 1) == 1
}
func (f renditionFlags) BitmapEncoding() compressionType {
	return compressionType(types.ExtractBits(uint64(f), 2, 4))
}
func (f renditionFlags) OptOutOfThinning() bool {
	return types.ExtractBits(uint64(f), 6, 1) == 1
}
func (f renditionFlags) IsFlippable() bool {
	return types.ExtractBits(uint64(f), 7, 1) == 1
}
func (f renditionFlags) IsTintable() bool {
	return types.ExtractBits(uint64(f), 8, 1) == 1
}
func (f renditionFlags) PreservedVectorRepresentation() bool {
	return types.ExtractBits(uint64(f), 9, 1) == 1
}
func (f renditionFlags) PreserveForArchiveOnly() bool {
	return types.ExtractBits(uint64(f), 10, 1) == 1
}
func (f renditionFlags) String() string {
	return fmt.Sprintf(
		"Flags:\n"+
			"  is_vector_based:                 %t\n"+
			"  is_opaque:                       %t\n"+
			"  bitmap_encoding:                 %s\n"+
			"  opt_out_of_thinning:             %t\n"+
			"  is_flippable:                    %t\n"+
			"  is_tintable:                     %t\n"+
			"  preserved_vector_representation: %t\n"+
			"  preserve_for_archive_only:       %t",
		f.IsVectorBased(),
		f.IsOpaque(),
		f.BitmapEncoding(),
		f.OptOutOfThinning(),
		f.IsFlippable(),
		f.IsTintable(),
		f.PreservedVectorRepresentation(),
		f.PreserveForArchiveOnly(),
	)
}

type colorSpaceID uint32

const (
	Generic colorSpaceID = iota
	SRGB
	Mono
	DisplayP3
	ExtendedSRGB
	ExtendedLinear
	ExtendedGray
)

func (c colorSpaceID) String() string {
	switch c {
	case Generic:
		return "Generic"
	case SRGB:
		return "sRGB"
	case Mono:
		return "Generic Gray Gamma 2.2"
	case DisplayP3:
		return "Display P3"
	case ExtendedSRGB:
		return "Extended sRGB"
	case ExtendedLinear:
		return "Extended Linear sRGB"
	case ExtendedGray:
		return "Extended Gray"
	default:
		return "Unknown"
	}
}

type csiColorSpace uint32

func (c csiColorSpace) ColorSpaceID() colorSpaceID {
	return colorSpaceID(types.ExtractBits(uint64(c), 0, 4))
}

type csiMetaData struct {
	Modtime    uint32
	Layout     renditionLayoutType
	Generation uint16
	Name       [128]byte
}

type csiBitmapList struct {
	Count       uint32
	AccumLength []uint32
}

type csiHeaderFlags uint32

const (
	CSIAssetIsFPO                         csiHeaderFlags = (1 << 0)
	CSIAssetIsExcludedFromFilter          csiHeaderFlags = (1 << 1)
	CSIAssetIsVectorBased                 csiHeaderFlags = (1 << 2)
	CSIAssetIsTemplate                    csiHeaderFlags = (1 << 3)
	CSIAssetIsTemplateAutomatic           csiHeaderFlags = (1 << 4)
	CSIAssetOptOutOfThinning              csiHeaderFlags = (1 << 5)
	CSIAssetIsFlippable                   csiHeaderFlags = (1 << 6)
	CSIAssetIsTintable                    csiHeaderFlags = (1 << 7)
	CSIAssetPreservedVectorRepresentation csiHeaderFlags = (1 << 8)
)

type csiHeader struct {
	Signature   CSISignature
	Version     uint32
	Flags       csiHeaderFlags
	Width       uint32
	Height      uint32
	ScaleFactor uint32 // 100 to @1x, 200 to @2x, 300 to @3x (0 is native rez)
	PixelFormat [4]byte
	ColorSpace  csiColorSpace
	Metadata    csiMetaData
	ChainSize   uint32
	ImageIndex  csiBitmapList
} // immediatly followed by a chain of resources

/* RESOURCE CHAIN */

type csiResource struct {
	ID     resourceID
	Length uint32
	Data   []byte
}

type resourceID uint32

const (
	SliceID                    resourceID = 1001
	SampleID                   resourceID = 1002
	MetricsID                  resourceID = 1003
	CompositingOptionsID       resourceID = 1004
	MetaDataID                 resourceID = 1005
	MetaDataEXIFOrientationID  resourceID = 1006
	ImageRowBytesID            resourceID = 1007
	ExternalLinkID             resourceID = 1008
	LayerReferenceDeprecatedID resourceID = 1009
	InternalLinkID             resourceID = 1010
	AlphaCroppingID            resourceID = 1011
	LayerReferenceID           resourceID = 1012
	PackedNamesID              resourceID = 1013
	TextureInterpretationID    resourceID = 1014
	PhysicalSizeID             resourceID = 1015
	RenditionPropertyID        resourceID = 1016
	TransformationID           resourceID = 1017

	// Unknown1ID resourceID = 1020
	// Unknown2ID resourceID = 1021
)

type sliceResource struct {
	NumSlices uint32
	Slices    []struct {
		X, Y, Width, Height uint32
	}
}

func (s *sliceResource) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &s.NumSlices); err != nil {
		return fmt.Errorf("failed to read NumSlices: %w", err)
	}
	s.Slices = make([]struct {
		X, Y          uint32
		Width, Height uint32
	}, s.NumSlices)
	for i := range s.Slices {
		if err := binary.Read(r, binary.LittleEndian, &s.Slices[i]); err != nil {
			return fmt.Errorf("failed to read Slice %d: %w", i, err)
		}
	}
	return nil
}

type sampleResource struct {
	NumSamples uint32
	Samples    []struct {
		A, R, G, B uint8
	}
}

func (s *sampleResource) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &s.NumSamples); err != nil {
		return fmt.Errorf("failed to read NumSamples: %w", err)
	}
	s.Samples = make([]struct {
		A, R, G, B uint8
	}, s.NumSamples)
	for i := range s.Samples {
		if err := binary.Read(r, binary.LittleEndian, &s.Samples[i]); err != nil {
			return fmt.Errorf("failed to read Sample %d: %w", i, err)
		}
	}
	return nil
}

type metricsResource struct {
	NumMetrics uint32
	Metrics    []struct {
		LeftInset, TopInset, RightInset, BottomInset, Width, Height int32
	}
}

func (m *metricsResource) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &m.NumMetrics); err != nil {
		return fmt.Errorf("failed to read NumMetrics: %w", err)
	}
	m.Metrics = make([]struct {
		LeftInset, TopInset, RightInset, BottomInset int32
		Width, Height                                int32
	}, m.NumMetrics)
	for i := range m.Metrics {
		if err := binary.Read(r, binary.LittleEndian, &m.Metrics[i]); err != nil {
			return fmt.Errorf("failed to read Metric %d: %w", i, err)
		}
	}
	return nil
}

type csiLayerReferenceFlags uint32

func (f csiLayerReferenceFlags) FixedFrame() bool {
	return (f & 1) != 0
}

type layerResource struct {
	NumLayers uint32
	Flags     uint32
	Layers    []struct {
		Flags csiLayerReferenceFlags
		Frame struct {
			X      int32
			Y      int32
			Width  uint32
			Height uint32
		}
		BlendMode uint32
		Opacity   float32
		Length    uint32
		Data      []byte
	}
}

func (l *layerResource) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &l.NumLayers); err != nil {
		return fmt.Errorf("failed to read NumLayers: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &l.Flags); err != nil {
		return fmt.Errorf("failed to read Flags: %w", err)
	}
	l.Layers = make([]struct {
		Flags csiLayerReferenceFlags
		Frame struct {
			X, Y          int32
			Width, Height uint32
		}
		BlendMode uint32
		Opacity   float32
		Length    uint32
		Data      []byte
	}, l.NumLayers)
	for i := range l.Layers {
		if err := binary.Read(r, binary.LittleEndian, &l.Layers[i].Flags); err != nil {
			return fmt.Errorf("failed to read Flags for layer %d: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &l.Layers[i].Frame); err != nil {
			return fmt.Errorf("failed to read Frame for layer %d: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &l.Layers[i].BlendMode); err != nil {
			return fmt.Errorf("failed to read BlendMode for layer %d: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &l.Layers[i].Opacity); err != nil {
			return fmt.Errorf("failed to read Opacity for layer %d: %w", i, err)
		}
		if err := binary.Read(r, binary.LittleEndian, &l.Layers[i].Length); err != nil {
			return fmt.Errorf("failed to read Length for layer %d: %w", i, err)
		}
		l.Layers[i].Data = make([]byte, l.Layers[i].Length)
		if _, err := r.Read(l.Layers[i].Data); err != nil {
			return fmt.Errorf("failed to read Data for layer %d: %w", i, err)
		}
	}
	return nil
}

type compositingResource struct {
	BlendMode uint32
	Opacity   float32
}

type metadataResourceFlags uint32

const (
	UtiType metadataResourceFlags = 1
)

type metadataResource struct {
	Length uint32
	Flags  metadataResourceFlags
	Data   []byte
}

func (m *metadataResource) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &m.Length); err != nil {
		return fmt.Errorf("failed to read Length: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &m.Flags); err != nil {
		return fmt.Errorf("failed to read Flags: %w", err)
	}
	m.Data = make([]byte, m.Length)
	if _, err := r.Read(m.Data); err != nil {
		return fmt.Errorf("failed to read Data: %w", err)
	}
	return nil
}

type csiColorType uint8

const (
	NoSystemColorFollows csiColorType = iota
	SystemColorFollows
)

type csiColorInfo uint32

func (c csiColorInfo) ColorSpaceID() colorSpaceID {
	return colorSpaceID(types.ExtractBits(uint64(c), 0, 8))
}
func (c csiColorInfo) ColorType() csiColorType {
	return csiColorType(types.ExtractBits(uint64(c), 8, 3))
}
func (c csiColorInfo) Reserved() uint8 {
	return uint8(types.ExtractBits(uint64(c), 11, 21))
}

type csiColor struct {
	Signature          [4]byte // CsiColorSignature
	Version            uint32
	Info               csiColorInfo
	NumberOfComponents uint32
	Components         []float64
}

func (c *csiColor) ToTerminal() (string, error) {
	var rgba color.RGBA

	switch len(c.Components) {
	case 2: // Grayscale: luminance and alpha
		gray := alpha(c.Components[0])
		rgba = color.RGBA{
			R: gray,
			G: gray,
			B: gray,
			A: alpha(c.Components[1]),
		}
	case 4: // RGBA
		rgba = color.RGBA{
			R: alpha(c.Components[0]),
			G: alpha(c.Components[1]),
			B: alpha(c.Components[2]),
			A: alpha(c.Components[3]),
		}
	default:
		return "", fmt.Errorf("unsupported color format: %d components", len(c.Components))
	}

	return colorInTerminal(rgba)
}

type CSIGradientDataFlags uint32

const (
	CSIGradientIsDithered CSIGradientDataFlags = (1 << 0)
)

type CUIPSDGradientStyle uint32

const (
	// CUIPSDGradientStyleLinear    CUIPSDGradientStyle = `Lnr `
	// CUIPSDGradientStyleRadial    CUIPSDGradientStyle = `Rdl `
	// CUIPSDGradientStyleSweep     CUIPSDGradientStyle = `Angl`
	// CUIPSDGradientStyleReflected CUIPSDGradientStyle = `Rflc`
	// CUIPSDGradientStyleDiamond   CUIPSDGradientStyle = `Dmnd`
	CUIPSDGradientStyleInvalid CUIPSDGradientStyle = 0
)

type csigradientdata struct {
	Signature            [4]byte // CsiGradientSignature
	Flags                CSIGradientDataFlags
	Length               uint32
	Style                CUIPSDGradientStyle
	Version              uint32
	BlendMode            uint32
	FillRed              float64
	FillGreen            float64
	FillBlue             float64
	FillAlpha            float64
	Angle                float64 // only valid if style is CUIPSDGradientStyleSweep
	Smoothing            float64 // only valid if style is CUIPSDGradientStyleLinear or CUIPSDGradientStyleRadial
	ColorStopCount       uint32
	ColorMidpointCount   uint32
	OpacityStopCount     uint32
	OpacityMidpointCount uint32
	// NodeList             []uint8
}

// TODO: this is probably wrong
type gradientStartStops struct {
	Start float32
	Stop  float32
}

// TODO: this is probably wrong
type gradientStop struct {
	Stop       float32
	NameLength uint32
	Name       []byte
}

type csiNamedGradient struct {
	Signature  [4]byte // 'GGRA'
	ColorCount uint32
	Type       uint64
	StartStops []gradientStartStops
	Stops      []gradientStop
}

type csiSystemColorName struct {
	Signature [4]byte // CsiColorSignature
	Version   uint32
	Length    uint32
	Name      []byte
}

type csiMultiImgSetImageSize struct {
	Width  uint32
	Height uint32
	Index  uint32 // only valid if version > 0
}

type csiMultisizeImageSet struct {
	Signature   [4]byte // CsiMultisizeImageSetSignature
	Version     uint32
	NImageSizes uint32
	ImageSizes  []csiMultiImgSetImageSize
}

type csiExternaLinkData struct {
	Signature          [4]byte // CsiExternalLinkSignature
	Flags              uint32
	NumberExternalTags uint32
	ElementList        []byte // TODO: how to parse this?
}

type linkRect struct {
	X      uint32
	Y      uint32
	Width  uint32
	Height uint32
}

type csiInternalLinkData struct {
	Signature CSISignature // CsiInternalLinkSignature
	Flags     uint32       // 0
	Frame     linkRect
	Layout    uint16 // 3Part, 9Part, etc
	Length    uint32
	Reference []renditionAttribute
}

func (l *csiInternalLinkData) UnmarshalBinary(r *bytes.Reader) error {
	if err := binary.Read(r, binary.BigEndian, &l.Signature); err != nil {
		return fmt.Errorf("failed to read Signature: %w", err)
	}
	if l.Signature != CsiInternalLinkSignature {
		return fmt.Errorf("invalid signature: expected %s, got %s", CsiInternalLinkSignature, l.Signature)
	}
	if err := binary.Read(r, binary.LittleEndian, &l.Flags); err != nil {
		return fmt.Errorf("failed to read Flags: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &l.Frame); err != nil {
		return fmt.Errorf("failed to read Frame: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &l.Layout); err != nil {
		return fmt.Errorf("failed to read Layout: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &l.Length); err != nil {
		return fmt.Errorf("failed to read Length: %w", err)
	}
	data := make([]byte, l.Length)
	if _, err := r.Read(data); err != nil {
		return fmt.Errorf("failed to read ReferenceData: %w", err)
	}
	l.Reference = make([]renditionAttribute, len(data)/binary.Size(renditionAttribute{}))
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &l.Reference); err != nil {
		return fmt.Errorf("failed to read rendition internal link references: %v", err)
	}
	if r.Len() > 0 {
		return fmt.Errorf("unexpected data remaining after reading csiInternalLinkData: %d bytes", r.Len())
	}
	return nil
}

type originalSize struct {
	Width  uint32
	Height uint32
}

type alphaCropFrame struct {
	X      uint32
	Y      uint32
	Width  uint32
	Height uint32
}

type csiAlphaCroppingData struct {
	Signature      [4]byte // ?
	Flags          uint32
	OriginalSize   originalSize
	alphaCropFrame alphaCropFrame
}

type mipLevelReference struct {
	Length        uint32 // length in bytes of token list, including null terminator
	Flags         uint32 // 0
	ReferenceData []byte // renditionAttribute token list referencing texture image
}

type cuiThemeTexturePixelFormat uint32

const (
	ThemeTexturePixelFormatInvalid        = 0
	ThemeTexturePixelFormatA8Unorm        = 1
	ThemeTexturePixelFormatR8Unorm        = 10
	ThemeTexturePixelFormatR8UnormSRgb    = 11
	ThemeTexturePixelFormatR8Snorm        = 12
	ThemeTexturePixelFormatR16Unorm       = 20
	ThemeTexturePixelFormatR16Snorm       = 22
	ThemeTexturePixelFormatR16Float       = 25
	ThemeTexturePixelFormatRg8Unorm       = 30
	ThemeTexturePixelFormatRg8UnormSRgb   = 31
	ThemeTexturePixelFormatRg8Snorm       = 32
	ThemeTexturePixelFormatR32Float       = 55
	ThemeTexturePixelFormatRg16Unorm      = 60
	ThemeTexturePixelFormatRg16Snorm      = 62
	ThemeTexturePixelFormatRg16Float      = 65
	ThemeTexturePixelFormatRgba8Unorm     = 70
	ThemeTexturePixelFormatRgba8UnormSRgb = 71
	ThemeTexturePixelFormatRgba8Snorm     = 72
	ThemeTexturePixelFormatBgra8Unorm     = 80
	ThemeTexturePixelFormatBgra8UnormSRgb = 81
	ThemeTexturePixelFormatRgb10A2Unorm   = 90
	ThemeTexturePixelFormatRg11B10Float   = 92
	ThemeTexturePixelFormatRgb9E5Float    = 93
	ThemeTexturePixelFormatBgra10XrSRgb   = 553
	ThemeTexturePixelFormatBgr10XrSRgb    = 555
	ThemeTexturePixelFormatRg32Float      = 105
	ThemeTexturePixelFormatRgba16Unorm    = 110
	ThemeTexturePixelFormatRgba16Snorm    = 112
	ThemeTexturePixelFormatRgba16Float    = 115
	ThemeTexturePixelFormatRgba32Float    = 125
	ThemeTexturePixelFormatAstc_4x4SRgb   = 186
	ThemeTexturePixelFormatAstc_8x8SRgb   = 194
	ThemeTexturePixelFormatAstc_4x4Ldr    = 204
	ThemeTexturePixelFormatAstc_8x8Ldr    = 212
)

type cuiThemeTextureType uint16

const (
	ThemeTextureType2D   = 1
	ThemeTextureTypeCube = 5
)

type csiTextureData struct {
	Signature     [4]byte // CsiTextureDataSignature
	Flags         uint32
	TextureFormat cuiThemeTexturePixelFormat
	TextureDepth  uint32 //  1
	ArrayLength   uint32 //  1
	TextureType   cuiThemeTextureType
	MipLevelCount uint16
	MipReferences []mipLevelReference
}

type csiEffectlist struct {
	Count       uint32
	AccumLength []uint32
}

type csiEffectData struct {
	Signature   [4]byte // CsiEffectDataSignature
	Version     uint32
	Flags       uint32
	_           uint32
	EffectIndex csiEffectlist
}

type cuiShapeEffectType [4]byte

const ( // TODO: convert these into uint32 ?
	ShapeEffectColorFill     = `Colr`
	ShapeEffectGradientFill  = `Grad`
	ShapeEffectInnerGlow     = `iGlw`
	ShapeEffectInnerShadow   = `inSh`
	ShapeEffectOuterGlow     = `oGlw`
	ShapeEffectDropShadow    = `Drop`
	ShapeEffectBevelEmboss   = `Embs`
	ShapeEffectExtraShadow   = `Xtra`
	ShapeEffectShapeOpacity  = `SOpc`
	ShapeEffectOutputOpacity = `Fade`
	ShapeEffectHueSaturation = `HueS`
)

type cuiShapeEffectParameter uint32

const (
	EffectParameterColor1 cuiShapeEffectParameter = iota
	EffectParameterColor2
	EffectParameterOpacity
	EffectParameterOpacity2
	EffectParameterBlurSize
	EffectParameterOffset
	EffectParameterAngle
	EffectParameterBlendMode
	EffectParameterSoftenSize
	EffectParameterSpread
	EffectParameterTintable
	EffectParameterBevelStyle
)

type csiEffectParameter struct {
	Name  cuiShapeEffectParameter
	Value any // can be float64, uint32 enum, uint16 angle (-180 to 180), or rgb color
}

type csiEffectParameterBlock struct {
	Type           cuiShapeEffectType
	ParameterCount uint32
	Parameters     []csiEffectParameter
}

func alpha(f float64) uint8 {
	if f >= 1 {
		return 255
	}
	return uint8(f * 256)
}

func colorInTerminal(c color.RGBA) (string, error) {
	width, height := 75, 75

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{c}, image.Point{}, draw.Src)

	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	if err := png.Encode(buf, img); err != nil {
		return "", fmt.Errorf("failed to encode color PNG file: %v", err)
	}
	buf.Flush()

	ti, err := termimg.From(bytes.NewReader(dat.Bytes()))
	if err != nil {
		return "", fmt.Errorf("failed to create terminal image: %v", err)
	}

	return ti.Render()
}

func createColorPNG(name string, c color.RGBA) error {
	colorFile, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create color.png file: %v", err)
	}
	width := 250
	height := 250
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.SetRGBA(x, y, c)
		}
	}
	if err := png.Encode(colorFile, img); err != nil {
		return fmt.Errorf("failed to encode color.png file: %v", err)
	}
	return nil
}
