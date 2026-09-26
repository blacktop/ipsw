package car

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"io"

	"github.com/blacktop/ipsw/pkg/car/deepmap2"
	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
	"github.com/blacktop/ipsw/pkg/car/texture"
)

const (
	PixFmtARGB    = "ARGB" // Color image
	PixFmtARGB16  = "RGBW" // Deep color image
	PixFmtRGB555  = "RGB5" // Packed 16-bit per pixel opaque image
	PixFmtGray    = "GA8 " // Gray scale image with alpha
	PixFmtGray16  = "GA16" // Deep gray scale image with alpha
	PixFmtPDF     = "PDF " // PDF raw bytes
	PixFmtJPEG    = "JPEG" // JPEG raw bytes
	PixFmtHEIF    = "HEIF" // HEIF raw bytes
	PixFmtRawData = "DATA" // Raw bytes
)

type compressionType uint32

const (
	Uncompressed compressionType = 0
	RLE          compressionType = 1
	ZIP          compressionType = 2
	LZVN         compressionType = 3
	LZFSE        compressionType = 4
	JPEGLZFSE    compressionType = 5
	BlurredImage compressionType = 6
	ASTCImage    compressionType = 7
	PaletteImage compressionType = 8
	HEVC         compressionType = 9
	DeepmapLZFSE compressionType = 10
	Deepmap2     compressionType = 11
	DXTC         compressionType = 12
)

type csiBitmapFlags uint32

func (f csiBitmapFlags) ChunksFollow() bool {
	return f&1 != 0
}
func (f csiBitmapFlags) IsOpaque() bool {
	return f&2 != 0
}
func (f csiBitmapFlags) String() string {
	return fmt.Sprintf("chunks_follow: %t, is_opaque: %t", f.ChunksFollow(), f.IsOpaque())
}

type csiBitmap struct {
	Signature [4]byte // 'PELM'
	Flags     csiBitmapFlags
	Encoding  compressionType
	Length    uint32
	// Data      []byte
}

type csiBitmapChunk struct {
	Signature [4]byte // 'PECH' PELM Chunk
	Flags     uint32  // always 0
	Version   uint32
	Rows      uint32
	Length    uint32
	// Data      []byte
}

type deepmapPixelFormat uint8

const (
	ImageDeepmapPixelFormatG8      deepmapPixelFormat = 0x01
	ImageDeepmapPixelFormatGA8     deepmapPixelFormat = 0x02
	ImageDeepmapPixelFormatRGB8    deepmapPixelFormat = 0x03
	ImageDeepmapPixelFormatRGBA8   deepmapPixelFormat = 0x04
	ImageDeepmapPixelFormatRGBA16  deepmapPixelFormat = 0x0A // 16-bit per channel RGBA
	ImageDeepmapPixelFormatG16F    deepmapPixelFormat = 0x11
	ImageDeepmapPixelFormatGA16F   deepmapPixelFormat = 0x12
	ImageDeepmapPixelFormatRGB16F  deepmapPixelFormat = 0x13
	ImageDeepmapPixelFormatRGBA16F deepmapPixelFormat = 0x14
)

type deepmapCompressionMethod uint8

const (
	ImageDeepmapCompressionNone     deepmapCompressionMethod = 1
	ImageDeepmapCompressionDefault  deepmapCompressionMethod = 2
	ImageDeepmapCompressionLossless deepmapCompressionMethod = 3
	ImageDeepmapCompressionPalette  deepmapCompressionMethod = 4
)

// BGRA to RGBA
type BGRA struct {
	image.RGBA
}

func (p *BGRA) RGBAAt(x, y int) color.RGBA {
	c := p.RGBA.RGBAAt(x, y)
	return color.RGBA{R: c.B, G: c.G, B: c.R, A: c.A}
}

func (p *BGRA) RGBA64At(x, y int) color.RGBA64 {
	c := p.RGBA.RGBA64At(x, y)
	return color.RGBA64{R: c.B, G: c.G, B: c.R, A: c.A}
}

func (p *BGRA) At(x, y int) color.Color {
	return p.RGBAAt(x, y)
}

func (p *BGRA) SubImage(r image.Rectangle) image.Image {
	c := p.RGBA.SubImage(r).(*image.RGBA)
	return &BGRA{*c}
}

type GA8 struct {
	Pix    []uint8
	Stride int
	Rect   image.Rectangle
}

func (p *GA8) ColorModel() color.Model { return color.RGBAModel }

func (p *GA8) Bounds() image.Rectangle { return p.Rect }

func (p *GA8) At(x, y int) color.Color {
	return p.GA8At(x, y)
}

func (p *GA8) GA8At(x, y int) color.RGBA {
	if !(image.Point{x, y}.In(p.Rect)) {
		return color.RGBA{}
	}
	i := p.PixOffset(x, y)
	if i+2 > len(p.Pix) {
		return color.RGBA{}
	}
	s := p.Pix[i : i+2 : i+2] // Small cap improves performance, see https://golang.org/issue/27857
	return color.RGBA{s[0], s[0], s[0], s[1]}
}

func (p *GA8) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*2
}

// decodeImage dispatches CoreUI bitmap compression after validating its framing.
func decodeImage(r io.Reader, ci csiHeader, conf *Config, rowBytesOverride int) (image.Image, error) {
	width, height := int(ci.Width), int(ci.Height)
	if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
		return nil, err
	}
	data, err := compression.ReadLimited(r, pixel.MaxBytes)
	if err != nil {
		return nil, err
	}
	elem, chunks, err := readCSIBitmap(data)
	if err != nil {
		return nil, err
	}
	format, opaque := string(ci.PixelFormat[:]), elem.Flags.IsOpaque()
	space := ci.ColorSpace.ColorSpaceID()
	switch elem.Encoding {
	case Deepmap2, DeepmapLZFSE, PaletteImage, ASTCImage, DXTC:
		return assembleBitmapChunks(chunks, width, height, func(data []byte, rows int) (image.Image, error) {
			switch elem.Encoding {
			case Deepmap2:
				return deepmap2.Decode(data, width, rows, format, space == ExtendedSRGB || space == ExtendedLinear, opaque)
			case DeepmapLZFSE:
				return deepmap2.DecodeLegacy(data, width, rows, format, space == ExtendedSRGB || space == ExtendedLinear, opaque)
			case PaletteImage:
				return decodePaletteImage(data, width, rows, format, space, opaque)
			case ASTCImage:
				decoder := ""
				if conf != nil {
					decoder = conf.ASTCDecoder
				}
				return texture.DecodeASTC(data, width, rows, decoder, space == ExtendedLinear, opaque)
			default:
				return texture.DecodeDXTC(data, width, rows, opaque)
			}
		})
	case JPEGLZFSE:
		if format != PixFmtARGB {
			return nil, fmt.Errorf("%w: JPEG+LZFSE pixel format %q", errUnsupportedRendition, format)
		}
		return decodeJPEGLZFSE(chunks, width, height, opaque)
	case HEVC, BlurredImage:
		return nil, fmt.Errorf("%w: pixel decoding %s", errUnsupportedRendition, elem.Encoding)
	}
	bpp, err := pixelSize(format)
	if err != nil {
		return nil, err
	}
	stride, _, err := pixel.Layout(width, height, bpp, rowBytesOverride)
	if err != nil {
		return nil, err
	}
	limit := stride * height
	var out []byte
	rleRows := 0
	for _, chunk := range chunks {
		var part []byte
		if elem.Encoding == RLE {
			rows := int(chunk.rows)
			if rows == 0 && len(chunks) == 1 {
				rows = height
			}
			if rows <= 0 || rows > height-rleRows {
				return nil, fmt.Errorf("invalid RLE chunk height: %d", rows)
			}
			part, err = decodeRLERows(chunk.data, width, rows, stride, format)
			rleRows += rows
		} else {
			chunkLimit := limit - len(out)
			if elem.Encoding == LZVN && len(chunks) > 1 {
				if chunk.rows == 0 || uint64(chunk.rows)*uint64(stride) > uint64(chunkLimit) {
					return nil, fmt.Errorf("invalid LZVN chunk height")
				}
				chunkLimit = int(chunk.rows) * stride
			}
			part, err = decodeBitmapBytes(chunk.data, elem.Encoding, chunkLimit)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	if elem.Encoding == RLE && rleRows != height {
		return nil, fmt.Errorf("RLE chunks contain %d rows, expected %d", rleRows, height)
	}
	if format == PixFmtARGB16 && (space == ExtendedSRGB || space == ExtendedLinear) {
		return pixel.DecodeHalfFloatRGBA(out, width, height, rowBytesOverride, opaque)
	}
	return decodePixels(out, width, height, format, rowBytesOverride, opaque)
}

// assembleBitmapChunks keeps the decoder's sample precision, including 16-bit
// straight alpha. A single chunk needs no extra image allocation.
func assembleBitmapChunks(chunks []bitmapChunk, width, height int, decode func([]byte, int) (image.Image, error)) (image.Image, error) {
	var dst draw.Image
	y := 0
	for _, chunk := range chunks {
		rows := int(chunk.rows)
		if rows == 0 && len(chunks) == 1 {
			rows = height
		}
		if rows <= 0 || rows > height-y {
			return nil, fmt.Errorf("invalid bitmap chunk height: %d", rows)
		}
		img, err := decode(chunk.data, rows)
		if err != nil {
			return nil, err
		}
		if img.Bounds().Dx() != width || img.Bounds().Dy() != rows {
			return nil, fmt.Errorf("decoded chunk dimensions do not match CSI")
		}
		if len(chunks) == 1 && rows == height {
			return img, nil
		}
		wide := img.ColorModel() == color.RGBA64Model || img.ColorModel() == color.NRGBA64Model || img.ColorModel() == color.Gray16Model
		if dst == nil || (wide && dst.ColorModel() != color.NRGBA64Model && dst.ColorModel() != color.RGBA64Model) {
			bpp := 4
			if wide {
				bpp = 8
			}
			if _, _, err := pixel.Layout(width, height, bpp, 0); err != nil {
				return nil, err
			}
			previous := dst
			if wide && img.ColorModel() == color.RGBA64Model {
				dst = image.NewRGBA64(image.Rect(0, 0, width, height))
			} else if wide {
				dst = image.NewNRGBA64(image.Rect(0, 0, width, height))
			} else {
				dst = image.NewRGBA(image.Rect(0, 0, width, height))
			}
			if previous != nil {
				draw.Draw(dst, image.Rect(0, 0, width, y), previous, image.Point{}, draw.Src)
			}
		}
		draw.Draw(dst, image.Rect(0, y, width, y+rows), img, img.Bounds().Min, draw.Src)
		y += rows
	}
	if y != height {
		return nil, fmt.Errorf("bitmap chunks contain %d rows, expected %d", y, height)
	}
	return dst, nil
}
