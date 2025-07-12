package car

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/comp"
	"github.com/blacktop/lzfse-cgo"
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
	return types.ExtractBits(uint64(f), 0, 1) == 1
}
func (f csiBitmapFlags) IsOpaque() bool {
	return types.ExtractBits(uint64(f), 1, 1) == 1
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

// csiElement also known as CUIThemePixelRendition
type csiElement struct {
	Signature [4]byte // CsiElementSignature - 'CELM'
	Version   uint32
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

type csiRawData struct {
	Signature [4]byte // 'RAWD'
	Flags     uint32
	Length    uint32
	// Data      []byte
}

type csiJpegLZFSEData struct {
	Version           uint32
	ChucksFollowing   uint32
	LzfseAlphaSize    uint32
	LzfseDataRowBytes uint32
	JpegDataSize      uint32
}

type csiASTCData struct {
	Version      uint32 // 0 == raw ATSC Data; 1 == lzfse compressed ATSC Data
	DataSize     uint32
	AstcDataSize uint32
	// Data      []byte
}

type csiHEVCData struct {
	Version      uint32
	HevcDataSize uint32
}

type csiDeepmapData struct {
	Version         uint32
	PixelFormat     uint32
	CompressedBytes uint64
}

type csiDeepmap2Data struct {
	Version  uint32
	Encoding compressionType
	Length   uint64
}

type deepmapPixelFormat uint8

const (
	ImageDeepmapPixelFormatG8      deepmapPixelFormat = 0x01
	ImageDeepmapPixelFormatGA8     deepmapPixelFormat = 0x02
	ImageDeepmapPixelFormatRGB8    deepmapPixelFormat = 0x03
	ImageDeepmapPixelFormatRGBA8   deepmapPixelFormat = 0x04
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

type deepmap2 struct {
	Signature         [4]byte // 'dmp2'
	Scale             uint8
	BlobVersion       uint8 // 1
	PixelFormat       deepmapPixelFormat
	CompressionMethod deepmapCompressionMethod
	Width             uint16
	Height            uint16
	CompressedBlock   uint32
}

// BGRA to RGBA
type BGRA struct {
	image.RGBA
}

func (p *BGRA) RGBAAt(x, y int) color.RGBA {
	c := p.RGBA.RGBAAt(x, y)
	return color.RGBA{R: c.B, G: c.G, B: c.R, A: c.A}
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
	s := p.Pix[i : i+2 : i+2] // Small cap improves performance, see https://golang.org/issue/27857
	return color.RGBA{s[0], s[0], s[0], s[1]}
}

func (p *GA8) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*2
}

func decodeImage(r io.Reader, ci csiHeader, conf *Config) (image.Image, error) {
	var out bytes.Buffer

	// f, err := os.Create(filepath.Join(conf.Output, fmt.Sprintf("%s", string(bytes.Trim(ci.Metadata.Name[:], "\x00")))))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create output file: %v", err)
	// }
	// defer f.Close()
	// io.Copy(f, r)

	// var elem csiElement
	var elem csiBitmap
	if err := binary.Read(r, binary.LittleEndian, &elem); err != nil {
		return nil, fmt.Errorf("failed to read CSIBitmap: %s", err)
	}

	// log.WithFields(log.Fields{
	// 	"signature": string(elem.Signature[:]),
	// 	"flags":     elem.Flags.String(),
	// 	"encoding":  elem.Encoding,
	// 	"length":    elem.Length,
	// }).Info("Reading CSIElement")

	if elem.Flags.ChunksFollow() {
		for i := uint32(0); i < elem.Length; i++ {
			var chunk csiBitmapChunk
			if err := binary.Read(r, binary.LittleEndian, &chunk); err != nil {
				return nil, err
			}
			if chunk.Signature != [4]byte{'K', 'C', 'B', 'C'} {
				return nil, fmt.Errorf("invalid chunk signature: %s", chunk.Signature)
			}
			data := make([]byte, chunk.Length)
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, err
			}
			switch elem.Encoding {
			case Uncompressed:
				out.Write(data)
			case RLE:
			case ZIP:
				gr, err := gzip.NewReader(bytes.NewReader(data))
				if err != nil {
					return nil, err
				}
				if _, err := io.Copy(&out, gr); err != nil {
					return nil, err
				}
			case LZVN:
				dec := make([]byte, len(data)*4)
				if n := lzfse.DecodeLZVNBuffer(data, dec); n == 0 {
					return nil, fmt.Errorf("failed to decompress lzvn data")
				} else {
					out.Write(dec[:n])
				}
			case LZFSE:
				decompressed, err := comp.Decompress(data, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
				}
				out.Write(decompressed)
			default:
				return nil, fmt.Errorf("unknown encoding: %s", elem.Encoding)
			}
		}
	} else {
		data := make([]byte, elem.Length)
		if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
			return nil, err
		}
		switch elem.Encoding {
		case Uncompressed:
			out.Write(data)
		case RLE:
		case ZIP:
			gr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(&out, gr); err != nil {
				return nil, err
			}
		case LZVN:
			dec := make([]byte, len(data)*4)
			if n := lzfse.DecodeLZVNBuffer(data, dec); n == 0 {
				return nil, fmt.Errorf("failed to decompress lzvn data")
			} else {
				out.Write(dec[:n])
			}
		case LZFSE:
			decompressed, err := comp.Decompress(data, comp.LZFSE)
			if err != nil {
				return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
			}
			out.Write(decompressed)
		case Deepmap2:
			// os.WriteFile(fmt.Sprintf("%s.compressed.%s", string(bytes.Trim(ci.Metadata.Name[:], "\x00")), bm.Encoding), data, 0644)
			dmr := bytes.NewReader(data)
			var cdm2 csiDeepmap2Data
			if err := binary.Read(dmr, binary.LittleEndian, &cdm2); err != nil {
				return nil, err
			}
			log.WithFields(log.Fields{
				"version":  cdm2.Version,
				"encoding": cdm2.Encoding,
				"length":   cdm2.Length,
			}).Info("Reading Deepmap2 Data")
			var dm2 deepmap2
			if err := binary.Read(dmr, binary.LittleEndian, &dm2); err != nil {
				return nil, err
			}
			if dm2.Signature != [4]byte{'d', 'm', 'p', '2'} {
				return nil, fmt.Errorf("invalid deepmap2 signature: %s", dm2.Signature)
			}
			log.WithFields(log.Fields{
				"signature":          string(dm2.Signature[:]),
				"blob_version":       dm2.BlobVersion,
				"pixel_format":       dm2.PixelFormat,
				"compression_method": dm2.CompressionMethod,
				"width":              dm2.Width,
				"height":             dm2.Height,
				"scale":              dm2.Scale,
				"compressed_block":   dm2.CompressedBlock,
			}).Warn("Reading Deepmap2")
			if dm2.BlobVersion != 1 {
				return nil, fmt.Errorf("unsupported deepmap2 blob version: %d", dm2.BlobVersion)
			}
			switch cdm2.Encoding {
			case LZFSE, ZIP:
				if dmr.Len() < int(dm2.CompressedBlock) {
					fname := fmt.Sprintf("%s.compressed.%s", string(bytes.Trim(ci.Metadata.Name[:], "\x00")), cdm2.Encoding)
					fname = filepath.Join(conf.Output, fname)
					log.Errorf("deepmap2 compressed block size %d is larger than remaining data %d, writing to %s", dm2.CompressedBlock, dmr.Len(), fname)
					os.WriteFile(fname, data, 0644)
					return nil, fmt.Errorf("deepmap2 compressed block size %d is larger than remaining data %d", dm2.CompressedBlock, dmr.Len())
				}
				chunck := make([]byte, dm2.CompressedBlock)
				if err := binary.Read(dmr, binary.LittleEndian, &chunck); err != nil {
					return nil, fmt.Errorf("failed to read deepmap2 compressed block: %v", err)
				}
				decompressed, err := comp.Decompress(chunck, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
				}
				out.Write(decompressed)
				for dmr.Len() > 0 {
					var size uint32
					if err := binary.Read(dmr, binary.LittleEndian, &size); err != nil {
						return nil, fmt.Errorf("failed to read deepmap2 block size: %v", err)
					}
					chunck = make([]byte, size)
					if err := binary.Read(dmr, binary.LittleEndian, &chunck); err != nil {
						return nil, fmt.Errorf("failed to read deepmap2 block data: %v", err)
					}
					decompressed, err = comp.Decompress(chunck, comp.LZFSE)
					if err != nil {
						return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
					}
					out.Write(decompressed)
				}
				if dmr.Len() > 0 {
					log.Warnf("deepmap2 reader still has %d bytes left after reading compressed block", dmr.Len())
				}
			// case ZIP:
			// 	chunck := make([]byte, dm2.CompressedBlock)
			// 	if err := binary.Read(dmr, binary.LittleEndian, &chunck); err != nil {
			// 		return nil, err
			// 	}
			// 	fname := fmt.Sprintf("%s.compressed.%s", string(bytes.Trim(ci.Metadata.Name[:], "\x00")), cdm2.Encoding)
			// 	os.WriteFile(fname, chunck, 0644)
			// 	gr, err := gzip.NewReader(bytes.NewReader(chunck))
			// 	if err != nil {
			// 		return nil, err
			// 	}
			// 	if _, err := io.Copy(&out, gr); err != nil {
			// 		return nil, err
			// 	}
			default:
				return nil, fmt.Errorf("unsupported deepmap2 encoding: %s", cdm2.Encoding)
			}
		default:
			return nil, fmt.Errorf("unknown encoding: %s", elem.Encoding)
		}
	}

	// os.WriteFile(fmt.Sprintf("%s.uncompressed", string(bytes.Trim(ci.Metadata.Name[:], "\x00"))), out.Bytes(), 0644)

	format := string(ci.PixelFormat[:])
	switch format {
	case PixFmtARGB:
		// Special handling for IconImage layout which uses channel-separated ARGB format
		if ci.Metadata.Layout == IconImage { // AppIcon renditionLayoutType
			return decodeAppIconARGB(out.Bytes(), int(ci.Width), int(ci.Height))
		}

		var offset int
		if v := out.Len() - int(ci.Width*ci.Height*4); v != 0 {
			offset = v / int(ci.Height*4)
		}
		if offset < 0 {
			return nil, errors.New("error image content")
		}
		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{
				X: int(ci.Width),
				Y: int(ci.Height),
			},
		}
		// rgba := image.NewRGBA(rect)
		// rgba.Pix = out.Bytes()
		// rgba.Stride = (rect.Dx() + offset) * 4
		// return rgba, nil
		bgra := &BGRA{image.RGBA{
			Pix:    out.Bytes(),
			Stride: (rect.Dx() + offset) * 4,
			Rect:   rect,
		}}
		return bgra, nil
	case PixFmtGray:
		var offset int
		if v := out.Len() - int(ci.Width*ci.Height*2); v != 0 {
			offset = v / int(ci.Height*2)
		}
		if offset < 0 {
			return nil, errors.New("error image content")
		}

		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{
				X: int(ci.Width),
				Y: int(ci.Height),
			},
		}
		bgra := &GA8{
			Pix:    out.Bytes(),
			Stride: (rect.Dx() + offset) * 2,
			Rect:   rect,
		}
		return bgra, nil
	default:
		return nil, fmt.Errorf("unknown pixel format: %s", format)
	}
}

// decodeAppIconARGB decodes AppIcon ARGB format where channels are separated
// Instead of interleaved ARGBARGBARGB, the data is stored as AAARRRGGGBBB
func decodeAppIconARGB(data []byte, width, height int) (image.Image, error) {
	pixelCount := width * height
	expectedSize := pixelCount * 4 // 4 bytes per pixel (ARGB)

	if len(data) < expectedSize {
		return nil, fmt.Errorf("insufficient data for AppIcon ARGB: got %d bytes, expected %d", len(data), expectedSize)
	}

	rect := image.Rectangle{
		Min: image.Point{0, 0},
		Max: image.Point{X: width, Y: height},
	}

	img := image.NewRGBA(rect)

	// Extract the separate channels
	// The format is: all alpha values, then all red, then all green, then all blue
	alphaChannel := data[0:pixelCount]
	redChannel := data[pixelCount : pixelCount*2]
	greenChannel := data[pixelCount*2 : pixelCount*3]
	blueChannel := data[pixelCount*3 : pixelCount*4]

	// Reconstruct interleaved RGBA pixels
	for i := 0; i < pixelCount; i++ {
		pixelIndex := i * 4
		img.Pix[pixelIndex+0] = redChannel[i]   // R
		img.Pix[pixelIndex+1] = greenChannel[i] // G
		img.Pix[pixelIndex+2] = blueChannel[i]  // B
		img.Pix[pixelIndex+3] = alphaChannel[i] // A
	}

	return img, nil
}
