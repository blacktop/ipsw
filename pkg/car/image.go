package car

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/magic"
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

type deepmap struct {
	Signature         [4]byte // 'dmap'
	CompressionMethod deepmapCompressionMethod
	Scale             uint8
	Unknown           uint8 // 10 ?
	PixelFormat       deepmapPixelFormat
	CompressedBlock   uint32
}

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

func decodeImage(r io.Reader, ci csiHeader, conf *Config, rowBytesOverride int) (image.Image, error) {
	var out bytes.Buffer
	// Track Deepmap2 origin and pixel format so we can render without BGRA swap
	fromDeepmap2 := false
	var deepmap2PixFmt deepmapPixelFormat

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
				out.Write(decodeRLE(data))
			case ZIP:
				// Try gzip first
				gr, err := gzip.NewReader(bytes.NewReader(data))
				if err == nil {
					if _, err := io.Copy(&out, gr); err != nil {
						return nil, fmt.Errorf("failed to decompress gzip: %v", err)
					}
				} else {
					// Try zlib
					zr, err := zlib.NewReader(bytes.NewReader(data))
					if err == nil {
						if _, err := io.Copy(&out, zr); err != nil {
							return nil, fmt.Errorf("failed to decompress zlib: %v", err)
						}
						zr.Close()
					} else {
						// Try raw deflate
						fr := flate.NewReader(bytes.NewReader(data))
						if _, err := io.Copy(&out, fr); err != nil {
							// Last resort - assume uncompressed
							out.Write(data)
						}
						fr.Close()
					}
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
			case JPEGLZFSE:
				// JPEG with LZFSE-compressed alpha channel
				var jpegInfo csiJpegLZFSEData
				r := bytes.NewReader(data)
				if err := binary.Read(r, binary.LittleEndian, &jpegInfo); err != nil {
					return nil, fmt.Errorf("failed to read JPEGLZFSE header: %v", err)
				}
				// Skip the JPEG data for now and decompress the alpha channel
				jpegData := make([]byte, jpegInfo.JpegDataSize)
				if err := binary.Read(r, binary.LittleEndian, &jpegData); err != nil {
					return nil, fmt.Errorf("failed to read JPEG data: %v", err)
				}
				if jpegInfo.LzfseAlphaSize > 0 {
					alphaData := make([]byte, jpegInfo.LzfseAlphaSize)
					if err := binary.Read(r, binary.LittleEndian, &alphaData); err != nil {
						return nil, fmt.Errorf("failed to read alpha data: %v", err)
					}
					// Decompress alpha channel
					decompressed, err := comp.Decompress(alphaData, comp.LZFSE)
					if err != nil {
						return nil, fmt.Errorf("failed to decompress JPEGLZFSE alpha: %v", err)
					}
					// For now, just output the decompressed alpha
					out.Write(decompressed)
				} else {
					// No alpha channel, just JPEG
					out.Write(jpegData)
				}
			case HEVC:
				// HEVC/H.265 video data
				var hevcInfo csiHEVCData
				r := bytes.NewReader(data)
				if err := binary.Read(r, binary.LittleEndian, &hevcInfo); err != nil {
					return nil, fmt.Errorf("failed to read HEVC header: %v", err)
				}
				// Read the HEVC data
				hevcData := make([]byte, hevcInfo.HevcDataSize)
				if err := binary.Read(r, binary.LittleEndian, &hevcData); err != nil {
					return nil, fmt.Errorf("failed to read HEVC data: %v", err)
				}
				// Output raw HEVC data (would need HEVC decoder for actual image)
				out.Write(hevcData)
			case PaletteImage:
				// Magic byte detection for compression format
				if len(data) >= 4 {
					magic := data[0:4]
					if string(magic) == "lzvn" || (len(data) >= 4 && magic[0] == 0x68 && magic[1] == 0x01 && magic[2] == 0x00 && magic[3] == 0xf0) {
						// LZVN compressed palette image
						dec := make([]byte, len(data)*4)
						if n := lzfse.DecodeLZVNBuffer(data, dec); n == 0 {
							return nil, fmt.Errorf("failed to decompress PaletteImage LZVN data")
						} else {
							out.Write(dec[:n])
						}
					} else {
						// Raw palette image data
						out.Write(data)
					}
				} else {
					out.Write(data)
				}
			case ASTCImage:
				// ASTC texture compression
				var astcInfo csiASTCData
				r := bytes.NewReader(data)
				if err := binary.Read(r, binary.LittleEndian, &astcInfo); err != nil {
					return nil, fmt.Errorf("failed to read ASTC header: %v", err)
				}
				// Read the ASTC data
				astcData := make([]byte, astcInfo.AstcDataSize)
				if err := binary.Read(r, binary.LittleEndian, &astcData); err != nil {
					return nil, fmt.Errorf("failed to read ASTC data: %v", err)
				}
				if astcInfo.Version == 1 {
					// LZFSE compressed ASTC data
					decompressed, err := comp.Decompress(astcData, comp.LZFSE)
					if err != nil {
						return nil, fmt.Errorf("failed to decompress ASTC data: %v", err)
					}
					out.Write(decompressed)
				} else {
					// Raw ASTC data
					out.Write(astcData)
				}
			case DeepmapLZFSE:
				// Deepmap with LZFSE compression
				var deepmapInfo csiDeepmapData
				r := bytes.NewReader(data)
				if err := binary.Read(r, binary.LittleEndian, &deepmapInfo); err != nil {
					return nil, fmt.Errorf("failed to read Deepmap header: %v", err)
				}
				log.WithFields(log.Fields{
					"version":          deepmapInfo.Version,
					"pixel_format":     deepmapInfo.PixelFormat,
					"compressed_bytes": deepmapInfo.CompressedBytes,
				}).Debug("Reading Deepmap")
				// Read the deepmap structure header
				var dm deepmap
				if err := binary.Read(r, binary.LittleEndian, &dm); err != nil {
					return nil, fmt.Errorf("failed to read deepmap structure: %v", err)
				}
				if dm.Signature != [4]byte{'d', 'm', 'a', 'p'} {
					return nil, fmt.Errorf("invalid deepmap signature: %s", dm.Signature)
				}
				// Read the compressed data
				compressedData := make([]byte, dm.CompressedBlock)
				if err := binary.Read(r, binary.LittleEndian, &compressedData); err != nil {
					return nil, fmt.Errorf("failed to read Deepmap compressed data: %v", err)
				}
				log.WithFields(log.Fields{
					"signature":          string(dm.Signature[:]),
					"compression_method": dm.CompressionMethod,
					"scale":              dm.Scale,
					"pixel_format":       dm.PixelFormat,
					"compressed_block":   dm.CompressedBlock,
				}).Debug("Reading Deepmap")
				if isLZFSE, _ := magic.IsLZFSE(compressedData); isLZFSE {
					// Decompress the data
					decompressed, err := comp.Decompress(compressedData, comp.LZFSE)
					if err != nil {
						return nil, fmt.Errorf("failed to decompress DeepmapLZFSE data: %v", err)
					}
					out.Write(decompressed)
				} else {
					out.Write(compressedData)
				}
				// switch dm.CompressionMethod {
				// case ImageDeepmapCompressionDefault:
				// 	// Decompress the data
				// 	decompressed, err := comp.Decompress(compressedData, comp.LZFSE)
				// 	if err != nil {
				// 		return nil, fmt.Errorf("failed to decompress DeepmapLZFSE data: %v", err)
				// 	}
				// 	out.Write(decompressed)
				// case ImageDeepmapCompressionNone:
				// 	out.Write(compressedData)
				// default:
				// 	out.Write(compressedData)
				// 	// return nil, fmt.Errorf("unsupported deepmap compression method: %d", dm.CompressionMethod)
				// }
			case Deepmap2:
				// Handle Deepmap2 inside chunk stream
				rdm := bytes.NewReader(data)
				var cdm2 csiDeepmap2Data
				if err := binary.Read(rdm, binary.LittleEndian, &cdm2); err != nil {
					return nil, err
				}
				var dm2 deepmap2
				if err := binary.Read(rdm, binary.LittleEndian, &dm2); err != nil {
					return nil, err
				}
				if dm2.Signature != [4]byte{'d', 'm', 'p', '2'} {
					return nil, fmt.Errorf("invalid deepmap2 signature: %s", dm2.Signature)
				}
				// Override CSI header dims/pixfmt to match deepmap2 payload
				ci.Width = uint32(dm2.Width)
				ci.Height = uint32(dm2.Height)
				fromDeepmap2 = true
				deepmap2PixFmt = dm2.PixelFormat
				switch dm2.PixelFormat {
				case ImageDeepmapPixelFormatRGBA16:
					copy(ci.PixelFormat[:], "RGBW")
				case ImageDeepmapPixelFormatRGBA8:
					copy(ci.PixelFormat[:], "ARGB")
				case ImageDeepmapPixelFormatGA8:
					copy(ci.PixelFormat[:], "GA8 ")
				default:
					// Assume 8-bit RGBA when Deepmap2 pixel format is unknown
					copy(ci.PixelFormat[:], "ARGB")
				}
				// Gather compressed payload which may span multiple KCBC chunks
				compressed := make([]byte, int(dm2.CompressedBlock))
				readSoFar := 0
				if rdm.Len() > 0 {
					frag := make([]byte, rdm.Len())
					if _, err := io.ReadFull(rdm, frag); err == nil {
						copy(compressed[0:], frag)
						readSoFar += len(frag)
					}
				}
				// If not enough, consume following KCBC chunks from the outer reader 'r'
				extraChunks := uint32(0)
				for readSoFar < int(dm2.CompressedBlock) {
					var next csiBitmapChunk
					if err := binary.Read(r, binary.LittleEndian, &next); err != nil {
						return nil, fmt.Errorf("failed to continue deepmap2 payload: %v", err)
					}
					if next.Signature != [4]byte{'K', 'C', 'B', 'C'} {
						return nil, fmt.Errorf("unexpected chunk while continuing deepmap2 payload: %s", next.Signature)
					}
					buf := make([]byte, next.Length)
					if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
						return nil, fmt.Errorf("failed to read continuation chunk: %v", err)
					}
					remain := int(dm2.CompressedBlock) - readSoFar
					toCopy := remain
					if len(buf) < toCopy {
						toCopy = len(buf)
					}
					copy(compressed[readSoFar:readSoFar+toCopy], buf[:toCopy])
					readSoFar += toCopy
					extraChunks++
				}
				// Skip accounting for consumed chunks in the outer loop
				i += extraChunks
				// Palette compression carries a palette before an LZFSE block; decode directly to image
				if dm2.CompressionMethod == ImageDeepmapCompressionPalette {
					magic := []byte("bvx2")
					pos := bytes.Index(compressed, magic)
					if pos > 0 {
						palette := compressed[:pos]
						indicesCompressed := compressed[pos:]
						decomp, err := comp.Decompress(indicesCompressed, comp.LZFSE)
						if err == nil {
							// Compose [palette][indices] and decode
							combo := append([]byte{}, append(palette, decomp...)...)
							if palImg, err := decodePalettedImage(combo, int(ci.Width), int(ci.Height)); err == nil {
								return palImg, nil
							}
						}
					}
				}
				switch cdm2.Encoding {
				case LZFSE:
					if isLZFSE, _ := magic.IsLZFSE(compressed); isLZFSE {
						decompressed, err := comp.Decompress(compressed, comp.LZFSE)
						if err != nil {
							return nil, fmt.Errorf("failed to decompress Deepmap2 LZFSE data: %v", err)
						}
						out.Write(decompressed)
					} else {
						// Some payloads are raw when marked LZFSE
						out.Write(compressed)
					}
				case ZIP:
					if isLZFSE, _ := magic.IsLZFSE(compressed); isLZFSE {
						decompressed, err := comp.Decompress(compressed, comp.LZFSE)
						if err != nil {
							return nil, fmt.Errorf("failed to decompress Deepmap2 LZFSE-as-ZIP data: %v", err)
						}
						out.Write(decompressed)
						break
					}
					if gr, err := gzip.NewReader(bytes.NewReader(compressed)); err == nil {
						if _, err := io.Copy(&out, gr); err != nil {
							return nil, fmt.Errorf("failed to decompress gzip data: %v", err)
						}
					} else if zr, err := zlib.NewReader(bytes.NewReader(compressed)); err == nil {
						if _, err := io.Copy(&out, zr); err != nil {
							return nil, fmt.Errorf("failed to decompress zlib data: %v", err)
						}
						zr.Close()
					} else {
						fr := flate.NewReader(bytes.NewReader(compressed))
						if _, err := io.Copy(&out, fr); err != nil {
							// Assume raw on failure
							out.Write(compressed)
						}
						fr.Close()
					}
				case Deepmap2:
					// Nested Deepmap2 often uses LZFSE after a small header
					if len(data) > 16 {
						decompressed, err := comp.Decompress(data[16:], comp.LZFSE)
						if err != nil {
							return nil, fmt.Errorf("failed to decompress nested Deepmap2: %v", err)
						}
						out.Write(decompressed)
					} else {
						out.Write(compressed)
					}
				default:
					return nil, fmt.Errorf("unsupported deepmap2 encoding: %s", cdm2.Encoding)
				}
			default:
				return nil, fmt.Errorf("unknown encoding: %s (value: %d)", elem.Encoding, elem.Encoding)
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
			out.Write(decodeRLE(data))
		case ZIP:
			// Try gzip first
			gr, err := gzip.NewReader(bytes.NewReader(data))
			if err == nil {
				if _, err := io.Copy(&out, gr); err != nil {
					return nil, fmt.Errorf("failed to decompress gzip: %v", err)
				}
			} else {
				// Try zlib
				zr, err := zlib.NewReader(bytes.NewReader(data))
				if err == nil {
					if _, err := io.Copy(&out, zr); err != nil {
						return nil, fmt.Errorf("failed to decompress zlib: %v", err)
					}
					zr.Close()
				} else {
					// Try raw deflate
					fr := flate.NewReader(bytes.NewReader(data))
					if _, err := io.Copy(&out, fr); err != nil {
						// Last resort - assume uncompressed
						out.Write(data)
					}
					fr.Close()
				}
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
		case JPEGLZFSE:
			// JPEG with LZFSE-compressed alpha channel
			var jpegInfo csiJpegLZFSEData
			r := bytes.NewReader(data)
			if err := binary.Read(r, binary.LittleEndian, &jpegInfo); err != nil {
				return nil, fmt.Errorf("failed to read JPEGLZFSE header: %v", err)
			}
			// Skip the JPEG data for now and decompress the alpha channel
			jpegData := make([]byte, jpegInfo.JpegDataSize)
			if err := binary.Read(r, binary.LittleEndian, &jpegData); err != nil {
				return nil, fmt.Errorf("failed to read JPEG data: %v", err)
			}
			if jpegInfo.LzfseAlphaSize > 0 {
				alphaData := make([]byte, jpegInfo.LzfseAlphaSize)
				if err := binary.Read(r, binary.LittleEndian, &alphaData); err != nil {
					return nil, fmt.Errorf("failed to read alpha data: %v", err)
				}
				// Decompress alpha channel
				decompressed, err := comp.Decompress(alphaData, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress JPEGLZFSE alpha: %v", err)
				}
				// For now, just output the decompressed alpha
				out.Write(decompressed)
			} else {
				// No alpha channel, just JPEG
				out.Write(jpegData)
			}
		case HEVC:
			// HEVC/H.265 video data
			var hevcInfo csiHEVCData
			r := bytes.NewReader(data)
			if err := binary.Read(r, binary.LittleEndian, &hevcInfo); err != nil {
				return nil, fmt.Errorf("failed to read HEVC header: %v", err)
			}
			// Read the HEVC data
			hevcData := make([]byte, hevcInfo.HevcDataSize)
			if err := binary.Read(r, binary.LittleEndian, &hevcData); err != nil {
				return nil, fmt.Errorf("failed to read HEVC data: %v", err)
			}
			// Output raw HEVC data (would need HEVC decoder for actual image)
			out.Write(hevcData)
		case ASTCImage:
			// ASTC texture compression
			var astcInfo csiASTCData
			r := bytes.NewReader(data)
			if err := binary.Read(r, binary.LittleEndian, &astcInfo); err != nil {
				return nil, fmt.Errorf("failed to read ASTC header: %v", err)
			}
			// Read the ASTC data
			astcData := make([]byte, astcInfo.AstcDataSize)
			if err := binary.Read(r, binary.LittleEndian, &astcData); err != nil {
				return nil, fmt.Errorf("failed to read ASTC data: %v", err)
			}
			if astcInfo.Version == 1 {
				// LZFSE compressed ASTC data
				decompressed, err := comp.Decompress(astcData, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress ASTC data: %v", err)
				}
				out.Write(decompressed)
			} else {
				// Raw ASTC data
				out.Write(astcData)
			}
		case PaletteImage:
			if isLZFSE, _ := magic.IsLZFSE(data); isLZFSE {
				// Decompress the data
				decompressed, err := comp.Decompress(data, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress DeepmapLZFSE data: %v", err)
				}
				out.Write(decompressed)
			} else {
				// Raw palette image data
				out.Write(data)
			}
			// After decompression, the data should contain palette indices
			// We'll handle this in the pixel format switch below
		case DeepmapLZFSE:
			// Deepmap with LZFSE compression
			var deepmapInfo csiDeepmapData
			r := bytes.NewReader(data)
			if err := binary.Read(r, binary.LittleEndian, &deepmapInfo); err != nil {
				return nil, fmt.Errorf("failed to read Deepmap header: %v", err)
			}
			// Debug: Save deepmap data for analysis (comment out in production)
			// df, err := os.Create("deepmap.data")
			// if err != nil {
			// 	return nil, fmt.Errorf("failed to create deepmap file: %v", err)
			// }
			// io.Copy(df, r)
			// df.Close()
			// r.Seek(int64(binary.Size(deepmapInfo)), io.SeekStart) // Reset reader to start for deepmap reading
			var dm deepmap
			if err := binary.Read(r, binary.LittleEndian, &dm); err != nil {
				return nil, err
			}
			if dm.Signature != [4]byte{'d', 'm', 'a', 'p'} {
				return nil, fmt.Errorf("invalid deepmap signature: %s", dm.Signature)
			}
			// Read the compressed data
			compressedData := make([]byte, dm.CompressedBlock)
			if err := binary.Read(r, binary.LittleEndian, &compressedData); err != nil {
				return nil, fmt.Errorf("failed to read Deepmap compressed data: %v", err)
			}
			switch dm.CompressionMethod {
			case ImageDeepmapCompressionLossless:
				if isLZFSE, _ := magic.IsLZFSE(compressedData); isLZFSE {
					// Decompress the data
					decompressed, err := comp.Decompress(compressedData, comp.LZFSE)
					if err != nil {
						return nil, fmt.Errorf("failed to decompress DeepmapLZFSE data: %v", err)
					}
					out.Write(decompressed)
				} else {
					return nil, fmt.Errorf("lzfse magic bytes not found in DeepmapLZFSE data")
				}
			case ImageDeepmapCompressionDefault:
				out.Write(decodeRLE(compressedData))
			case ImageDeepmapCompressionNone:
				out.Write(compressedData)
			case ImageDeepmapCompressionPalette:
				panic("Deepmap Palette compression not implemented yet")
			}
			// switch dm.CompressionMethod {
			// case ImageDeepmapCompressionDefault:
			// 	// Decompress the data
			// 	decompressed, err := comp.Decompress(compressedData, comp.LZFSE)
			// 	if err != nil {
			// 		return nil, fmt.Errorf("failed to decompress DeepmapLZFSE data: %v", err)
			// 	}
			// 	out.Write(decompressed)
			// case ImageDeepmapCompressionNone:
			// 	out.Write(compressedData)
			// default:
			// 	return nil, fmt.Errorf("unsupported deepmap compression method: %d", dm.CompressionMethod)
			// }
		case Deepmap2:
			// os.WriteFile(fmt.Sprintf("%s.compressed.%s", string(bytes.Trim(ci.Metadata.Name[:], "\x00")), bm.Encoding), data, 0644)
			dmr := bytes.NewReader(data)
			var cdm2 csiDeepmap2Data
			if err := binary.Read(dmr, binary.LittleEndian, &cdm2); err != nil {
				return nil, err
			}
			if conf != nil && conf.Verbose {
				log.WithFields(log.Fields{
					"version":  cdm2.Version,
					"encoding": cdm2.Encoding,
					"length":   cdm2.Length,
				}).Info("Reading Deepmap2 Data")
			}
			var dm2 deepmap2
			if err := binary.Read(dmr, binary.LittleEndian, &dm2); err != nil {
				return nil, err
			}
			if dm2.Signature != [4]byte{'d', 'm', 'p', '2'} {
				return nil, fmt.Errorf("invalid deepmap2 signature: %s", dm2.Signature)
			}
			if conf != nil && conf.Verbose {
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
			}
			if dm2.BlobVersion != 1 {
				return nil, fmt.Errorf("unsupported deepmap2 blob version: %d", dm2.BlobVersion)
			}

			// Override image dimensions and pixel format to match DM2 payload
			ci.Width = uint32(dm2.Width)
			ci.Height = uint32(dm2.Height)
			fromDeepmap2 = true
			deepmap2PixFmt = dm2.PixelFormat
			switch dm2.PixelFormat {
			case ImageDeepmapPixelFormatRGBA16:
				copy(ci.PixelFormat[:], "RGBW")
			case ImageDeepmapPixelFormatRGBA8:
				copy(ci.PixelFormat[:], "ARGB")
			case ImageDeepmapPixelFormatGA8:
				copy(ci.PixelFormat[:], "GA8 ")
			}
			switch cdm2.Encoding {
			case LZFSE, ZIP:
				// Gather the full Deepmap2 compressed block, which may follow in KCBC chunks
				need := int(dm2.CompressedBlock)
				compressed := make([]byte, need)
				readSoFar := 0
				if dmr.Len() > 0 {
					frag := make([]byte, dmr.Len())
					if _, err := io.ReadFull(dmr, frag); err == nil {
						toCopy := len(frag)
						if toCopy > need {
							toCopy = need
						}
						copy(compressed[0:], frag[:toCopy])
						readSoFar += toCopy
					}
				}
				for readSoFar < need {
					// Expect KCBC chunk with more of the payload
					var next csiBitmapChunk
					if err := binary.Read(r, binary.LittleEndian, &next); err != nil {
						// If we hit EOF, just proceed with what we have
						if err == io.EOF {
							break
						}
						return nil, fmt.Errorf("failed to continue deepmap2 payload (non-chunk path): %v", err)
					}
					if next.Signature != [4]byte{'K', 'C', 'B', 'C'} {
						return nil, fmt.Errorf("unexpected chunk while continuing deepmap2 payload (non-chunk path): %s", next.Signature)
					}
					buf := make([]byte, next.Length)
					if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
						return nil, fmt.Errorf("failed to read continuation chunk (non-chunk path): %v", err)
					}
					remain := need - readSoFar
					toCopy := remain
					if len(buf) < toCopy {
						toCopy = len(buf)
					}
					copy(compressed[readSoFar:readSoFar+toCopy], buf[:toCopy])
					readSoFar += toCopy
				}

				// If palette compression, split palette and indices and decode paletted directly
				if dm2.CompressionMethod == ImageDeepmapCompressionPalette {
					// Look for LZFSE block header magic commonly seen as 'bvx2'
					pos := bytes.Index(compressed, []byte("bvx2"))
					if pos > 0 {
						palette := compressed[:pos]
						indicesCompressed := compressed[pos:]
						// Some files mark ZIP but actually contain LZFSE
						decomp, err := comp.Decompress(indicesCompressed, comp.LZFSE)
						if err == nil {
							combo := append([]byte{}, append(palette, decomp...)...)
							if palImg, err := decodePalettedImage(combo, int(ci.Width), int(ci.Height)); err == nil {
								return palImg, nil
							}
						}
					}
				}

				// Otherwise, decompress the full block
				if cdm2.Encoding == ZIP {
					if isLZFSE, _ := magic.IsLZFSE(compressed); isLZFSE {
						decompressed, err := comp.Decompress(compressed, comp.LZFSE)
						if err != nil {
							return nil, fmt.Errorf("failed to decompress Deepmap2 LZFSE data: %v", err)
						}
						out.Write(decompressed)
					} else if gr, err := gzip.NewReader(bytes.NewReader(compressed)); err == nil {
						if _, err := io.Copy(&out, gr); err != nil {
							return nil, fmt.Errorf("failed to decompress gzip data: %v", err)
						}
					} else if zr, err := zlib.NewReader(bytes.NewReader(compressed)); err == nil {
						if _, err := io.Copy(&out, zr); err != nil {
							return nil, fmt.Errorf("failed to decompress zlib data: %v", err)
						}
						zr.Close()
					} else {
						fr := flate.NewReader(bytes.NewReader(compressed))
						if _, err := io.Copy(&out, fr); err != nil {
							out.Write(compressed)
						}
						fr.Close()
					}
				} else {
					if isLZFSE, _ := magic.IsLZFSE(compressed); isLZFSE {
						decompressed, err := comp.Decompress(compressed, comp.LZFSE)
						if err != nil {
							return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
						}
						out.Write(decompressed)
					} else {
						out.Write(compressed)
					}
				}
			case Deepmap2:
				// Handle nested Deepmap2 encoding
				if dmr.Len() > 16 {
					payload := make([]byte, dmr.Len())
					if _, err := io.ReadFull(dmr, payload); err == nil {
						decompressed, err := comp.Decompress(payload[16:], comp.LZFSE)
						if err != nil {
							return nil, fmt.Errorf("failed to decompress nested Deepmap2: %v", err)
						}
						out.Write(decompressed)
					}
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
			return nil, fmt.Errorf("unknown encoding: %s (value: %d)", elem.Encoding, elem.Encoding)
		}
	}

	// os.WriteFile(fmt.Sprintf("%s.uncompressed", string(bytes.Trim(ci.Metadata.Name[:], "\x00"))), out.Bytes(), 0644)

	// Check for invalid image dimensions
	if ci.Width == 0 || ci.Height == 0 {
		return nil, fmt.Errorf("invalid image dimensions: %dx%d", ci.Width, ci.Height)
	}

	// Check if this was a PaletteImage compression type
	// If so, decode as a paletted image regardless of pixel format
	if elem.Encoding == PaletteImage {
		// Try to decode as a paletted image
		if palImg, err := decodePalettedImage(out.Bytes(), int(ci.Width), int(ci.Height)); err == nil {
			return palImg, nil
		} else {
			// If palette decoding fails, log and try normal pixel format handling as fallback
			log.Debugf("Failed to decode as PaletteImage for %s: %v, falling back to pixel format", string(bytes.Trim(ci.Metadata.Name[:], "\x00")), err)
		}
	}

	format := string(ci.PixelFormat[:])
	switch format {
	case PixFmtARGB, PixFmtARGB16:
		// Special handling for IconImage layout which often uses channel-separated ARGB format (AAAA RRRR GGGG BBBB)
		if ci.Metadata.Layout == IconImage {
			pixelCount := int(ci.Width * ci.Height)
			// Prefer exact-sized channel data, but allow >= to tolerate minor padding
			if out.Len() >= pixelCount*4 {
				if img, err := decodeAppIconARGB(out.Bytes(), int(ci.Width), int(ci.Height)); err == nil {
					return img, nil
				}
			}
		}

		var offset int
		bytesPerPixel := 4 // Default for ARGB (8-bit per channel)
		if format == PixFmtARGB16 {
			bytesPerPixel = 8 // 16-bit per channel (2 bytes per channel × 4 channels)
		}

		expectedSize := int(ci.Width * ci.Height * uint32(bytesPerPixel))
		actualSize := out.Len()

		if actualSize < expectedSize {
			// Not enough data for the image; drop a debug blob into output dir or temp, not project root
			if conf != nil {
				outDir := conf.Output
				if outDir == "" {
					outDir = filepath.Join(os.TempDir(), "ipsw-car-errors")
				}
				_ = os.MkdirAll(outDir, 0o755)
				name := strings.Trim(string(bytes.Trim(ci.Metadata.Name[:], "\x00")), " ")
				if name == "" {
					name = fmt.Sprintf("asset_%dx%d_%s", ci.Width, ci.Height, format)
				}
				errPath := filepath.Join(outDir, fmt.Sprintf("%s.error", name))
				_ = os.WriteFile(errPath, out.Bytes(), 0644)
			}
			return nil, fmt.Errorf("insufficient image data: got %d bytes, expected %d bytes for %dx%d %s", actualSize, expectedSize, ci.Width, ci.Height, format)
		}

		if v := actualSize - expectedSize; v != 0 {
			offset = v / int(ci.Height*uint32(bytesPerPixel))
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
		// Deepmap2 emits RGBA ordering; do not apply BGRA swap, and downconvert 16-bit to 8-bit
		if fromDeepmap2 {
			if format == PixFmtARGB16 || deepmap2PixFmt == ImageDeepmapPixelFormatRGBA16 {
				// downconvert RGBA16 (LE) to RGBA8
				in := out.Bytes()
				px := rect.Dx() * rect.Dy()
				dst := make([]byte, px*4)
				for i := 0; i < px; i++ {
					j := i * 8
					// take high byte of each 16-bit LE component
					r := in[j+1]
					g := in[j+3]
					b := in[j+5]
					a := in[j+7]
					k := i * 4
					dst[k+0] = r
					dst[k+1] = g
					dst[k+2] = b
					dst[k+3] = a
				}
				stride := rect.Dx() * 4
				img := &image.RGBA{Pix: dst, Stride: stride, Rect: rect}
				return img, nil
			}
			// RGBA8
			stride := rect.Dx() * 4
			if rowBytesOverride > 0 {
				stride = rowBytesOverride
			}
			img := &image.RGBA{Pix: out.Bytes(), Stride: stride, Rect: rect}
			return img, nil
		}

		// Default path: treat as BGRA in memory and swap when reading
		stride := (rect.Dx() + offset) * bytesPerPixel
		if rowBytesOverride > 0 {
			stride = rowBytesOverride
		}
		bgra := &BGRA{image.RGBA{
			Pix:    out.Bytes(),
			Stride: stride,
			Rect:   rect,
		}}
		return bgra, nil
	case PixFmtGray, PixFmtGray16:
		var offset int
		bytesPerPixel := 2 // GA8: gray + alpha (1 byte each)
		if format == PixFmtGray16 {
			bytesPerPixel = 4 // GA16: gray + alpha (2 bytes each)
		}

		expectedSize := int(ci.Width * ci.Height * uint32(bytesPerPixel))
		actualSize := out.Len()

		if actualSize < expectedSize {
			// Not enough data for the image
			return nil, fmt.Errorf("insufficient image data: got %d bytes, expected %d bytes for %dx%d %s", actualSize, expectedSize, ci.Width, ci.Height, format)
		}

		if v := actualSize - expectedSize; v != 0 {
			offset = v / int(ci.Height*uint32(bytesPerPixel))
		}

		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{
				X: int(ci.Width),
				Y: int(ci.Height),
			},
		}
		// For 16-bit gray images, we need proper handling
		// TODO: Implement proper 16-bit gray image support
		if format == PixFmtGray16 {
			// For now, just return the raw data structure
			bgra := &GA8{
				Pix:    out.Bytes(),
				Stride: (rect.Dx() + offset) * bytesPerPixel,
				Rect:   rect,
			}
			return bgra, nil
		}

		stride := (rect.Dx() + offset) * bytesPerPixel
		if rowBytesOverride > 0 {
			stride = rowBytesOverride
		}
		bgra := &GA8{
			Pix:    out.Bytes(),
			Stride: stride,
			Rect:   rect,
		}
		return bgra, nil
	default:
		return nil, fmt.Errorf("unknown pixel format: %s", format)
	}
}

// decodePalettedImage creates a paletted image from palette data and indices
// The format is typically: [palette colors (256 * 4 bytes RGBA)][pixel indices]
func decodePalettedImage(data []byte, width, height int) (image.Image, error) {
	const paletteSize = 256 // Standard 256-color palette
	const bytesPerColor = 4 // RGBA

	paletteBytes := paletteSize * bytesPerColor
	pixelCount := width * height

	log.Debugf("decodePalettedImage: data size=%d, width=%d, height=%d, pixelCount=%d", len(data), width, height, pixelCount)

	// Try different palette formats based on data size
	// Format 1: [palette (256*4 bytes)][pixel indices]
	if len(data) == paletteBytes+pixelCount {
		log.Debugf("Using format 1: palette + indices")
		// Extract the palette
		palette := make(color.Palette, paletteSize)
		for i := 0; i < paletteSize; i++ {
			offset := i * bytesPerColor
			// Try RGBA format
			palette[i] = color.RGBA{
				R: data[offset],
				G: data[offset+1],
				B: data[offset+2],
				A: data[offset+3],
			}
		}

		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{X: width, Y: height},
		}

		img := image.NewPaletted(rect, palette)
		// honor per-row stride when present (common case: row padded)
		indices := data[paletteBytes:]
		if len(indices)%height == 0 {
			stride := len(indices) / height
			for y := 0; y < height; y++ {
				start := y * stride
				copy(img.Pix[y*width:(y+1)*width], indices[start:start+width])
			}
		} else {
			copy(img.Pix, indices[:pixelCount])
		}
		return img, nil
	}

	// Format 2: Just pixel indices (palette might be predefined or elsewhere)
	if len(data) == pixelCount {
		log.Debugf("Using format 2: indices only, creating grayscale palette")
		// Create a grayscale palette as fallback
		palette := make(color.Palette, 256)
		for i := 0; i < 256; i++ {
			gray := uint8(i)
			palette[i] = color.RGBA{gray, gray, gray, 255}
		}

		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{X: width, Y: height},
		}

		img := image.NewPaletted(rect, palette)
		if len(data)%height == 0 {
			stride := len(data) / height
			for y := 0; y < height; y++ {
				start := y * stride
				copy(img.Pix[y*width:(y+1)*width], data[start:start+width])
			}
		} else {
			copy(img.Pix, data[:pixelCount])
		}
		return img, nil
	}

	// Format 3: Maybe the palette is at the end?
	if len(data) > pixelCount && len(data) >= pixelCount+paletteBytes {
		log.Debugf("Using format 3: indices first, then palette")
		// Try indices first, then palette
		indices := data[:pixelCount]
		paletteData := data[pixelCount : pixelCount+paletteBytes]

		palette := make(color.Palette, paletteSize)
		for i := 0; i < paletteSize; i++ {
			offset := i * bytesPerColor
			palette[i] = color.RGBA{
				R: paletteData[offset],
				G: paletteData[offset+1],
				B: paletteData[offset+2],
				A: paletteData[offset+3],
			}
		}

		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{X: width, Y: height},
		}

		img := image.NewPaletted(rect, palette)
		if len(indices)%height == 0 {
			stride := len(indices) / height
			for y := 0; y < height; y++ {
				start := y * stride
				copy(img.Pix[y*width:(y+1)*width], indices[start:start+width])
			}
		} else {
			copy(img.Pix, indices)
		}
		return img, nil
	}

	// Format 4: Maybe it's in BGRA format instead of RGBA?
	if len(data) >= paletteBytes+pixelCount {
		log.Debugf("Using format 4: trying BGRA palette format")
		// Extract the palette in BGRA format
		palette := make(color.Palette, paletteSize)
		for i := 0; i < paletteSize; i++ {
			offset := i * bytesPerColor
			// Try BGRA format
			palette[i] = color.RGBA{
				R: data[offset+2], // B -> R
				G: data[offset+1], // G -> G
				B: data[offset],   // R -> B
				A: data[offset+3], // A -> A
			}
		}

		rect := image.Rectangle{
			Min: image.Point{0, 0},
			Max: image.Point{X: width, Y: height},
		}

		img := image.NewPaletted(rect, palette)
		indices := data[paletteBytes:]
		if len(indices)%height == 0 {
			stride := len(indices) / height
			for y := 0; y < height; y++ {
				start := y * stride
				copy(img.Pix[y*width:(y+1)*width], indices[start:start+width])
			}
		} else {
			copy(img.Pix, indices[:pixelCount])
		}
		return img, nil
	}

	return nil, fmt.Errorf("insufficient data for paletted image: got %d bytes, pixelCount=%d, paletteBytes=%d", len(data), pixelCount, paletteBytes)
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
