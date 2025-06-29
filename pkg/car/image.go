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

type csiBitmapEncoding uint32

const (
	RawBytes     csiBitmapEncoding = 0
	RLE          csiBitmapEncoding = 1
	ZIP          csiBitmapEncoding = 2
	LZVN         csiBitmapEncoding = 3
	LZFSE        csiBitmapEncoding = 4
	JPEGLZFSE    csiBitmapEncoding = 5
	BlurredImage csiBitmapEncoding = 6
	ASTCImage    csiBitmapEncoding = 7
	PaletteImage csiBitmapEncoding = 8
	HEVC         csiBitmapEncoding = 9
	Deepmap      csiBitmapEncoding = 10
	Deepmap2     csiBitmapEncoding = 11
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
	Encoding  csiBitmapEncoding
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
	Encoding csiBitmapEncoding
	Length   uint64
}

type deepmap2Type uint8

const (
	Deepmap2DecodeNone                      deepmap2Type = 1
	Deepmap2DecodeDefaultScratchBufferSize  deepmap2Type = 2
	Deepmap2DecodeLosslessScratchBufferSize deepmap2Type = 3
	Deepmap2DecodePaletteScratchBufferSize  deepmap2Type = 4
)

type deepmap2 struct {
	Signature       [4]byte // 'dmp2'
	BlockCount      uint8
	Unknown         uint8
	Thing1          uint8
	Type            deepmap2Type
	Width           uint16
	Height          uint16
	CompressedBlock uint32
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

func decodeImage(r io.Reader, ci csiHeader) (image.Image, error) {
	var out bytes.Buffer

	var bm csiBitmap
	if err := binary.Read(r, binary.LittleEndian, &bm); err != nil {
		return nil, fmt.Errorf("failed to read CSIBitmap: %s", err)
	}

	if bm.Flags.ChunksFollow() {
		for i := uint32(0); i < bm.Length; i++ {
			var chunk csiBitmapChunk
			if err := binary.Read(r, binary.LittleEndian, &chunk); err != nil {
				return nil, err
			}
			data := make([]byte, chunk.Length)
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, err
			}
			switch bm.Encoding {
			case RawBytes:
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
				return nil, fmt.Errorf("unknown encoding: %s", bm.Encoding)
			}
		}
	} else {
		data := make([]byte, bm.Length)
		if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
			return nil, err
		}
		switch bm.Encoding {
		case RawBytes:
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
			var dm2 deepmap2
			if err := binary.Read(dmr, binary.LittleEndian, &dm2); err != nil {
				return nil, err
			}
			_ = dm2
			if cdm2.Encoding == LZFSE {
				chunck := make([]byte, dm2.CompressedBlock)
				if err := binary.Read(dmr, binary.LittleEndian, &chunck); err != nil {
					return nil, err
				}
				decompressed, err := comp.Decompress(chunck, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
				}
				out.Write(decompressed)
				var size uint32
				if err := binary.Read(dmr, binary.LittleEndian, &size); err != nil {
					return nil, err
				}
				chunck = make([]byte, size)
				if err := binary.Read(dmr, binary.LittleEndian, &chunck); err != nil {
					return nil, err
				}
				decompressed, err = comp.Decompress(chunck, comp.LZFSE)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress LZFSE data: %v", err)
				}
				out.Write(decompressed)
			} else {
				return nil, fmt.Errorf("unsupported deepmap2 encoding: %s", cdm2.Encoding)
			}
		default:
			return nil, fmt.Errorf("unknown encoding: %s", bm.Encoding)
		}
	}

	// os.WriteFile(fmt.Sprintf("%s.uncompressed", string(bytes.Trim(ci.Metadata.Name[:], "\x00"))), out.Bytes(), 0644)

	format := string(ci.PixelFormat[:])
	switch format {
	case PixFmtARGB:
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
	}

	return nil, nil
}
