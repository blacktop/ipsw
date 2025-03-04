package ibootim

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"

	"github.com/blacktop/lzss"
)

type CompressionType uint32

const (
	CompressionTypeLzss CompressionType = 0x6C7A7373 // 'lzss'
)

func (t CompressionType) String() string {
	switch t {
	case CompressionTypeLzss:
		return "lzss"
	default:
		return "unknown"
	}
}

type ColorSpace uint32

const (
	ColorSpaceGrayscale ColorSpace = 0x67726579 // 'grey'
	ColorSpaceArgb      ColorSpace = 0x61726762 // 'argb'
)

func (c ColorSpace) String() string {
	switch c {
	case ColorSpaceGrayscale:
		return "grayscale"
	case ColorSpaceArgb:
		return "argb"
	default:
		return "unknown"
	}
}

var Magic = [8]byte{'i', 'B', 'o', 'o', 't', 'I', 'm', 0}

type Header struct {
	Magic           [8]byte
	Adler           uint32
	CompressionType CompressionType
	ColorSpace      ColorSpace
	Width           uint16
	Height          uint16
	OffsetX         int16
	OffsetY         int16
	CompressedSize  uint32
	_               [8]uint32
}

type IBootIm struct {
	Header

	Data []byte

	f *os.File
}

func Open(filename string) (*IBootIm, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	ibim, err := Parse(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ibim.f = f
	return ibim, nil
}

func (i *IBootIm) Close() error {
	if i.f != nil {
		err := i.f.Close()
		i.f = nil
		return err
	}
	return nil
}

func Parse(r io.ReadSeeker) (*IBootIm, error) {
	var ibim IBootIm

	if err := binary.Read(r, binary.LittleEndian, &ibim.Header); err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}
	if ibim.Magic != Magic {
		return nil, fmt.Errorf("invalid magic bytes: expected %x, got %x", Magic, ibim.Magic)
	}
	if ibim.Width == 0 || ibim.Height == 0 {
		return nil, fmt.Errorf("invalid image dimensions: %dx%d", ibim.Width, ibim.Height)
	}
	switch ibim.ColorSpace {
	case ColorSpaceGrayscale, ColorSpaceArgb:
	default:
		return nil, fmt.Errorf("unsupported color space: %v", ibim.ColorSpace)
	}

	compdata := make([]byte, ibim.CompressedSize)
	if n, err := r.Read(compdata); err != nil {
		return nil, fmt.Errorf("failed to read compressed data: %v", err)
	} else if n != int(ibim.CompressedSize) {
		return nil, fmt.Errorf("incomplete read: expected %d bytes, got %d", ibim.CompressedSize, n)
	}

	expectedSize := int(ibim.Width) * int(ibim.Height)
	if ibim.ColorSpace == ColorSpaceGrayscale {
		expectedSize *= 2 // 2 bytes per pixel (gray + alpha)
	} else {
		expectedSize *= 4 // 4 bytes per pixel (ARGB)
	}

	ibim.Data = make([]byte, expectedSize)
	copy(ibim.Data, lzss.Decompress(compdata))

	return &ibim, nil
}

func (i *IBootIm) String() string {
	return fmt.Sprintf("IBootIm{Adler: %x, Width: %d, Height: %d, ColorSpace: %s, CompressedSize: %d, OffsetX: %d, OffsetY: %d}",
		i.Adler, i.Width, i.Height, i.ColorSpace, i.CompressedSize, i.OffsetX, i.OffsetY)
}

func (i *IBootIm) ToPNG(output string) error {
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	var img image.Image

	switch i.ColorSpace {
	case ColorSpaceArgb:
		// For ARGB color space (4 bytes per pixel)
		rgba := image.NewRGBA(image.Rect(0, 0, int(i.Width), int(i.Height)))

		for y := range int(i.Height) {
			for x := range int(i.Width) {
				pos := (y*int(i.Width) + x) * 4

				b := i.Data[pos]
				g := i.Data[pos+1]
				r := i.Data[pos+2]
				a := i.Data[pos+3]

				// invert the alpha channel
				a = 255 - a

				rgba.SetRGBA(x, y, color.RGBA{r, g, b, a})
			}
		}
		img = rgba

	case ColorSpaceGrayscale:
		// For grayscale color space (2 bytes per pixel: brightness and alpha)
		gray := image.NewGray(image.Rect(0, 0, int(i.Width), int(i.Height)))
		alpha := image.NewAlpha(image.Rect(0, 0, int(i.Width), int(i.Height)))

		pos := 0
		for y := range int(i.Height) {
			for x := range int(i.Width) {
				pos = (y*int(i.Width) + x) * 2

				brightness := i.Data[pos]
				a := i.Data[pos+1]

				// invert the alpha channel
				a = 255 - a

				gray.SetGray(x, y, color.Gray{Y: brightness})
				alpha.SetAlpha(x, y, color.Alpha{A: a})
			}
		}

		// Create a new NRGBA image with the grayscale and alpha data
		nrgba := image.NewNRGBA(image.Rect(0, 0, int(i.Width), int(i.Height)))
		for y := range int(i.Height) {
			for x := range int(i.Width) {
				g := gray.GrayAt(x, y).Y
				a := alpha.AlphaAt(x, y).A
				nrgba.SetNRGBA(x, y, color.NRGBA{g, g, g, a})
			}
		}
		img = nrgba

	default:
		return fmt.Errorf("unsupported color space: %s", i.ColorSpace)
	}

	return png.Encode(f, img)
}
