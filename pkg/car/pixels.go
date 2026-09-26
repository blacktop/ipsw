package car

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

const PixFmtGrayscale = "GRAY" // Gray scale without alpha.

func pixelSize(format string) (int, error) {
	switch format {
	case PixFmtARGB, PixFmtGray16:
		return 4, nil
	case PixFmtARGB16:
		return 8, nil
	case PixFmtRGB555, PixFmtGray:
		return 2, nil
	case PixFmtGrayscale:
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported pixel format: %q", format)
	}
}

func decodePixels(data []byte, width, height int, format string, stride int, opaque bool) (image.Image, error) {
	if format == PixFmtARGB16 {
		return pixel.DecodeRGBA64(data, width, height, stride, opaque)
	}
	bpp, err := pixelSize(format)
	if err != nil {
		return nil, err
	}
	stride, needed, err := pixel.Layout(width, height, bpp, stride)
	if err != nil {
		return nil, err
	}
	if len(data) < needed {
		return nil, fmt.Errorf("truncated %s pixels: got %d bytes, need %d", format, len(data), needed)
	}
	// Converted formats may need more storage than their source representation.
	outBPP := 4
	if format == PixFmtGray16 {
		outBPP = 8
	}
	if _, _, err := pixel.Layout(width, height, outBPP, 0); err != nil {
		return nil, err
	}
	// CoreUI ignores stored alpha for opaque bitmaps, including atlas padding.
	if opaque {
		alphaBytes := 0
		switch format {
		case PixFmtARGB, PixFmtGray:
			alphaBytes = 1
		case PixFmtGray16:
			alphaBytes = 2
		}
		for y := range height {
			for x := range width {
				end := y*stride + (x+1)*bpp
				for i := end - alphaBytes; i < end; i++ {
					data[i] = 255
				}
			}
		}
	}
	rect := image.Rect(0, 0, width, height)
	switch format {
	case PixFmtARGB:
		return &BGRA{image.RGBA{Pix: data, Stride: stride, Rect: rect}}, nil
	case PixFmtGray:
		return &GA8{Pix: data, Stride: stride, Rect: rect}, nil
	case PixFmtGrayscale:
		return &image.Gray{Pix: data, Stride: stride, Rect: rect}, nil
	case PixFmtGray16:
		img := image.NewRGBA64(rect)
		for y := range height {
			for x := range width {
				p := data[y*stride+x*4:][:4]
				g := binary.LittleEndian.Uint16(p[:2])
				img.SetRGBA64(x, y, color.RGBA64{R: g, G: g, B: g, A: binary.LittleEndian.Uint16(p[2:])})
			}
		}
		return img, nil
	case PixFmtRGB555:
		img := image.NewNRGBA(rect)
		for y := range height {
			for x := range width {
				p := data[y*stride+x*2:][:2]
				v := binary.LittleEndian.Uint16(p)
				expand := func(v uint16) uint8 { return uint8(v<<3 | v>>2) }
				c := color.NRGBA{R: expand((v >> 10) & 31), G: expand((v >> 5) & 31), B: expand(v & 31), A: 255}
				img.SetNRGBA(x, y, c)
			}
		}
		return img, nil
	}
	return nil, fmt.Errorf("unsupported pixel format: %q", format)
}
