package car

import (
	"encoding/binary"
	"fmt"
	"image"

	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

const cafef00dMagic = 0xcafef00d

// decodePaletteImage reads the quantized-image stream used by PaletteImage.
// Index rows are padded to 16 bits. Within each little-endian word, the first
// pixel occupies the most significant bits. Palette colors have their own
// channel representation, independent of the ordinary bitmap representation.
func decodePaletteImage(data []byte, width, height int, format string, space colorSpaceID, opaque bool) (image.Image, error) {
	bpp := 4
	if format == PixFmtARGB16 {
		bpp = 8
	} else if format != PixFmtARGB {
		return nil, fmt.Errorf("palette: unsupported pixel format %q", format)
	}
	_, size, err := pixel.Layout(width, height, bpp, 0)
	if err != nil {
		return nil, err
	}
	if compression.IsAppleStream(data) {
		// The widest index occupies two bytes; a palette has at most 4096 colors.
		limit := min(pixel.MaxBytes, 10+4096*bpp+((width*2+1)&^1)*height)
		data, err = compression.Decode(data, limit, false)
		if err != nil {
			return nil, fmt.Errorf("palette: %w", err)
		}
	}
	if len(data) < 10 || len(data) > pixel.MaxBytes || binary.LittleEndian.Uint32(data) != cafef00dMagic {
		return nil, fmt.Errorf("palette: invalid quantized image header")
	}
	if version := binary.LittleEndian.Uint32(data[4:]); version > 1 {
		return nil, fmt.Errorf("palette: unsupported version %d", version)
	}
	count := int(binary.LittleEndian.Uint16(data[8:]))
	if count == 0 || count > 4096 || len(data)-10 < count*bpp {
		return nil, fmt.Errorf("palette: invalid or truncated palette of %d colors", count)
	}
	indexBits := 1
	for count > 1<<indexBits {
		indexBits *= 2
	}
	rowBytes := ((width*indexBits + 15) / 16) * 2
	colors, indices := data[10:10+count*bpp], data[10+count*bpp:]
	if len(indices) != rowBytes*height {
		return nil, fmt.Errorf("palette: got %d index bytes, expected %d", len(indices), rowBytes*height)
	}
	pixels := make([]byte, size)
	for y := range height {
		for x := range width {
			bit := x * indexBits
			word := binary.LittleEndian.Uint16(indices[y*rowBytes+(bit/16)*2:])
			index := int(word>>(16-indexBits-bit%16)) & ((1 << indexBits) - 1)
			if index >= count {
				return nil, fmt.Errorf("palette: index %d at (%d,%d) exceeds %d colors", index, x, y, count)
			}
			entry := colors[index*bpp : (index+1)*bpp]
			dst := pixels[(y*width+x)*bpp:][:bpp]
			if bpp == 4 {
				// Eight-bit palette entries are A,R,G,B; output is premultiplied RGBA.
				copy(dst, entry[1:])
				dst[3] = entry[0]
				if opaque {
					dst[3] = 255
				}
			} else {
				// Wide palette entries are B,G,R,A integers with unity at 10000.
				// CoreUI reconstructs RGBA binary16 before displaying this format.
				for c, source := range [...]int{2, 1, 0, 3} {
					v := binary.LittleEndian.Uint16(entry[source*2:])
					binary.LittleEndian.PutUint16(dst[c*2:], pixel.EncodeHalf(float32(v)/10000))
				}
			}
		}
	}
	if bpp == 8 {
		// CoreUI chooses the numeric interpretation from the CSI color space,
		// even though palette reconstruction itself always produces half words.
		if space == ExtendedSRGB || space == ExtendedLinear {
			return pixel.DecodeHalfFloatRGBA(pixels, width, height, 0, opaque)
		}
		return pixel.DecodeRGBA64(pixels, width, height, 0, opaque)
	}
	return &image.RGBA{Pix: pixels, Stride: width * 4, Rect: image.Rect(0, 0, width, height)}, nil
}
