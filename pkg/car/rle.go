package car

import (
	"encoding/binary"
	"fmt"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// decodeRLERows expands CoreUI rows. Each row has an absolute byte offset
// and uint32 packets: a 24-bit pixel count with high byte 0 (literal) or 0x80
// (repeat). The encoded rows are tight; CSI row padding is added on output.
func decodeRLERows(data []byte, width, height, stride int, format string) ([]byte, error) {
	bpp, err := pixelSize(format)
	if err != nil {
		return nil, err
	}
	var encoding uint32
	switch format {
	case PixFmtGrayscale:
		encoding = 1
	case PixFmtGray, PixFmtRGB555:
		encoding = 3
	case PixFmtARGB, PixFmtGray16:
		encoding = 4
	default:
		return nil, fmt.Errorf("unsupported RLE pixel format: %q", format)
	}
	stride, _, err = pixel.Layout(width, height, bpp, stride)
	if err != nil {
		return nil, err
	}
	if len(data) > pixel.MaxBytes || len(data) < 12 || height > (len(data)-12)/4 {
		return nil, fmt.Errorf("invalid RLE row table")
	}
	if stored := binary.LittleEndian.Uint32(data); stored != encoding {
		return nil, fmt.Errorf("RLE pixel encoding %d does not match %q", stored, format)
	}
	if binary.LittleEndian.Uint32(data[4:]) != uint32(width) || binary.LittleEndian.Uint32(data[8:]) != uint32(height) {
		return nil, fmt.Errorf("RLE dimensions do not match CSI")
	}
	out := make([]byte, stride*height)
	headerSize := 12 + 4*height
	for y := range height {
		start := uint64(binary.LittleEndian.Uint32(data[12+y*4:]))
		// Rows may share storage or appear in a different order in the stream.
		if start < uint64(headerSize) || start >= uint64(len(data)) {
			return nil, fmt.Errorf("invalid RLE row %d range", y)
		}
		row := data[int(start):]
		x := 0
		for x < width {
			if len(row) < 4 {
				return nil, fmt.Errorf("truncated RLE row %d packet", y)
			}
			control := binary.LittleEndian.Uint32(row)
			row = row[4:]
			count := int(control & 0xffffff)
			if count == 0 || count > width-x {
				return nil, fmt.Errorf("invalid RLE row %d pixel count: %d", y, count)
			}
			dst := out[y*stride+x*bpp : y*stride+(x+count)*bpp]
			switch control >> 24 {
			case 0:
				if len(row) < len(dst) {
					return nil, fmt.Errorf("truncated RLE row %d literal", y)
				}
				copy(dst, row[:len(dst)])
				row = row[len(dst):]
			case 0x80:
				if len(row) < bpp {
					return nil, fmt.Errorf("truncated RLE row %d repeat", y)
				}
				for i := 0; i < len(dst); i += bpp {
					copy(dst[i:i+bpp], row[:bpp])
				}
				row = row[bpp:]
			default:
				return nil, fmt.Errorf("unsupported RLE row %d packet: %#x", y, control)
			}
			x += count
		}
	}
	return out, nil
}
