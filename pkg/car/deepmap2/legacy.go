package deepmap2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/draw"

	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// DecodeLegacy handles the original dmap codec. Unlike dmp2, geometry
// comes from CSI and the compressed tiles are fixed at 256 by 256 pixels.
// pixelFormat, floatingPoint, and opaque have the same meaning as in Decode.
func DecodeLegacy(data []byte, width, height int, format string, floatingPoint, opaque bool) (image.Image, error) {
	if _, _, err := pixel.Layout(width, height, 8, 0); err != nil {
		return nil, err
	}
	if len(data) < 24 || len(data) > pixel.MaxBytes {
		return nil, fmt.Errorf("deepmap: truncated or excessive payload")
	}
	if binary.LittleEndian.Uint32(data) != 1 || binary.LittleEndian.Uint64(data[8:]) != uint64(len(data)-16) {
		return nil, fmt.Errorf("deepmap: invalid CoreUI wrapper")
	}
	data = data[16:]
	if string(data[:4]) != "dmap" {
		return nil, fmt.Errorf("deepmap: missing dmap header")
	}
	method, scale, stored := data[4], data[5], data[7]
	data = data[8:]
	switch format {
	case "ARGB", "RGBW", "GA8 ", "GRAY":
	default:
		return nil, fmt.Errorf("deepmap: unsupported CSI pixel format %q: %w", format, errors.ErrUnsupported)
	}
	bpp := int(stored)
	if stored == 20 {
		bpp = 8
	} else if stored < 1 || stored > 4 {
		return nil, fmt.Errorf("deepmap: unsupported pixel format %d: %w", stored, errors.ErrUnsupported)
	}
	// A source format must agree with the CSI channel count; do not reinterpret
	// a half-float tile as twice as many byte pixels.
	if (format == "RGBW") != (stored == 20) ||
		(format == "GA8 " && stored != 2) ||
		(format == "GRAY" && stored != 1) ||
		(format == "ARGB" && stored != 3 && stored != 4) {
		return nil, fmt.Errorf("deepmap: stored format %d does not match %q", stored, format)
	}
	if method == 1 {
		if len(data) != width*height*bpp {
			return nil, fmt.Errorf("deepmap: raw pixel size mismatch")
		}
		return legacyPixels(data, width, height, stored, floatingPoint, opaque)
	}
	if method < 2 || method > 4 {
		return nil, fmt.Errorf("deepmap: unsupported method %d: %w", method, errors.ErrUnsupported)
	}
	var palette []byte
	if method == 4 {
		if stored != 4 {
			return nil, fmt.Errorf("deepmap: unsupported palette format %d: %w", stored, errors.ErrUnsupported)
		}
		if len(data) < 4 {
			return nil, fmt.Errorf("deepmap: truncated palette header")
		}
		count := int(binary.LittleEndian.Uint16(data))
		if binary.LittleEndian.Uint16(data[2:]) != 0 || count == 0 || count > 256 || len(data)-4 < count*4 {
			return nil, fmt.Errorf("deepmap: invalid palette descriptor")
		}
		palette, data = data[4:4+count*4], data[4+count*4:]
	}
	var dst draw.Image = image.NewRGBA(image.Rect(0, 0, width, height))
	if stored == 20 {
		if floatingPoint {
			dst = image.NewNRGBA64(dst.Bounds())
		} else {
			dst = image.NewRGBA64(dst.Bounds())
		}
	}
	for y := 0; y < height; y += 256 {
		for x := 0; x < width; x += 256 {
			w, h := min(256, width-x), min(256, height-y)
			limit := w * h * bpp
			if method == 2 {
				components, alpha := 1, 0
				if stored >= 3 {
					components = 3
				}
				if stored == 2 || stored == 4 || stored == 20 {
					alpha = w * h
				}
				limit = (alpha + h + w*h*components*2 + 7) &^ 7
			} else if method == 4 {
				limit = w * h * 2 // Alpha plane followed by one-byte palette indices.
			}
			if len(data) < 4 {
				return nil, fmt.Errorf("deepmap: missing tile at (%d,%d)", x, y)
			}
			length := uint64(binary.LittleEndian.Uint32(data))
			data = data[4:]
			if length == 0 || length > uint64(len(data)) {
				return nil, fmt.Errorf("deepmap: truncated tile at (%d,%d)", x, y)
			}
			decoded, err := compression.Decode(data[:int(length)], limit, true)
			if err != nil {
				return nil, fmt.Errorf("deepmap: tile (%d,%d): %w", x, y, err)
			}
			data = data[int(length):]
			if len(decoded) != limit {
				return nil, fmt.Errorf("deepmap: tile (%d,%d) has %d bytes, expected %d", x, y, len(decoded), limit)
			}
			if method == 2 {
				first := 0
				if stored == 2 || stored == 4 || stored == 20 {
					first = w * h
				}
				if decoded[first] != 0 && decoded[first] != 2 {
					return nil, fmt.Errorf("deepmap: first tile row requires an independent or left predictor")
				}
			}
			var tile image.Image
			switch method {
			case 2:
				if stored == 20 {
					tile, err = legacyWidePredict(decoded, w, h, scale, floatingPoint, opaque)
					break
				}
				pixels := image.NewRGBA(image.Rect(0, 0, w, h))
				err = predictPixels(pixels.Pix, decoded, header{format: stored, scale: scale}, w, h, h)
				if opaque {
					for i := 3; i < len(pixels.Pix); i += 4 {
						pixels.Pix[i] = 255
					}
				}
				tile = pixels
			case 3:
				tile, err = legacyPixels(decoded, w, h, stored, floatingPoint, opaque)
			case 4:
				pixels := make([]byte, w*h*4)
				for i, index := range decoded[w*h:] {
					if int(index) >= len(palette)/4 {
						return nil, fmt.Errorf("deepmap: palette index %d exceeds %d colors", index, len(palette)/4)
					}
					copy(pixels[i*4:], palette[int(index)*4:][:4])
					pixels[i*4+3] = decoded[i]
				}
				tile, err = legacyPixels(pixels, w, h, stored, floatingPoint, opaque)
			}
			if err != nil {
				return nil, err
			}
			draw.Draw(dst, image.Rect(x, y, x+w, y+h), tile, image.Point{}, draw.Src)
		}
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("deepmap: %d trailing bytes after final tile", len(data))
	}
	return dst, nil
}

// The wide dmap predictor uses the same signed residual planes as eight-bit
// dmap, but its reconstructed color units are 1/512 and its output is RGBA
// binary16. Keep its extended and negative values until the final conversion.
func legacyWidePredict(data []byte, width, height int, scale byte, floatingPoint, opaque bool) (image.Image, error) {
	count := width * height
	predictors := data[count : count+height]
	high := data[count+height : count+height+count*3]
	low := data[count+height+count*3:]
	pixels := make([]byte, count*8)
	previous, row := make([]int16, width*3), make([]int16, width*3)
	for y, predictor := range predictors {
		if predictor > 4 {
			return nil, fmt.Errorf("deepmap: unsupported predictor %d: %w", predictor, errors.ErrUnsupported)
		}
		for x := range width {
			base := x * 3
			leftWins := false
			if predictor == 1 && x > 0 {
				corner := int(previous[base-3])
				leftWins = abs(int(previous[base])-corner) <= abs(int(row[base-3])-corner)
			}
			for c := range 3 {
				i := base + c
				index := y*width*3 + i
				encoded := uint16(high[index])<<8 | uint16(low[index])
				value := int(encoded >> 1)
				if encoded&1 != 0 {
					value = -value
				}
				up, left := int(previous[i]), 0
				if x > 0 {
					left = int(row[i-3])
				}
				switch predictor {
				case 1:
					if leftWins {
						value += left
					} else {
						value += up
					}
				case 2:
					value += left
				case 3:
					value += up
				case 4:
					if x == 0 {
						value += up
					} else {
						value += (left + up + 1) / 2
					}
				}
				row[i] = int16(value)
			}
			co, cg := int(row[base+1]), int(row[base+2])
			if scale != 0 {
				co, cg = co*2, cg*2
			}
			temp := int(row[base]) - cg/2
			channels := [4]float32{
				float32(temp+co-co/2) / 512,
				float32(temp+cg) / 512,
				float32(temp-co/2) / 512,
				float32(data[y*width+x]) / 255,
			}
			for c, value := range channels {
				binary.LittleEndian.PutUint16(pixels[(y*width+x)*8+c*2:], pixel.EncodeHalf(value))
			}
		}
		previous, row = row, previous
	}
	return decodeWidePixels(pixels, width, height, 0, floatingPoint, opaque)
}

func legacyPixels(data []byte, width, height int, format byte, floatingPoint, opaque bool) (image.Image, error) {
	if format == 20 {
		return decodeWidePixels(data, width, height, 0, floatingPoint, opaque)
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	rawPixels(img.Pix, data, format)
	if opaque {
		for i := 3; i < len(img.Pix); i += 4 {
			img.Pix[i] = 255
		}
	}
	return img, nil
}
