// Package pixel provides bounded layouts and wide-channel conversions for CAR decoders.
package pixel

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"math"
)

// MaxBytes bounds decoded image storage.
const MaxBytes = 256 << 20

// Layout checks dimensions and row stride before calculating allocation sizes.
func Layout(width, height, bpp, stride int) (int, int, error) {
	if width <= 0 || height <= 0 || bpp <= 0 || width > MaxBytes/bpp {
		return 0, 0, fmt.Errorf("invalid image dimensions: %dx%d", width, height)
	}
	row := width * bpp
	if stride == 0 {
		stride = row
	}
	if stride < row || stride > MaxBytes || height > MaxBytes/stride {
		return 0, 0, fmt.Errorf("invalid or excessive image stride: %d for %dx%d", stride, width, height)
	}
	return stride, (height-1)*stride + row, nil
}

// Extended-color RGBW stores premultiplied RGBA binary16 components in
// little-endian order; ordinary color spaces use integer RGBA16 instead.
// PNG's integer samples cannot represent extended-range colors. Unpremultiply
// before clipping, so a color above the alpha value does not brighten its
// translucent neighbors. Retain 16-bit precision in the bounded result.
func DecodeHalfFloatRGBA(data []byte, width, height, stride int, opaque bool) (*image.NRGBA64, error) {
	stride, needed, err := Layout(width, height, 8, stride)
	if err != nil {
		return nil, err
	}
	if len(data) < needed {
		return nil, fmt.Errorf("truncated RGBW pixels: got %d bytes, need %d", len(data), needed)
	}
	img := image.NewNRGBA64(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			p := data[y*stride+x*8:][:8]
			var channels [4]float64
			for c := range channels {
				if c == 3 && opaque {
					channels[c] = 1
					continue
				}
				bits := binary.LittleEndian.Uint16(p[c*2:])
				if bits&0x7c00 == 0x7c00 {
					return nil, fmt.Errorf("RGBW: non-finite component at (%d,%d)", x, y)
				}
				channels[c] = halfFloat(bits)
			}
			alpha := channels[3]
			var pixel color.NRGBA64
			if alpha > 0 {
				pixel = color.NRGBA64{
					R: normalized16(channels[0] / alpha),
					G: normalized16(channels[1] / alpha),
					B: normalized16(channels[2] / alpha),
					A: normalized16(alpha),
				}
			}
			img.SetNRGBA64(x, y, pixel)
		}
	}
	return img, nil
}

func halfFloat(bits uint16) float64 {
	exponent, fraction := int(bits>>10&31), int(bits&1023)
	value := math.Ldexp(float64(fraction), -24)
	if exponent != 0 {
		value = math.Ldexp(float64(1024+fraction), exponent-25)
	}
	if bits&0x8000 != 0 {
		return -value
	}
	return value
}

func normalized16(value float64) uint16 {
	if value <= 0 {
		return 0
	}
	if value >= 1 {
		return 65535
	}
	return uint16(value*65535 + 0.5)
}

// EncodeHalf rounds normal finite values or zero to binary16, ties to even.
// CAR predictor units, alpha fractions, and palette samples stay in this range.
func EncodeHalf(value float32) uint16 {
	if value == 0 {
		return 0
	}
	bits := math.Float32bits(value)
	sign := uint16(bits >> 16 & 0x8000)
	bits &= 0x7fffffff
	bits += 0xfff + (bits>>13)&1
	return sign | uint16((bits>>13)-((127-15)<<10))
}

// DecodeRGBA64 converts little-endian premultiplied RGBA16 samples.
func DecodeRGBA64(data []byte, width, height, stride int, opaque bool) (*image.RGBA64, error) {
	stride, needed, err := Layout(width, height, 8, stride)
	if err != nil {
		return nil, err
	}
	if len(data) < needed {
		return nil, fmt.Errorf("truncated RGBW pixels: got %d bytes, need %d", len(data), needed)
	}
	img := image.NewRGBA64(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			p := data[y*stride+x*8:][:8]
			if opaque {
				p[6], p[7] = 255, 255
			}
			img.SetRGBA64(x, y, color.RGBA64{
				R: binary.LittleEndian.Uint16(p[:2]), G: binary.LittleEndian.Uint16(p[2:4]),
				B: binary.LittleEndian.Uint16(p[4:6]), A: binary.LittleEndian.Uint16(p[6:8]),
			})
		}
	}
	return img, nil
}
