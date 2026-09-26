// Package texture decodes CoreUI ASTC and DXTC texture payloads.
package texture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"

	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// texturePayload removes the wrapper shared by CoreUI ASTC and DXTC bitmaps.
// Version zero contains texture bytes; version one contains an Apple stream.
func texturePayload(data []byte) ([]byte, error) {
	if len(data) < 12 || len(data) > pixel.MaxBytes {
		return nil, fmt.Errorf("invalid texture wrapper length")
	}
	version := binary.LittleEndian.Uint32(data)
	stored := binary.LittleEndian.Uint32(data[4:])
	size := binary.LittleEndian.Uint32(data[8:])
	if uint64(stored) != uint64(len(data)-12) || size < 16 || size > pixel.MaxBytes {
		return nil, fmt.Errorf("invalid texture payload size")
	}
	data = data[12:]
	switch version {
	case 0:
	case 1:
		var err error
		data, err = compression.DecodeLZFSE(data, int(size))
		if err != nil {
			return nil, fmt.Errorf("texture compression: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported texture wrapper version %d", version)
	}
	if len(data) != int(size) {
		return nil, fmt.Errorf("texture size mismatch: got %d, expected %d", len(data), size)
	}
	return data, nil
}

func textureUint24(b []byte) int {
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16
}

func textureBlockSize(width, height, blockWidth, blockHeight, blockBytes int) (int, error) {
	if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
		return 0, err
	}
	if blockWidth <= 0 || blockHeight <= 0 || blockBytes <= 0 {
		return 0, fmt.Errorf("invalid texture block geometry")
	}
	blocksWide := (width-1)/blockWidth + 1
	blocksHigh := (height-1)/blockHeight + 1
	if blocksWide > pixel.MaxBytes/blockBytes || blocksHigh > pixel.MaxBytes/(blocksWide*blockBytes) {
		return 0, fmt.Errorf("texture block storage exceeds size limit")
	}
	return blocksWide * blocksHigh * blockBytes, nil
}

func astcPayload(data []byte, width, height int) ([]byte, error) {
	// Also accept a standalone ASTC file, which has exactly one surface and mip.
	if !bytes.HasPrefix(data, []byte{0x13, 0xab, 0xa1, 0x5c}) {
		var err error
		data, err = texturePayload(data)
		if err != nil {
			return nil, err
		}
	}
	if len(data) < 16 || !bytes.Equal(data[:4], []byte{0x13, 0xab, 0xa1, 0x5c}) {
		return nil, fmt.Errorf("invalid ASTC signature")
	}
	bw, bh := int(data[4]), int(data[5])
	valid := false
	// The complete set of two-dimensional footprints in the ASTC specification.
	for _, block := range [][2]int{{4, 4}, {5, 4}, {5, 5}, {6, 5}, {6, 6}, {8, 5}, {8, 6}, {8, 8}, {10, 5}, {10, 6}, {10, 8}, {10, 10}, {12, 10}, {12, 12}} {
		valid = valid || (bw == block[0] && bh == block[1])
	}
	if !valid || data[6] != 1 || textureUint24(data[13:16]) != 1 {
		return nil, fmt.Errorf("unsupported ASTC block or volume geometry")
	}
	if textureUint24(data[7:10]) != width || textureUint24(data[10:13]) != height {
		return nil, fmt.Errorf("ASTC dimensions do not match CSI")
	}
	size, err := textureBlockSize(width, height, bw, bh, 16)
	if err != nil {
		return nil, err
	}
	if len(data)-16 != size {
		return nil, fmt.Errorf("ASTC block length mismatch: got %d, expected %d", len(data)-16, size)
	}
	return data, nil
}

// Texture codecs encode CoreUI's premultiplied channels. Their lossy output may
// place a color above alpha; CoreUI clamps those values when rendering a bitmap.
func finishTexture(img *image.RGBA, opaque bool) *image.RGBA {
	for i := 0; i < len(img.Pix); i += 4 {
		if opaque {
			img.Pix[i+3] = 255
		}
		for j := range 3 {
			img.Pix[i+j] = min(img.Pix[i+j], img.Pix[i+3])
		}
	}
	return img
}

// DecodeDXTC handles the ATEC container emitted by CoreUI. Its format
// identifiers are independent of the current AppleTextureConverter SDK enum.
func DecodeDXTC(data []byte, width, height int, opaque bool) (image.Image, error) {
	data, err := texturePayload(data)
	if err != nil {
		return nil, err
	}
	if string(data[:4]) != "ATEC" || data[4] != 4 || data[5] != 4 || data[6] != 0 {
		return nil, fmt.Errorf("invalid DXTC ATEC header")
	}
	if textureUint24(data[7:10]) != width || textureUint24(data[10:13]) != height {
		return nil, fmt.Errorf("DXTC dimensions do not match CSI")
	}
	format := textureUint24(data[13:16])
	blockBytes := 16
	switch format {
	case 33, 36: // BC1, BC4 UNORM
		blockBytes = 8
	case 34, 35, 38, 42: // BC2, BC3, BC5 UNORM, BC7
	default:
		return nil, fmt.Errorf("unsupported DXTC ATEC format %d", format)
	}
	size, err := textureBlockSize(width, height, 4, 4, blockBytes)
	if err != nil {
		return nil, err
	}
	if len(data)-16 != size {
		return nil, fmt.Errorf("DXTC block length mismatch: got %d, expected %d", len(data)-16, size)
	}
	if format == 42 {
		// DDS's DX10 header supplies the BC7 format and explicitly restricts the
		// texture to one two-dimensional surface, with no mipmaps or array.
		dds := make([]byte, 148+size)
		copy(dds, "DDS ")
		for offset, value := range map[int]uint32{4: 124, 8: 0x81007, 12: uint32(height), 16: uint32(width), 20: uint32(size), 28: 1, 76: 32, 80: 4, 108: 0x1000, 128: 98, 132: 3, 140: 1} {
			binary.LittleEndian.PutUint32(dds[offset:], value)
		}
		copy(dds[84:], "DX10")
		copy(dds[148:], data[16:])
		img, err := decodeNativeTexture(dds, width, height)
		if err != nil {
			return nil, fmt.Errorf("BC7 decoding: %w", err)
		}
		return finishTexture(img, opaque), nil
	}
	return finishTexture(decodeBCBlocks(data[16:], width, height, format, blockBytes), opaque), nil
}

// decodeBCBlocks follows the BC1-BC5 block layouts in the Microsoft Direct3D
// block compression specification. Bounds and exact block count are validated
// by DecodeDXTC before entering the block loop.
func decodeBCBlocks(data []byte, width, height, format, blockBytes int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for by := 0; by < height; by += 4 {
		for bx := 0; bx < width; bx += 4 {
			block := data[:blockBytes]
			data = data[blockBytes:]
			var pixels [16][4]byte
			if format == 36 || format == 38 {
				r := decodeBCAlpha(block[:8])
				var g [16]byte
				if format == 38 {
					g = decodeBCAlpha(block[8:])
				}
				for i := range pixels {
					pixels[i] = [4]byte{r[i], g[i], 0, 255}
					if format == 36 {
						pixels[i] = [4]byte{r[i], r[i], r[i], 255}
					}
				}
			} else {
				colors := block
				if format != 33 {
					colors = block[8:]
				}
				c0, c1 := binary.LittleEndian.Uint16(colors), binary.LittleEndian.Uint16(colors[2:])
				var palette [4][4]byte
				for c, field := range [][2]int{{11, 31}, {5, 63}, {0, 31}} {
					shift, mask := field[0], field[1]
					a, b := int(c0>>shift)&mask, int(c1>>shift)&mask
					// Interpolate normalized endpoints before quantizing to eight
					// bits. CoreUI rounds halfway results toward the lower value.
					quantize := func(v, divisor int) byte {
						return byte((v*255 + (divisor-1)/2) / divisor)
					}
					palette[0][c], palette[1][c] = quantize(a, mask), quantize(b, mask)
					if format != 33 || c0 > c1 {
						palette[2][c], palette[3][c] = quantize(2*a+b, 3*mask), quantize(a+2*b, 3*mask)
					} else {
						palette[2][c] = quantize(a+b, 2*mask)
					}
				}
				palette[0][3], palette[1][3] = 255, 255
				palette[2][3] = 255
				if format != 33 || c0 > c1 {
					palette[3][3] = 255
				}
				indices := binary.LittleEndian.Uint32(colors[4:])
				for i := range pixels {
					pixels[i] = palette[(indices>>uint(i*2))&3]
				}
				if format == 34 {
					alpha := binary.LittleEndian.Uint64(block)
					for i := range pixels {
						pixels[i][3] = byte((alpha>>uint(i*4))&15) * 17
					}
				} else if format == 35 {
					alpha := decodeBCAlpha(block[:8])
					for i := range pixels {
						pixels[i][3] = alpha[i]
					}
				}
			}
			for y := 0; y < 4 && by+y < height; y++ {
				for x := 0; x < 4 && bx+x < width; x++ {
					copy(img.Pix[(by+y)*img.Stride+(bx+x)*4:], pixels[y*4+x][:])
				}
			}
		}
	}
	return img
}

func decodeBCAlpha(block []byte) [16]byte {
	a, b := int(block[0]), int(block[1])
	palette := [8]byte{byte(a), byte(b)}
	steps := 7
	if a <= b {
		steps = 5
		palette[6], palette[7] = 0, 255
	}
	for i := 1; i < steps; i++ {
		palette[i+1] = byte(((steps-i)*a + i*b) / steps)
	}
	bits := binary.LittleEndian.Uint64(block) >> 16
	var out [16]byte
	for i := range out {
		out[i] = palette[(bits>>uint(i*3))&7]
	}
	return out
}
