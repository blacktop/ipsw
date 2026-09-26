// Package deepmap2 decodes CoreUI Deepmap2 and legacy Deepmap images.
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

// CREDIT: deepmap2 reconstruction is adapted from skytoup/car-parser

const maxBytes = 256 << 20

type header struct {
	method, scale, format byte
	storedFormat          byte
	width, height         int
	paletteType           uint16
	palette               []byte
}

// Decode consumes the CoreUI wrapper (version, pixel format, u64
// length), followed by a dmp2 image or a KCBC tile grid. Integer images retain
// CoreUI's premultiplied RGBA8 or RGBA16. Set floatingPoint to interpret wide
// channels as binary16 and produce bounded NRGBA64; opaque ignores stored alpha.
// pixelFormat is the CSI FourCC, or empty to use the stored channel layout.
func Decode(data []byte, width, height int, pixelFormat string, floatingPoint, opaque bool) (image.Image, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("deepmap2: truncated CoreUI header")
	}
	if version := binary.LittleEndian.Uint32(data); version != 1 {
		return nil, fmt.Errorf("deepmap2: unsupported CoreUI version %d: %w", version, errors.ErrUnsupported)
	}
	length := binary.LittleEndian.Uint64(data[8:])
	if length != uint64(len(data)-16) {
		return nil, fmt.Errorf("deepmap2: declared payload length %d does not match %d", length, len(data)-16)
	}
	if length > maxBytes {
		return nil, fmt.Errorf("deepmap2: payload exceeds size limit")
	}
	data = data[16:]
	if len(data) >= 4 && string(data[:4]) == "KCBC" {
		return decodeTiles(data, width, height, pixelFormat, floatingPoint, opaque)
	}
	return decodeImage(data, width, height, pixelFormat, floatingPoint, opaque)
}

func readHeader(data []byte, pixelFormat string) (header, []byte, error) {
	var h header
	if len(data) < 12 || string(data[:4]) != "dmp2" {
		return h, nil, fmt.Errorf("deepmap2: missing or truncated dmp2 header")
	}
	h = header{
		method: data[4], scale: data[5], format: data[7], storedFormat: data[7],
		width: int(binary.LittleEndian.Uint16(data[8:])), height: int(binary.LittleEndian.Uint16(data[10:])),
	}
	// CSI describes the channel layout. The dmp2 format still controls sample
	// precision: 0x14 is four 16-bit channels, not four byte channels. Extended
	// color spaces interpret those channels as binary16 floating-point values.
	switch pixelFormat {
	case "ARGB", "RGBW":
		h.format = 4
	case "GA8 ":
		h.format = 2
	}
	if h.storedFormat == 0x14 {
		h.format = 4
	}
	if h.format < 1 || h.format > 4 {
		return h, nil, fmt.Errorf("deepmap2: unsupported pixel format %d: %w", h.format, errors.ErrUnsupported)
	}
	if h.width == 0 || h.height == 0 {
		return h, nil, fmt.Errorf("deepmap2: zero dimensions")
	}
	data = data[12:]
	if h.method == 4 {
		if len(data) < 4 {
			return h, nil, fmt.Errorf("deepmap2: truncated palette header")
		}
		n := int(binary.LittleEndian.Uint16(data))
		h.paletteType = binary.LittleEndian.Uint16(data[2:])
		if n == 0 || n > 256 || len(data)-4 < n*4 {
			return h, nil, fmt.Errorf("deepmap2: invalid or truncated palette of %d entries", n)
		}
		if h.paletteType != 3 && h.paletteType != 4 {
			return h, nil, fmt.Errorf("deepmap2: unsupported palette type %d: %w", h.paletteType, errors.ErrUnsupported)
		}
		h.palette = data[4 : 4+n*4]
		data = data[4+n*4:]
	}
	return h, data, nil
}

func checkDimensions(width, height int) error {
	if width <= 0 || height <= 0 || width > maxBytes/4 || height > maxBytes/4/width {
		return fmt.Errorf("deepmap2: invalid or oversized dimensions %dx%d", width, height)
	}
	return nil
}

func decodeImage(data []byte, width, height int, pixelFormat string, floatingPoint, opaque bool) (image.Image, error) {
	h, payload, err := readHeader(data, pixelFormat)
	if err != nil {
		return nil, err
	}
	if width == 0 {
		width = h.width
	}
	if height == 0 {
		height = h.height
	}
	if width != h.width {
		return nil, fmt.Errorf("deepmap2: width %d does not match dmp2 width %d", width, h.width)
	}
	if err := checkDimensions(width, height); err != nil {
		return nil, err
	}
	if h.method < 1 || h.method > 4 {
		return nil, fmt.Errorf("deepmap2: unsupported method %d: %w", h.method, errors.ErrUnsupported)
	}
	if h.storedFormat == 0x14 {
		return decodeWide(h, payload, width, height, floatingPoint, opaque)
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	if opaque {
		// Ignore stored alpha only after byte reconstruction. Floating-point
		// samples handle opacity before unpremultiplication in the wide path.
		defer func() {
			for i := 3; i < len(img.Pix); i += 4 {
				img.Pix[i] = 255
			}
		}()
	}
	if h.method == 4 {
		return img, decodePalette(img.Pix, h, payload, width*height)
	}
	if h.method == 1 {
		if len(payload) != width*height*int(h.format) {
			return nil, fmt.Errorf("deepmap2: raw pixel size mismatch")
		}
		rawPixels(img.Pix, payload, h.format)
		return img, nil
	}
	chunks, framed := readChunks(payload)
	if !framed {
		chunks = [][]byte{payload}
	}
	row := 0
	for _, chunk := range chunks {
		if row >= height {
			return nil, fmt.Errorf("deepmap2: extra pixel chunks")
		}
		rowBytes := width * int(h.format)
		if h.method == 2 {
			components := 1
			if h.format >= 3 {
				components = 3
			}
			rowBytes = 1 + width*components*2
			if h.format == 2 || h.format == 4 {
				rowBytes += width
			}
		}
		// A chunk may contain padding rows. Keep its complete planes until
		// reconstruction; truncating first would move the alpha/high/low offsets.
		maxRows := max(h.height, height-row)
		if rowBytes > (maxBytes-15)/maxRows {
			return nil, fmt.Errorf("deepmap2: decoded planes exceed size limit")
		}
		limit := rowBytes * maxRows
		if h.method == 2 {
			limit = (limit + 15) &^ 15
		}
		decoded, err := compression.Decode(chunk, limit, true)
		if err != nil {
			return nil, err
		}
		sourceRows := len(decoded) / rowBytes
		// Default's split planes can have up to 15 trailing alignment bytes.
		// Use the expected row count first so padding on tiny images cannot be
		// mistaken for additional pixel rows.
		if h.method == 2 && len(decoded)%16 == 0 {
			expectedRows := min(h.height, sourceRows)
			if (expectedRows*rowBytes+15)&^15 == len(decoded) {
				sourceRows = expectedRows
			}
			if padding := len(decoded) - sourceRows*rowBytes; padding <= 15 {
				decoded = decoded[:sourceRows*rowBytes]
			}
		}
		if sourceRows == 0 || len(decoded)%rowBytes != 0 {
			return nil, fmt.Errorf("deepmap2: decoded chunk does not contain whole rows")
		}
		rows := min(sourceRows, height-row)
		dst := img.Pix[row*width*4 : (row+rows)*width*4]
		if h.method == 2 {
			if err := predictPixels(dst, decoded, h, width, sourceRows, rows); err != nil {
				return nil, err
			}
		} else {
			rawPixels(dst, decoded[:rows*rowBytes], h.format)
		}
		row += rows
	}
	if row != height {
		return nil, fmt.Errorf("deepmap2: decoded %d rows, expected %d", row, height)
	}
	return img, nil
}

func decodeWide(h header, payload []byte, width, height int, floatingPoint, opaque bool) (image.Image, error) {
	stride, size, err := pixel.Layout(width, height, 8, 0)
	if err != nil {
		return nil, err
	}
	if h.method == 1 {
		if len(payload) != size {
			return nil, fmt.Errorf("deepmap2: 16-bit raw pixel size mismatch")
		}
		return decodeWidePixels(payload, width, height, stride, floatingPoint, opaque)
	}
	if h.method == 2 {
		return decodeWidePredict(h, payload, width, height, floatingPoint, opaque)
	}
	if h.method != 3 {
		return nil, fmt.Errorf("deepmap2: unsupported 16-bit method %d: %w", h.method, errors.ErrUnsupported)
	}
	chunks, framed := readChunks(payload)
	if !framed {
		chunks = [][]byte{payload}
	}
	pixels := make([]byte, 0, size)
	row := 0
	for _, chunk := range chunks {
		if row >= height {
			return nil, fmt.Errorf("deepmap2: extra 16-bit chunks")
		}
		maxRows := max(h.height, height-row)
		if maxRows > maxBytes/stride {
			return nil, fmt.Errorf("deepmap2: 16-bit planes exceed size limit")
		}
		decoded, err := compression.Decode(chunk, stride*maxRows, true)
		if err != nil {
			return nil, err
		}
		if len(decoded) == 0 || len(decoded)%stride != 0 {
			return nil, fmt.Errorf("deepmap2: 16-bit chunk does not contain whole rows")
		}
		rows := min(len(decoded)/stride, height-row)
		pixels = append(pixels, decoded[:rows*stride]...)
		row += rows
	}
	if row != height {
		return nil, fmt.Errorf("deepmap2: decoded %d 16-bit rows, expected %d", row, height)
	}
	return decodeWidePixels(pixels, width, height, stride, floatingPoint, opaque)
}

func decodeWidePredict(h header, payload []byte, width, height int, floatingPoint, opaque bool) (image.Image, error) {
	chunks, framed := readChunks(payload)
	if !framed {
		chunks = [][]byte{payload}
	}
	rect := image.Rect(0, 0, width, height)
	var dst draw.Image = image.NewRGBA64(rect)
	if floatingPoint {
		dst = image.NewNRGBA64(rect)
	}
	rowBytes, y := width*7+1, 0 // alpha bytes, row predictor, high/low RGB planes
	for _, chunk := range chunks {
		if y >= height {
			return nil, fmt.Errorf("deepmap2: extra wide predictor chunks")
		}
		maxRows := max(h.height, height-y)
		if rowBytes > (maxBytes-15)/maxRows {
			return nil, fmt.Errorf("deepmap2: wide predictor planes exceed size limit")
		}
		decoded, err := compression.Decode(chunk, (rowBytes*maxRows+15)&^15, true)
		if err != nil {
			return nil, err
		}
		sourceRows := len(decoded) / rowBytes
		expectedRows := min(h.height, sourceRows)
		if len(decoded)%16 == 0 && (expectedRows*rowBytes+15)&^15 == len(decoded) {
			sourceRows = expectedRows
		}
		padding := len(decoded) - sourceRows*rowBytes
		if sourceRows == 0 || padding > 15 || padding != 0 && len(decoded)%16 != 0 {
			return nil, fmt.Errorf("deepmap2: incomplete wide predictor planes")
		}
		if _, _, err := pixel.Layout(width, sourceRows, 8, 0); err != nil {
			return nil, err
		}
		// dmap and dmp2 share the wide residual units and binary16 output;
		// only framing, geometry, and plane alignment differ.
		img, err := legacyWidePredict(decoded, width, sourceRows, h.scale, floatingPoint, opaque)
		if err != nil {
			return nil, err
		}
		rows := min(sourceRows, height-y)
		draw.Draw(dst, image.Rect(0, y, width, y+rows), img, image.Point{}, draw.Src)
		y += rows
	}
	if y != height {
		return nil, fmt.Errorf("deepmap2: decoded %d wide predictor rows, expected %d", y, height)
	}
	return dst, nil
}

func decodeWidePixels(data []byte, width, height, stride int, floatingPoint, opaque bool) (image.Image, error) {
	if floatingPoint {
		return pixel.DecodeHalfFloatRGBA(data, width, height, stride, opaque)
	}
	return pixel.DecodeRGBA64(data, width, height, stride, opaque)
}

// A complete sequence of nonempty u32-length-prefixed streams is distinct from
// the raw Apple compression stream accepted by the other branch.
func readChunks(data []byte) ([][]byte, bool) {
	var chunks [][]byte
	for len(data) >= 4 {
		n := uint64(binary.LittleEndian.Uint32(data))
		data = data[4:]
		if n == 0 || n > uint64(len(data)) || len(chunks) >= 65536 {
			return nil, false
		}
		chunks = append(chunks, data[:int(n)])
		data = data[int(n):]
	}
	return chunks, len(data) == 0 && len(chunks) != 0
}

func rawPixels(dst, src []byte, format byte) {
	for i, j := 0, 0; i < len(dst); i, j = i+4, j+int(format) {
		dst[i+3] = 255
		if format <= 2 {
			dst[i], dst[i+1], dst[i+2] = src[j], src[j], src[j]
			if format == 2 {
				dst[i+3] = src[j+1]
			}
		} else {
			dst[i], dst[i+1], dst[i+2] = src[j+2], src[j+1], src[j]
			if format == 4 {
				dst[i+3] = src[j+3]
			}
		}
	}
}

func decodePalette(dst []byte, h header, payload []byte, count int) error {
	expected := count
	if h.paletteType == 3 {
		expected *= 2
	}
	chunks, framed := readChunks(payload)
	if !framed {
		chunks = [][]byte{payload}
	}
	decoded := make([]byte, 0, expected)
	for _, chunk := range chunks {
		if len(decoded) == expected {
			return fmt.Errorf("deepmap2: extra palette chunks")
		}
		part, err := compression.Decode(chunk, expected-len(decoded), true)
		if err != nil {
			return err
		}
		decoded = append(decoded, part...)
	}
	if len(decoded) != expected {
		return fmt.Errorf("deepmap2: palette data size %d, expected %d", len(decoded), expected)
	}
	indices := decoded
	if h.paletteType == 3 {
		indices = decoded[count:]
	}
	for i, index := range indices {
		entry := int(index) * 4
		if entry >= len(h.palette) {
			return fmt.Errorf("deepmap2: palette index %d exceeds %d entries", index, len(h.palette)/4)
		}
		p := h.palette[entry : entry+4]
		alpha := p[3]
		if h.paletteType == 3 {
			alpha = decoded[i]
		}
		copy(dst[i*4:], []byte{p[2], p[1], p[0], alpha})
	}
	return nil
}

func predictPixels(dst, data []byte, h header, width, sourceRows, rows int) error {
	components := 1
	if h.format >= 3 {
		components = 3
	}
	count := width * sourceRows
	alphaSize := 0
	if h.format == 2 || h.format == 4 {
		alphaSize = count
	}
	predictors := data[alphaSize : alphaSize+sourceRows]
	high := data[alphaSize+sourceRows : alphaSize+sourceRows+count*components]
	low := data[alphaSize+sourceRows+count*components:]
	prev, current := make([]int16, width*components), make([]int16, width*components)
	for y := range rows {
		predictor := predictors[y]
		if predictor > 4 {
			return fmt.Errorf("deepmap2: unsupported predictor %d: %w", predictor, errors.ErrUnsupported)
		}
		for x := range width {
			base := x * components
			useLeft := false
			if predictor == 1 && x > 0 {
				left, up, upperLeft := int(current[base-components]), int(prev[base]), int(prev[base-components])
				useLeft = abs(up-upperLeft) <= abs(left-upperLeft)
			}
			for c := range components {
				i := base + c
				index := y*width*components + i
				encoded := uint16(low[index]) | uint16(high[index])<<8
				value := int(encoded >> 1)
				if encoded&1 != 0 {
					value = -value // Deepmap2 uses signed magnitude, not protobuf zigzag.
				}
				up := int(prev[i])
				left := 0
				if x > 0 {
					left = int(current[i-components])
				}
				switch predictor {
				case 1:
					if useLeft {
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
				current[i] = int16(value) // The predictor arithmetic deliberately wraps at 16 bits.
			}
			pixel := (y*width + x) * 4
			gray := byte(current[base])
			dst[pixel], dst[pixel+1], dst[pixel+2], dst[pixel+3] = gray, gray, gray, 255
			if components == 3 {
				co, cg := int(current[base+1]), int(current[base+2])
				if h.scale != 0 {
					co, cg = co*2, cg*2
				}
				temp := int(current[base]) - cg/2
				// CoreUI's transformed color axes are BGR ordered.
				dst[pixel] = clamp(temp - co/2)
				dst[pixel+1] = clamp(temp + cg)
				dst[pixel+2] = clamp(temp + co - co/2)
			}
			if alphaSize != 0 {
				dst[pixel+3] = data[y*width+x]
			}
		}
		prev, current = current, prev
	}
	return nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func clamp(n int) byte { return byte(min(255, max(0, n))) }
