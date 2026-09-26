package car

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"

	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// decodeJPEGLZFSE joins JPEG color planes with their losslessly stored alpha.
// CoreUI encodes premultiplied RGB in the JPEG, so applying alpha a second time
// would darken translucent pixels.
func decodeJPEGLZFSE(chunks []bitmapChunk, width, height int, opaque bool) (image.Image, error) {
	if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
		return nil, err
	}
	if len(chunks) == 0 || len(chunks) > 65536 {
		return nil, fmt.Errorf("invalid JPEG+LZFSE chunk count: %d", len(chunks))
	}
	rows, encoded := 0, 0
	for _, chunk := range chunks {
		n := int(chunk.rows)
		if n == 0 && len(chunks) == 1 {
			n = height
		}
		if n <= 0 || n > height-rows || len(chunk.data) > pixel.MaxBytes-encoded {
			return nil, fmt.Errorf("invalid JPEG+LZFSE chunk dimensions or size")
		}
		rows += n
		encoded += len(chunk.data)
	}
	if rows != height {
		return nil, fmt.Errorf("JPEG+LZFSE chunks contain %d rows, expected %d", rows, height)
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	y := 0
	for i, chunk := range chunks {
		rows := int(chunk.rows)
		if rows == 0 {
			rows = height
		}
		if err := decodeJPEGAlpha(chunk.data, img, y, rows, opaque); err != nil {
			return nil, fmt.Errorf("JPEG+LZFSE chunk %d: %w", i, err)
		}
		y += rows
	}
	return img, nil
}

func decodeJPEGAlpha(data []byte, dst *image.RGBA, startY, height int, opaque bool) error {
	if len(data) < 20 {
		return fmt.Errorf("truncated header")
	}
	version := binary.LittleEndian.Uint32(data)
	innerChunks := binary.LittleEndian.Uint32(data[4:])
	alphaSize := binary.LittleEndian.Uint32(data[8:])
	stride := binary.LittleEndian.Uint32(data[12:])
	jpegSize := binary.LittleEndian.Uint32(data[16:])
	if version != 0 || innerChunks != 0 {
		return fmt.Errorf("unsupported version %d or inner chunk count %d", version, innerChunks)
	}
	if uint64(alphaSize)+uint64(jpegSize) != uint64(len(data)-20) || alphaSize == 0 || jpegSize == 0 {
		return fmt.Errorf("invalid alpha or JPEG payload length")
	}
	width := dst.Rect.Dx()
	alphaStride, _, err := pixel.Layout(width, height, 1, int(stride))
	if err != nil || stride == 0 {
		return fmt.Errorf("invalid alpha row stride: %d", stride)
	}
	alpha, err := compression.DecodeLZFSE(data[20:20+int(alphaSize)], alphaStride*height)
	if err != nil {
		return fmt.Errorf("decode alpha: %w", err)
	}
	if len(alpha) != alphaStride*height {
		return fmt.Errorf("alpha plane has %d bytes, expected %d", len(alpha), alphaStride*height)
	}
	data = data[20+int(alphaSize):]
	config, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("read JPEG dimensions: %w", err)
	}
	// Check before Decode, which allocates from dimensions inside the JPEG.
	if config.Width != width || config.Height != height {
		return fmt.Errorf("JPEG dimensions %dx%d do not match chunk %dx%d", config.Width, config.Height, width, height)
	}
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode JPEG: %w", err)
	}
	for y := range height {
		for x := range width {
			c := color.RGBAModel.Convert(img.At(x, y)).(color.RGBA)
			a := alpha[y*alphaStride+x]
			if opaque {
				a = 255
			}
			// Lossy JPEG can make a component slightly larger than alpha.
			// Clamp to the premultiplied range, as CoreGraphics rendering does.
			dst.SetRGBA(x, startY+y, color.RGBA{R: min(c.R, a), G: min(c.G, a), B: min(c.B, a), A: a})
		}
	}
	return nil
}
