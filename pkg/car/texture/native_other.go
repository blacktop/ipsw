//go:build !darwin || !cgo

package texture

import (
	"fmt"
	"image"
)

func decodeNativeTexture(_ []byte, _, _ int) (*image.RGBA, error) {
	return nil, fmt.Errorf("native texture decoding requires macOS with cgo and ImageIO")
}
