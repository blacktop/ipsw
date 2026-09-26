//go:build !darwin || !cgo

package render

import (
	"fmt"
	"image"
)

func renderNative(_ []byte, format string, _, _ int) (image.Image, error) {
	return nil, fmt.Errorf("%s rendering requires macOS with cgo; export the original payload instead", format)
}
