// Package render rasterizes self-contained image and document payloads.
package render

import (
	"fmt"
	"image"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// Decode renders an extracted original. The output is 8-bit
// premultiplied sRGB. Zero dimensions use the source size; positive dimensions
// request an exact canvas size. PDF rendering uses the first page's crop box,
// with one pixel per point by default and aspect-preserving scaling otherwise.
// Orientation is left to the catalog's explicit orientation option.
func Decode(data []byte, format string, width, height int) (image.Image, error) {
	if len(data) == 0 || len(data) > pixel.MaxBytes {
		return nil, fmt.Errorf("invalid rendered payload size: %d", len(data))
	}
	if width < 0 || height < 0 || (width == 0) != (height == 0) {
		return nil, fmt.Errorf("invalid render dimensions: %dx%d", width, height)
	}
	if width != 0 {
		if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
			return nil, err
		}
	}
	switch format {
	case "HEIF", "PDF ":
	case "SVG ":
		if err := validateRenderSVG(data); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported rendered payload format: %q", format)
	}
	return renderNative(data, format, width, height)
}
