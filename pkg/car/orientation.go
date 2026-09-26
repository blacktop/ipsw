package car

import (
	"fmt"
	"image"
	"image/color"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// orientImage applies the TIFF/Exif orientation to a final rendition. Callers
// must crop atlas references first: their coordinates describe the stored image.
// The view preserves the source samples, alpha representation and color model;
// it does not allocate another raster or reduce 16-bit images to 8 bits.
func orientImage(src image.Image, orientation uint32) (image.Image, error) {
	if src == nil {
		return nil, fmt.Errorf("cannot orient a nil image")
	}
	if orientation > 8 {
		return nil, fmt.Errorf("invalid EXIF orientation: %d", orientation)
	}
	b := src.Bounds()
	bpp := 4
	model := src.ColorModel()
	if model == color.RGBA64Model || model == color.NRGBA64Model || model == color.Gray16Model {
		bpp = 8
	}
	if b.Empty() || uint64(b.Max.X)-uint64(b.Min.X) > uint64(pixel.MaxBytes/bpp) ||
		uint64(b.Max.Y)-uint64(b.Min.Y) > uint64(pixel.MaxBytes/bpp) {
		return nil, fmt.Errorf("invalid orientation image bounds: %v", b)
	}
	if _, _, err := pixel.Layout(b.Dx(), b.Dy(), bpp, 0); err != nil {
		return nil, err
	}
	if orientation <= 1 {
		return src, nil
	}
	w, h := b.Dx(), b.Dy()
	if orientation >= 5 {
		w, h = h, w
	}
	return &orientedImage{src: src, orientation: orientation, bounds: image.Rect(0, 0, w, h)}, nil
}

type orientedImage struct {
	src         image.Image
	orientation uint32
	bounds      image.Rectangle
}

func (p *orientedImage) ColorModel() color.Model { return p.src.ColorModel() }
func (p *orientedImage) Bounds() image.Rectangle { return p.bounds }

func (p *orientedImage) At(x, y int) color.Color {
	if !image.Pt(x, y).In(p.bounds) {
		return color.RGBA64{}
	}
	b := p.src.Bounds()
	w, h := b.Dx(), b.Dy()
	switch p.orientation {
	case 2: // horizontal reflection
		x = w - 1 - x
	case 3: // 180 degrees
		x, y = w-1-x, h-1-y
	case 4: // vertical reflection
		y = h - 1 - y
	case 5: // transpose across the top-left diagonal
		x, y = y, x
	case 6: // 90 degrees clockwise
		x, y = y, h-1-x
	case 7: // transpose across the bottom-left diagonal
		x, y = w-1-y, h-1-x
	case 8: // 90 degrees counterclockwise
		x, y = w-1-y, x
	}
	return p.src.At(b.Min.X+x, b.Min.Y+y)
}
