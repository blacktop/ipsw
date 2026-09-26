package car

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func TestOrientImageByteDepthLimit(t *testing.T) {
	// Bounds-only fixtures: orientation creates a view without reading pixels.
	bounds := image.Rect(0, 0, 8192, 8192)
	src := &image.RGBA{Rect: bounds}
	for _, orientation := range []uint32{0, 1, 6} {
		got, err := orientImage(src, orientation)
		if err != nil {
			t.Fatalf("orientation %d rejected an 8-bit image within the size limit: %v", orientation, err)
		}
		if got.Bounds() != bounds || got.ColorModel() != color.RGBAModel {
			t.Fatalf("orientation %d changed bounds or color model", orientation)
		}
		if _, err := orientImage(&image.RGBA64{Rect: bounds}, orientation); err == nil {
			t.Fatalf("orientation %d accepted a 16-bit image exceeding the size limit", orientation)
		}
	}
}

func TestOrientImage(t *testing.T) {
	// Non-zero source origin catches accidental use of atlas coordinates after
	// cropping. Distinct low bytes and alpha catch 8-bit or premultiply changes.
	src := image.NewNRGBA64(image.Rect(7, 11, 10, 13))
	for i := range 6 {
		src.SetNRGBA64(7+i%3, 11+i/3, color.NRGBA64{R: uint16(i+1)*1000 + 7, G: 299, B: 1703, A: 32769})
	}
	for orientation, rows := range [][]int{
		{1, 2, 3, 4, 5, 6}, // absent
		{1, 2, 3, 4, 5, 6}, // top left
		{3, 2, 1, 6, 5, 4}, // top right
		{6, 5, 4, 3, 2, 1}, // bottom right
		{4, 5, 6, 1, 2, 3}, // bottom left
		{1, 4, 2, 5, 3, 6}, // left top
		{4, 1, 5, 2, 6, 3}, // right top
		{6, 3, 5, 2, 4, 1}, // right bottom
		{3, 6, 2, 5, 1, 4}, // left bottom
	} {
		got, err := orientImage(src, uint32(orientation))
		if err != nil {
			t.Fatal(err)
		}
		w, h := 3, 2
		if orientation >= 5 {
			w, h = h, w
		}
		if got.Bounds().Dx() != w || got.Bounds().Dy() != h || got.ColorModel() != color.NRGBA64Model {
			t.Fatalf("orientation %d changed size or precision: %v", orientation, got.Bounds())
		}
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, got); err != nil {
			t.Fatal(err)
		}
		decoded, err := png.Decode(&encoded)
		if err != nil {
			t.Fatal(err)
		}
		for i, value := range rows {
			want := color.NRGBA64{R: uint16(value)*1000 + 7, G: 299, B: 1703, A: 32769}
			if actual := decoded.At(i%w, i/w); actual != want {
				t.Fatalf("orientation %d pixel %d = %v, want %v", orientation, i, actual, want)
			}
		}
		if orientation > 1 {
			if r, g, b, a := got.At(-1, 0).RGBA(); r|g|b|a != 0 {
				t.Fatalf("orientation %d returned a pixel outside bounds", orientation)
			}
		}
	}
	if _, err := orientImage(src, 9); err == nil {
		t.Fatal("accepted an invalid orientation")
	}
	if _, err := orientImage(nil, 1); err == nil {
		t.Fatal("accepted a nil image")
	}
	if _, err := orientImage(&image.Gray{Rect: image.Rect(0, 0, pixel.MaxBytes, 2)}, 6); err == nil {
		t.Fatal("accepted excessive image dimensions")
	}
}
