//go:build darwin && cgo

package texture

import (
	"image/color"
	"testing"
)

func TestNativeTextureASTC(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		img, err := DecodeASTC(textureFixture(astcFixture(), compressed), 4, 4, "", false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := img.At(3, 3); got != (color.RGBA{17, 34, 51, 68}) {
			t.Fatalf("native ASTC channels: %v", got)
		}
	}
}

func TestNativeTextureBC7(t *testing.T) {
	// One BC7 mode-six block: equal opaque-red endpoints and zero indices.
	// Mode 6 has seven-bit endpoints, shared per-endpoint p-bits and one subset.
	block := make([]byte, 16)
	bit := 0
	write := func(value, count int) {
		for i := range count {
			block[bit/8] |= byte((value>>i)&1) << uint(bit%8)
			bit++
		}
	}
	write(64, 7)
	for _, value := range []int{127, 127, 0, 0, 0, 0, 127, 127} {
		write(value, 7)
	}
	write(1, 1)
	write(1, 1)
	img, err := DecodeDXTC(atecFixture(4, 4, 42, block), 4, 4, false)
	if err != nil {
		t.Fatal(err)
	}
	// Shared p-bits make nominal zero endpoints equal to one.
	if got := img.At(2, 1); got != (color.RGBA{255, 1, 1, 255}) {
		t.Fatalf("native BC7 channels: %v", got)
	}
}
