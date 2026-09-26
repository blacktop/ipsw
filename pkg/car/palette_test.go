package car

import (
	"encoding/binary"
	"image/color"
	"testing"
)

func paletteFixture(count int, words ...uint16) []byte {
	data := binary.LittleEndian.AppendUint32(nil, cafef00dMagic)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint16(data, uint16(count))
	for i := range count {
		data = append(data, 255, byte(i), byte(i>>8), 40)
	}
	for _, word := range words {
		data = binary.LittleEndian.AppendUint16(data, word)
	}
	return data
}

func TestPaletteIndexWidths(t *testing.T) {
	for _, tt := range []struct {
		count int
		word  uint16
	}{
		{1, 0}, {2, 0x8000}, {3, 0x8000}, {5, 0x4000},
		{17, 0x1000}, {257, 0x0100}, {4096, 0x0fff},
	} {
		img, err := decodePaletteImage(paletteFixture(tt.count, tt.word), 1, 1, PixFmtARGB, SRGB, false)
		if err != nil {
			t.Fatalf("%d colors: %v", tt.count, err)
		}
		want := color.RGBA{byte(tt.count - 1), byte((tt.count - 1) >> 8), 40, 255}
		if got := color.RGBAModel.Convert(img.At(0, 0)); got != want {
			t.Errorf("%d colors: got %v, want %v", tt.count, got, want)
		}
	}
	// Each three-pixel row begins a new word; padding does not become a pixel.
	img, err := decodePaletteImage(paletteFixture(3, 0x1800, 0x9000), 3, 2, PixFmtARGB, SRGB, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []uint8{0, 1, 2, 2, 1, 0} {
		if got := color.RGBAModel.Convert(img.At(i%3, i/3)).(color.RGBA).R; got != want {
			t.Fatalf("pixel %d: got %d, want %d", i, got, want)
		}
	}
}

func TestPaletteWideAndOpaque(t *testing.T) {
	data := paletteFixture(1)
	data = data[:10]
	for _, v := range []uint16{2500, 5000, 7500, 10000, 0} {
		data = binary.LittleEndian.AppendUint16(data, v)
	}
	// Native CoreUI also interprets its reconstructed half words as integers
	// for ordinary color spaces; CGContext renders alpha 0x3c00 as 60/255.
	for _, space := range []colorSpaceID{SRGB, DisplayP3, ExtendedSRGB, ExtendedLinear} {
		img, err := decodePaletteImage(data, 1, 1, PixFmtARGB16, space, false)
		if err != nil {
			t.Fatal(err)
		}
		want := color.RGBA64{0x3a00, 0x3800, 0x3400, 0x3c00}
		if space == ExtendedSRGB || space == ExtendedLinear {
			want = color.RGBA64{49151, 32768, 16384, 65535}
		}
		if got := color.RGBA64Model.Convert(img.At(0, 0)); got != want {
			t.Fatalf("%s wide palette = %v, want %v", space, got, want)
		}
	}
	data = paletteFixture(1, 0)
	data[10] = 1
	img, err := decodePaletteImage(data, 1, 1, PixFmtARGB, SRGB, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a != 65535 {
		t.Fatalf("opaque palette alpha = %d", a)
	}
}

func TestPaletteMalformed(t *testing.T) {
	good := paletteFixture(3, 0x1800)
	for n := range len(good) {
		if _, err := decodePaletteImage(good[:n], 3, 1, PixFmtARGB, SRGB, false); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, data := range [][]byte{
		paletteFixture(0, 0), paletteFixture(4097, 0), paletteFixture(3, 0xc000),
		append(paletteFixture(1, 0), 0),
	} {
		if _, err := decodePaletteImage(data, 1, 1, PixFmtARGB, SRGB, false); err == nil {
			t.Fatal("accepted malformed palette")
		}
	}
	good[4] = 2
	if _, err := decodePaletteImage(good, 3, 1, PixFmtARGB, SRGB, false); err == nil {
		t.Fatal("accepted unknown version")
	}
}

func FuzzDecodePaletteImage(f *testing.F) {
	f.Add(paletteFixture(3, 0x1800), uint8(3), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, width, height uint8) {
		_, _ = decodePaletteImage(data, int(width), int(height), PixFmtARGB, SRGB, false)
	})
}
