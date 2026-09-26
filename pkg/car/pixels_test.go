package car

import (
	"bytes"
	"image/color"
	"testing"
)

func TestDecodePixels(t *testing.T) {
	for _, tt := range []struct {
		name, format string
		data         []byte
		want         color.Color
	}{
		{"bgra", PixFmtARGB, []byte{0x10, 0x20, 0x40, 0x80}, color.RGBA{64, 32, 16, 128}},
		{"gray", PixFmtGrayscale, []byte{42}, color.NRGBA64{0x2a2a, 0x2a2a, 0x2a2a, 0xffff}},
		{"gray-alpha", PixFmtGray, []byte{32, 64}, color.RGBA{32, 32, 32, 64}},
		{"gray16-alpha", PixFmtGray16, []byte{0, 0x40, 0, 0x80}, color.RGBA64{0x4000, 0x4000, 0x4000, 0x8000}},
		{"rgba16", PixFmtARGB16, []byte{0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0xff, 0xff}, color.NRGBA64{0x1234, 0x5678, 0x9abc, 0xffff}},
		{"rgb555", PixFmtRGB555, []byte{0x1f, 0xfc}, color.NRGBA64{0xffff, 0, 0xffff, 0xffff}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			img, err := decodePixels(tt.data, 1, 1, tt.format, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			r, g, b, a := img.At(0, 0).RGBA()
			wr, wg, wb, wa := tt.want.RGBA()
			if r != wr || g != wg || b != wb || a != wa {
				t.Fatalf("pixel = %04x %04x %04x %04x, want %04x %04x %04x %04x", r, g, b, a, wr, wg, wb, wa)
			}
		})
	}
}

func TestDecodePixelsOpaqueStride(t *testing.T) {
	for _, tt := range []struct {
		format string
		pixel  []byte
		want   color.RGBA64
	}{
		{PixFmtARGB, []byte{1, 2, 3, 0}, color.RGBA64{0x303, 0x202, 0x101, 0xffff}},
		{PixFmtGray, []byte{4, 0}, color.RGBA64{0x404, 0x404, 0x404, 0xffff}},
		{PixFmtARGB16, []byte{1, 2, 3, 4, 5, 6, 0, 0}, color.RGBA64{0x201, 0x403, 0x605, 0xffff}},
		{PixFmtGray16, []byte{7, 8, 0, 0}, color.RGBA64{0x807, 0x807, 0x807, 0xffff}},
	} {
		t.Run(tt.format, func(t *testing.T) {
			padding := []byte{99, 98, 97}
			data := append(append(bytes.Clone(tt.pixel), padding...), tt.pixel...)
			img, err := decodePixels(data, 1, 2, tt.format, len(tt.pixel)+len(padding), true)
			if err != nil {
				t.Fatal(err)
			}
			for y := range 2 {
				if got := color.RGBA64Model.Convert(img.At(0, y)).(color.RGBA64); got != tt.want {
					t.Fatalf("row %d: %v, want %v", y, got, tt.want)
				}
			}
			if !bytes.Equal(data[len(tt.pixel):len(tt.pixel)+len(padding)], padding) {
				t.Fatal("opacity changed row padding")
			}
		})
	}
}

func TestDecodePixelsStrideAndBounds(t *testing.T) {
	// Padding is not another pixel; the final row need not include padding.
	img, err := decodePixels([]byte{1, 2, 99, 3, 4}, 2, 2, PixFmtGrayscale, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := color.GrayModel.Convert(img.At(1, 1)).(color.Gray).Y; got != 4 {
		t.Fatalf("last pixel = %d", got)
	}
	for _, tt := range []struct {
		w, h, stride int
		data         []byte
	}{
		{1, 2, 8, make([]byte, 8)}, // enough packed bytes, missing the padded second row
		{2, 1, 4, make([]byte, 8)}, // stride too short
		{1, 1, -1, make([]byte, 4)},
		{0, 1, 0, nil},
		{1 << 32, 1 << 32, 0, nil},
	} {
		if _, err := decodePixels(tt.data, tt.w, tt.h, PixFmtARGB, tt.stride, false); err == nil {
			t.Errorf("accepted invalid layout %+v", tt)
		}
	}
}
