package pixel

import (
	"encoding/binary"
	"image/color"
	"math"
	"testing"
)

func TestHalfFloatPixels(t *testing.T) {
	for _, tt := range []struct {
		name   string
		bits   [4]uint16
		opaque bool
		want   color.NRGBA64
	}{
		{"opaque", [4]uint16{0x3400, 0x3800, 0x3a00, 0x3c00}, false, color.NRGBA64{16384, 32768, 49151, 65535}},
		{"premultiplied", [4]uint16{0x3400, 0x3000, 0, 0x3800}, false, color.NRGBA64{32768, 16384, 0, 32768}},
		{"extended", [4]uint16{0x3a00, 0xb400, 0x3000, 0x3800}, false, color.NRGBA64{65535, 0, 16384, 32768}},
		{"zero-alpha", [4]uint16{0x3c00, 0x3c00, 0x3c00, 0}, false, color.NRGBA64{}},
		{"opaque-flag", [4]uint16{0x3400, 0x3800, 0, 0}, true, color.NRGBA64{16384, 32768, 0, 65535}},
		{"subnormal", [4]uint16{1, 2, 3, 4}, false, color.NRGBA64{16384, 32768, 49151, 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var data []byte
			for _, bits := range tt.bits {
				data = binary.LittleEndian.AppendUint16(data, bits)
			}
			data = append(data, 77, 88, 99)
			data = append(data, data[:8]...)
			img, err := DecodeHalfFloatRGBA(data, 1, 2, 11, tt.opaque)
			if err != nil {
				t.Fatal(err)
			}
			for y := range 2 {
				if got := img.NRGBA64At(0, y); got != tt.want {
					t.Fatalf("row %d = %v, want %v", y, got, tt.want)
				}
			}
		})
	}
	for _, bits := range []uint16{0x7c00, 0xfc00, 0x7c01, 0x7fff} {
		data := binary.LittleEndian.AppendUint16(nil, bits)
		data = append(data, 0, 0, 0, 0, 0, 0x3c)
		if _, err := DecodeHalfFloatRGBA(data, 1, 1, 0, false); err == nil {
			t.Errorf("accepted non-finite component %04x", bits)
		}
	}
	if _, err := DecodeHalfFloatRGBA(make([]byte, 7), 1, 1, 0, false); err == nil {
		t.Fatal("accepted truncated pixel")
	}
}

func TestHalfFloatComponents(t *testing.T) {
	for bits, want := range map[uint16]float64{
		0: 0, 0x8000: math.Copysign(0, -1), 1: math.Ldexp(1, -24),
		0x3ff: math.Ldexp(1023, -24), 0x400: math.Ldexp(1, -14),
		0x3c00: 1, 0xbc00: -1, 0x7bff: 65504,
	} {
		if got := halfFloat(bits); got != want || math.Signbit(got) != math.Signbit(want) {
			t.Errorf("half %04x = %g, want %g", bits, got, want)
		}
	}
}
