package deepmap2

import (
	"encoding/binary"
	"image/color"
	"testing"
)

func legacyFixture(method, format byte, payload []byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, 1)
	data = binary.LittleEndian.AppendUint32(data, uint32(format))
	data = binary.LittleEndian.AppendUint64(data, uint64(8+len(payload)))
	data = append(data, 'd', 'm', 'a', 'p', method, 0, 10, format)
	return append(data, payload...)
}

func legacyLiteral(data []byte) []byte {
	var compressed []byte
	for len(data) > 0 {
		n := min(15, len(data))
		compressed = append(compressed, byte(0xe0+n))
		compressed = append(compressed, data[:n]...)
		data = data[n:]
	}
	compressed = append(compressed, 6, 0, 0, 0, 0, 0, 0, 0)
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(compressed))), compressed...)
}

func TestLegacyDeepmapMethods(t *testing.T) {
	for _, tt := range []struct {
		name    string
		method  byte
		payload []byte
		want    [2]color.RGBA
	}{
		{"raw", 1, []byte{10, 20, 30, 255, 40, 50, 60, 255}, [2]color.RGBA{{30, 20, 10, 255}, {60, 50, 40, 255}}},
		{"lossless", 3, legacyLiteral([]byte{10, 20, 30, 255, 40, 50, 60, 255}), [2]color.RGBA{{30, 20, 10, 255}, {60, 50, 40, 255}}},
		{"predictor", 2, legacyLiteral([]byte{255, 255, 0, 0, 0, 0, 0, 0, 0, 200, 40, 20, 200, 40, 20, 0}), [2]color.RGBA{{85, 105, 105, 255}, {85, 105, 105, 255}}},
		{"palette", 4, append([]byte{2, 0, 0, 0, 10, 20, 30, 255, 40, 50, 60, 255}, legacyLiteral([]byte{255, 255, 0, 1})...), [2]color.RGBA{{30, 20, 10, 255}, {60, 50, 40, 255}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			img, err := DecodeLegacy(legacyFixture(tt.method, 4, tt.payload), 2, 1, "ARGB", false, false)
			if err != nil {
				t.Fatal(err)
			}
			for x, want := range tt.want {
				if got := color.RGBAModel.Convert(img.At(x, 0)); got != want {
					t.Fatalf("pixel %d = %v, want %v", x, got, want)
				}
			}
		})
	}
}

func TestLegacyDeepmapTiles(t *testing.T) {
	var payload []byte
	for _, geometry := range [][3]int{{256, 256, 10}, {1, 256, 20}, {256, 1, 30}, {1, 1, 40}} {
		data := make([]byte, geometry[0]*geometry[1]*4)
		for i := 0; i < len(data); i += 4 {
			data[i], data[i+3] = byte(geometry[2]), 255
		}
		payload = append(payload, legacyLiteral(data)...)
	}
	img, err := DecodeLegacy(legacyFixture(3, 4, payload), 257, 257, "ARGB", false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range [][3]int{{255, 255, 10}, {256, 255, 20}, {255, 256, 30}, {256, 256, 40}} {
		if got := color.RGBAModel.Convert(img.At(point[0], point[1])).(color.RGBA).B; got != byte(point[2]) {
			t.Fatalf("pixel (%d,%d) = %d", point[0], point[1], got)
		}
	}
}

func TestLegacyDeepmapWide(t *testing.T) {
	data := legacyFixture(2, 20, legacyLiteral([]byte{255, 255, 0, 0, 0, 0, 0, 0, 0, 200, 40, 20, 200, 40, 20, 0}))
	for _, tt := range []struct {
		floatingPoint bool
		want          color.RGBA64
	}{
		{true, color.RGBA64{13440, 13440, 10880, 65535}},
		{false, color.RGBA64{0x3290, 0x3290, 0x3150, 0x3c00}},
	} {
		img, err := DecodeLegacy(data, 2, 1, "RGBW", tt.floatingPoint, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := color.RGBA64Model.Convert(img.At(0, 0)); got != tt.want {
			t.Fatalf("floating point %t: got %v, want %v", tt.floatingPoint, got, tt.want)
		}
	}
}

func TestLegacyDeepmapPredictors(t *testing.T) {
	// A nonuniform first row distinguishes left/up/adaptive/average predictors.
	for predictor, want := range map[byte][2]color.RGBA{
		1: {{92, 117, 117, 255}, {39, 49, 45, 255}},
		2: {{7, 12, 12, 255}, {25, 33, 31, 255}},
		3: {{92, 117, 117, 255}, {39, 49, 45, 255}},
		4: {{92, 117, 117, 255}, {75, 94, 91, 255}},
	} {
		planes := []byte{255, 255, 255, 255, 0, predictor}
		planes = append(planes, make([]byte, 12)...)
		planes = append(planes, 200, 40, 20, 50, 10, 10, 20, 10, 6, 40, 2, 4, 0, 0)
		img, err := DecodeLegacy(legacyFixture(2, 4, legacyLiteral(planes)), 2, 2, "ARGB", false, false)
		if err != nil {
			t.Fatal(err)
		}
		for x := range 2 {
			if got := color.RGBAModel.Convert(img.At(x, 1)); got != want[x] {
				t.Fatalf("predictor %d pixel %d = %v, want %v", predictor, x, got, want[x])
			}
		}
		wide, err := DecodeLegacy(legacyFixture(2, 20, legacyLiteral(planes)), 2, 2, "RGBW", true, false)
		if err != nil {
			t.Fatal(err)
		}
		for x := range 2 {
			// Wide dmap uses RGB axes and color units of 1/512.
			c := want[x]
			expect := color.RGBA64{uint16(c.B) * 128, uint16(c.G) * 128, uint16(c.R) * 128, 65535}
			if got := color.RGBA64Model.Convert(wide.At(x, 1)); got != expect {
				t.Fatalf("wide predictor %d pixel %d = %v, want %v", predictor, x, got, expect)
			}
		}
	}
}

func TestLegacyDeepmapMalformed(t *testing.T) {
	good := legacyFixture(3, 4, legacyLiteral([]byte{10, 20, 30, 255}))
	for n := range len(good) {
		if _, err := DecodeLegacy(good[:n], 1, 1, "ARGB", false, false); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, data := range [][]byte{
		legacyFixture(0, 4, nil), legacyFixture(1, 4, []byte{1, 2, 3}),
		legacyFixture(3, 4, legacyLiteral([]byte{1, 2, 3})),
		legacyFixture(3, 4, append(legacyLiteral([]byte{1, 2, 3, 4}), 0)),
		legacyFixture(4, 4, append([]byte{1, 0, 0, 0, 1, 2, 3, 4}, legacyLiteral([]byte{255, 1})...)),
		legacyFixture(2, 4, legacyLiteral([]byte{255, 5, 0, 0, 0, 0, 0, 0})),
		legacyFixture(2, 4, legacyLiteral([]byte{255, 3, 0, 0, 0, 0, 0, 0})),
	} {
		if _, err := DecodeLegacy(data, 1, 1, "ARGB", false, false); err == nil {
			t.Fatal("accepted malformed dmap")
		}
	}
}

func FuzzDecodeLegacyDeepmap(f *testing.F) {
	f.Add(legacyFixture(3, 4, legacyLiteral([]byte{1, 2, 3, 255})), uint8(1), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, width, height uint8) {
		_, _ = DecodeLegacy(data, int(width), int(height), "ARGB", false, false)
	})
}
