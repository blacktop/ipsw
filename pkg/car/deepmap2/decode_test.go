package deepmap2

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"testing"
)

func deepmap2TestBlob(method, format byte, width, height uint16, payload []byte) []byte {
	data := []byte{'d', 'm', 'p', '2', method, 0, 10, format}
	data = binary.LittleEndian.AppendUint16(data, width)
	data = binary.LittleEndian.AppendUint16(data, height)
	return append(data, payload...)
}

func deepmap2TestWrapper(blob []byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, 1)
	data = binary.LittleEndian.AppendUint32(data, 4)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(blob)))
	return append(data, blob...)
}

func deepmap2TestStream(data []byte) []byte {
	stream := binary.LittleEndian.AppendUint32([]byte("bvx-"), uint32(len(data)))
	stream = append(stream, data...)
	return append(stream, "bvx$"...)
}

func deepmap2TestChunks(chunks ...[]byte) []byte {
	var data []byte
	for _, chunk := range chunks {
		data = binary.LittleEndian.AppendUint32(data, uint32(len(chunk)))
		data = append(data, chunk...)
	}
	return data
}

func deepmap2TestPlanes(alpha, predictors []byte, residuals []int16) []byte {
	data := append([]byte(nil), alpha...)
	data = append(data, predictors...)
	high, low := make([]byte, len(residuals)), make([]byte, len(residuals))
	for i, residual := range residuals {
		value := int(residual)
		encoded := value * 2
		if value < 0 {
			encoded = -value*2 + 1
		}
		high[i], low[i] = byte(encoded>>8), byte(encoded)
	}
	data = append(data, high...)
	return append(data, low...)
}

func deepmap2TestPixels(t *testing.T, data []byte, width, height int, format string, want []byte) {
	t.Helper()
	decoded, err := Decode(data, width, height, format, false, false)
	if err != nil {
		t.Fatal(err)
	}
	img, ok := decoded.(*image.RGBA)
	if !ok || !bytes.Equal(img.Pix, want) {
		t.Fatalf("pixels = %v, want %v", decoded, want)
	}
}

func TestDeepmap2RawAndLossless(t *testing.T) {
	for _, tc := range []struct {
		name    string
		format  byte
		csi     string
		payload []byte
		want    []byte
	}{
		{"gray", 1, "GRAY", []byte{19}, []byte{19, 19, 19, 255}},
		{"gray-alpha", 2, "GA8 ", []byte{19, 128}, []byte{19, 19, 19, 128}},
		{"bgr", 3, "", []byte{10, 20, 30}, []byte{30, 20, 10, 255}},
		{"bgra", 4, "ARGB", []byte{10, 20, 30, 128}, []byte{30, 20, 10, 128}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []byte{1, 3} {
				payload := tc.payload
				if method == 3 {
					payload = deepmap2TestChunks(deepmap2TestStream(payload))
				}
				blob := deepmap2TestBlob(method, tc.format, 1, 1, payload)
				deepmap2TestPixels(t, deepmap2TestWrapper(blob), 1, 1, tc.csi, tc.want)
			}
		})
	}
}

func TestDeepmap2Predictors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		predictor byte
		residuals []int16
		want      []byte
	}{
		{"none", 0, []int16{1, 2, 3}, []byte{1, 2, 3}},
		{"paeth-up", 1, []int16{1, 2, 3}, []byte{11, 22, 33}},
		{"paeth-left", 1, []int16{100, 2, 3}, []byte{110, 112, 115}},
		{"left", 2, []int16{1, 2, 3}, []byte{1, 3, 6}},
		{"up", 3, []int16{1, 2, 3}, []byte{11, 22, 33}},
		{"mean", 4, []int16{1, 2, 3}, []byte{11, 18, 27}},
		{"negative", 3, []int16{-1, -2, -3}, []byte{9, 18, 27}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			residuals := append([]int16{10, 20, 30}, tc.residuals...)
			planes := deepmap2TestPlanes(nil, []byte{0, tc.predictor}, residuals)
			blob := deepmap2TestBlob(2, 1, 3, 2, deepmap2TestStream(planes))
			var want []byte
			for _, gray := range append([]byte{10, 20, 30}, tc.want...) {
				want = append(want, gray, gray, gray, 255)
			}
			deepmap2TestPixels(t, deepmap2TestWrapper(blob), 3, 2, "", want)
		})
	}
}

func TestDeepmap2ColorAlphaAndPadding(t *testing.T) {
	// Full plane offsets include both source rows even when KCBC requests only
	// the first row. Y=100, Co=20, Cg=-10 yields CoreUI BGR axes (95,95,115).
	planes := deepmap2TestPlanes([]byte{128, 0}, []byte{0, 0}, []int16{100, 20, -10, 0, 0, 0})
	blob := deepmap2TestBlob(2, 4, 1, 2, deepmap2TestChunks(deepmap2TestStream(planes)))
	deepmap2TestPixels(t, deepmap2TestWrapper(blob), 1, 1, "ARGB", []byte{95, 95, 115, 128})
	blob[5] = 1 // Scale chroma by two.
	deepmap2TestPixels(t, deepmap2TestWrapper(blob), 1, 1, "ARGB", []byte{90, 90, 130, 128})
}

func TestDeepmap2AlignedPlanes(t *testing.T) {
	planes := deepmap2TestPlanes([]byte{128}, []byte{0}, []int16{19})
	planes = append(planes, make([]byte, 16-len(planes))...)
	blob := deepmap2TestBlob(2, 2, 1, 1, deepmap2TestStream(planes))
	deepmap2TestPixels(t, deepmap2TestWrapper(blob), 1, 1, "GA8 ", []byte{19, 19, 19, 128})
}

func TestDeepmap2HalfFloatPixels(t *testing.T) {
	pixel := []byte{0, 0x34, 0, 0x30, 0, 0, 0, 0x38} // premultiplied (0.25,0.125,0,0.5)
	for _, method := range []byte{1, 3} {
		payload := pixel
		if method == 3 {
			payload = deepmap2TestStream(payload)
		}
		data := deepmap2TestWrapper(deepmap2TestBlob(method, 0x14, 1, 1, payload))
		decoded, err := Decode(data, 1, 1, "RGBW", true, false)
		if err != nil {
			t.Fatal(err)
		}
		img, ok := decoded.(*image.NRGBA64)
		if !ok || img.NRGBA64At(0, 0) != (color.NRGBA64{32768, 16384, 0, 32768}) {
			t.Fatalf("method %d: binary16 pixels = %v", method, decoded)
		}
	}
	first := deepmap2TestStream(append(bytes.Clone(pixel), pixel...))
	last := deepmap2TestStream(append([]byte{0, 0, 0, 0, 0, 0x3c, 0, 0x3c}, pixel...))
	data := deepmap2TestWrapper(deepmap2TestBlob(3, 0x14, 1, 2, deepmap2TestChunks(first, last)))
	decoded, err := Decode(data, 1, 3, "RGBW", true, false)
	if err != nil {
		t.Fatal(err)
	}
	img, ok := decoded.(*image.NRGBA64)
	if !ok || img.NRGBA64At(0, 2) != (color.NRGBA64{0, 0, 65535, 65535}) {
		t.Fatalf("binary16 chunk placement = %v", decoded)
	}
	for _, malformed := range [][]byte{
		deepmap2TestBlob(1, 0x14, 1, 1, pixel[:4]),
		deepmap2TestBlob(3, 0x14, 1, 1, deepmap2TestStream(pixel[:4])),
		deepmap2TestBlob(3, 0x14, 1, 2, deepmap2TestStream(pixel)),
		deepmap2TestBlob(3, 0x14, 1, 1, deepmap2TestChunks(first, last)),
	} {
		if _, err := Decode(deepmap2TestWrapper(malformed), 0, 0, "RGBW", true, false); err == nil {
			t.Fatal("accepted malformed binary16 data")
		}
	}
}

func TestDeepmap2WidePredictors(t *testing.T) {
	// Expected binary16 words come from native CoreUI reconstruction. An
	// ordinary color space exposes the stored words as premultiplied integers.
	want := []color.RGBA64{
		{0x2900, 0x2940, 0x28c0, 0x3c00}, {0x2da0, 0x2e20, 0x2ce0, 0x3c00},
		{0x2bc0, 0x2c20, 0x2a40, 0x3c00}, {0x2da0, 0x2e20, 0x2ce0, 0x3c00},
		{0x31b0, 0x31e0, 0x30b0, 0x3c00},
	}
	wantByte := []color.RGBA{{19, 21, 20, 255}, {39, 49, 45, 255}, {25, 33, 31, 255}, {39, 49, 45, 255}, {75, 94, 91, 255}}
	for predictor, expected := range want {
		planes := deepmap2TestPlanes([]byte{255, 255, 255, 255}, []byte{0, byte(predictor)},
			[]int16{100, 20, 10, 25, 5, 5, 10, 5, 3, 20, 1, 2})
		planes = append(planes, 0, 0) // dmp2 planes align to sixteen bytes.
		blob := deepmap2TestBlob(2, 0x14, 2, 2, legacyLiteral(planes))
		decoded, err := Decode(deepmap2TestWrapper(blob), 2, 2, "RGBW", false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := color.RGBA64Model.Convert(decoded.At(1, 1)).(color.RGBA64); got != expected {
			t.Errorf("predictor %d: %v, want %v", predictor, got, expected)
		}
		// Cropping a padded chunk must retain the original plane offsets.
		cropped, err := Decode(deepmap2TestWrapper(blob), 2, 1, "RGBW", false, false)
		if err != nil || cropped.At(1, 0) != decoded.At(1, 0) {
			t.Fatalf("predictor %d: padded chunk = %v, %v", predictor, cropped, err)
		}
		blob = deepmap2TestBlob(2, 4, 2, 2, legacyLiteral(planes))
		byteImage, err := Decode(deepmap2TestWrapper(blob), 2, 2, "ARGB", false, false)
		if err != nil || byteImage.At(1, 1) != wantByte[predictor] {
			t.Fatalf("predictor %d: LZVN byte image = %v, %v", predictor, byteImage, err)
		}
	}
}

func TestDeepmap2PredictorWrapAndChunkReset(t *testing.T) {
	planes := deepmap2TestPlanes(nil, []byte{2}, []int16{32767, 1})
	blob := deepmap2TestBlob(2, 1, 2, 1, deepmap2TestStream(planes))
	deepmap2TestPixels(t, deepmap2TestWrapper(blob), 2, 1, "", []byte{255, 255, 255, 255, 0, 0, 0, 255})
	first := deepmap2TestStream(deepmap2TestPlanes(nil, []byte{0}, []int16{10}))
	second := deepmap2TestStream(deepmap2TestPlanes(nil, []byte{3}, []int16{2}))
	blob = deepmap2TestBlob(2, 1, 1, 1, deepmap2TestChunks(first, second))
	deepmap2TestPixels(t, deepmap2TestWrapper(blob), 1, 2, "", []byte{10, 10, 10, 255, 2, 2, 2, 255})
}

func TestDeepmap2Palette(t *testing.T) {
	for _, typ := range []uint16{3, 4} {
		palette := binary.LittleEndian.AppendUint16(nil, 2)
		palette = binary.LittleEndian.AppendUint16(palette, typ)
		palette = append(palette, 10, 20, 30, 128, 40, 50, 60, 255)
		indices := []byte{1, 0}
		want := []byte{60, 50, 40, 255, 30, 20, 10, 128}
		if typ == 3 {
			indices = append([]byte{64, 32}, indices...)
			want[3], want[7] = 64, 32
		}
		payload := append(palette, deepmap2TestChunks(deepmap2TestStream(indices))...)
		blob := deepmap2TestBlob(4, 4, 2, 1, payload)
		deepmap2TestPixels(t, deepmap2TestWrapper(blob), 2, 1, "ARGB", want)
	}
}

func TestDeepmap2RejectsMalformedInput(t *testing.T) {
	valid := deepmap2TestWrapper(deepmap2TestBlob(1, 1, 1, 1, []byte{10}))
	cases := map[string][]byte{
		"short-header":  valid[:15],
		"length":        valid[:len(valid)-1],
		"raw-truncated": deepmap2TestWrapper(deepmap2TestBlob(1, 4, 1, 1, []byte{10})),
		"pixel-format":  deepmap2TestWrapper(deepmap2TestBlob(1, 20, 1, 1, []byte{10})),
		"method":        deepmap2TestWrapper(deepmap2TestBlob(99, 1, 1, 1, []byte{10})),
		"predictor": deepmap2TestWrapper(deepmap2TestBlob(2, 1, 1, 1,
			deepmap2TestStream(deepmap2TestPlanes(nil, []byte{5}, []int16{10})))),
		"palette-index": deepmap2TestWrapper(deepmap2TestBlob(4, 4, 1, 1,
			append([]byte{1, 0, 4, 0, 10, 20, 30, 255}, deepmap2TestStream([]byte{1})...))),
		"missing-rows": deepmap2TestWrapper(deepmap2TestBlob(3, 1, 1, 2, deepmap2TestStream([]byte{10}))),
		"wide-predictor": deepmap2TestWrapper(deepmap2TestBlob(2, 20, 1, 1,
			legacyLiteral([]byte{255, 5, 0, 0, 0, 0, 0, 0}))),
		"wide-plane-truncated": deepmap2TestWrapper(deepmap2TestBlob(2, 20, 1, 1,
			legacyLiteral([]byte{255, 0, 0, 0, 0, 0, 0}))),
		"wide-predictor-missing-rows": deepmap2TestWrapper(deepmap2TestBlob(2, 20, 1, 2,
			legacyLiteral([]byte{255, 0, 0, 0, 0, 0, 0, 0}))),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(data, 0, 0, "", false, false); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	if _, err := Decode(valid, 1, maxBytes, "", false, false); err == nil {
		t.Fatal("accepted oversized output")
	}
	if _, err := Decode(valid, 2, 1, "", false, false); err == nil {
		t.Fatal("accepted mismatched width")
	}
}

func FuzzDeepmap2(f *testing.F) {
	f.Add(deepmap2TestWrapper(deepmap2TestBlob(1, 1, 1, 1, []byte{10})))
	f.Add(deepmap2TestWrapper(deepmap2TestBlob(3, 0x14, 1, 1,
		deepmap2TestStream([]byte{0, 0x34, 0, 0x30, 0, 0, 0, 0x38}))))
	f.Add(deepmap2TestWrapper(deepmap2TestBlob(2, 0x14, 1, 1,
		legacyLiteral([]byte{255, 0, 0, 0, 0, 200, 40, 20, 0, 0, 0, 0, 0, 0, 0, 0}))))
	f.Add(deepmap2TestWrapper(deepmap2TestBlob(3, 2, 1, 1, deepmap2TestStream([]byte{10, 128}))))
	f.Add(deepmap2TestWrapper(deepmap2TestBlob(2, 4, 1, 1,
		deepmap2TestStream(deepmap2TestPlanes([]byte{128}, []byte{0}, []int16{19, 2, -1})))))
	f.Add(deepmap2TestWrapper(deepmap2TestBlob(4, 4, 1, 1,
		append([]byte{1, 0, 4, 0, 10, 20, 30, 255}, deepmap2TestStream([]byte{0})...))))
	f.Add(deepmap2TestWrapper(deepmap2TestTile(0, 0, 10)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, _ = Decode(data, 1, 1, "", true, false)
	})
}
