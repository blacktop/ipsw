package deepmap2

import (
	"encoding/binary"
	"image"
	"image/color"
	"testing"
)

func deepmap2TestTile(col, row uint32, gray byte) []byte {
	blob := deepmap2TestBlob(1, 1, 1, 1, []byte{gray})
	data := binary.LittleEndian.AppendUint32([]byte("KCBC"), col)
	data = binary.LittleEndian.AppendUint32(data, row)
	data = binary.LittleEndian.AppendUint32(data, 1)
	data = binary.LittleEndian.AppendUint32(data, uint32(20+len(blob)))
	return append(data, blob...)
}

func TestDeepmap2WideTileGrid(t *testing.T) {
	// An integer tile and a binary16 tile require a wide destination. The red
	// component's low byte proves assembly did not pass through an RGBA8 image.
	data := deepmap2TestTile(0, 0, 19)
	blob := deepmap2TestBlob(1, 0x14, 1, 1, []byte{1, 0x34, 0, 0, 0, 0, 0, 0x3c})
	tile := binary.LittleEndian.AppendUint32([]byte("KCBC"), 1)
	tile = binary.LittleEndian.AppendUint32(tile, 0)
	tile = binary.LittleEndian.AppendUint32(tile, 1)
	tile = binary.LittleEndian.AppendUint32(tile, uint32(20+len(blob)))
	data = append(data, append(tile, blob...)...)
	decoded, err := Decode(deepmap2TestWrapper(data), 2, 1, "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	img, ok := decoded.(*image.NRGBA64)
	if !ok {
		t.Fatalf("grid type = %T", decoded)
	}
	if got := img.NRGBA64At(0, 0); got != (color.NRGBA64{0x1313, 0x1313, 0x1313, 65535}) {
		t.Fatalf("byte tile = %v", got)
	}
	if got := img.NRGBA64At(1, 0); got != (color.NRGBA64{16400, 0, 0, 65535}) {
		t.Fatalf("binary16 tile = %v", got)
	}
}

func TestDeepmap2IntegerTileAlphaPrecision(t *testing.T) {
	data := deepmap2TestTile(0, 0, 19)
	blob := deepmap2TestBlob(1, 0x14, 1, 1, []byte{1, 0, 2, 0, 3, 0, 0x89, 0x12})
	tile := binary.LittleEndian.AppendUint32([]byte("KCBC"), 1)
	tile = binary.LittleEndian.AppendUint32(tile, 0)
	tile = binary.LittleEndian.AppendUint32(tile, 1)
	tile = binary.LittleEndian.AppendUint32(tile, uint32(20+len(blob)))
	data = append(data, append(tile, blob...)...)
	decoded, err := Decode(deepmap2TestWrapper(data), 2, 1, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	// Unpremultiplying and premultiplying integer samples during assembly loses
	// one unit per component for this alpha, even with a 16-bit destination.
	if got := color.RGBA64Model.Convert(decoded.At(1, 0)).(color.RGBA64); got != (color.RGBA64{1, 2, 3, 0x1289}) {
		t.Fatalf("premultiplied tile = %v", got)
	}
}

func TestDeepmap2TileGrid(t *testing.T) {
	// Unsorted file order exercises row/column placement.
	data := deepmap2TestTile(1, 1, 40)
	data = append(data, deepmap2TestTile(0, 0, 10)...)
	data = append(data, deepmap2TestTile(0, 1, 30)...)
	data = append(data, deepmap2TestTile(1, 0, 20)...)
	deepmap2TestPixels(t, deepmap2TestWrapper(data), 2, 2, "",
		[]byte{10, 10, 10, 255, 20, 20, 20, 255, 30, 30, 30, 255, 40, 40, 40, 255})
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"incomplete", data[:len(data)-33]},
		{"duplicate", append(append([]byte(nil), data...), deepmap2TestTile(0, 0, 50)...)},
		{"truncated", data[:len(data)-1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(deepmap2TestWrapper(tc.data), 2, 2, "", false, false); err == nil {
				t.Fatal("accepted malformed grid")
			}
		})
	}
}
