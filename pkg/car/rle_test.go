package car

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func rleFixture(width int, rows ...[]byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, 4)
	data = binary.LittleEndian.AppendUint32(data, uint32(width))
	data = binary.LittleEndian.AppendUint32(data, uint32(len(rows)))
	offset := 12 + 4*len(rows)
	for _, row := range rows {
		data = binary.LittleEndian.AppendUint32(data, uint32(offset))
		offset += len(row)
	}
	for _, row := range rows {
		data = append(data, row...)
	}
	return data
}

func TestDecodeRLERows(t *testing.T) {
	// First row mixes a literal pixel and a repeated pair. The second is literal.
	data := rleFixture(3,
		[]byte{1, 0, 0, 0, 10, 20, 30, 255, 2, 0, 0, 128, 40, 50, 60, 255},
		[]byte{3, 0, 0, 0, 1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255})
	got, err := decodeRLERows(data, 3, 2, 16, PixFmtARGB)
	want := []byte{10, 20, 30, 255, 40, 50, 60, 255, 40, 50, 60, 255, 0, 0, 0, 0,
		1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 0, 0, 0, 0}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("decoded rows = %x, %v", got, err)
	}
}

func TestDecodeRLEPixelFormats(t *testing.T) {
	for _, tt := range []struct {
		format   string
		encoding uint32
		pixel    []byte
	}{
		{PixFmtGrayscale, 1, []byte{80}},
		{PixFmtGray, 3, []byte{64, 255}},
		{PixFmtRGB555, 3, []byte{0, 0x7c}},
		{PixFmtGray16, 4, []byte{0, 0x40, 255, 255}},
	} {
		t.Run(tt.format, func(t *testing.T) {
			// One literal followed by a pair of repeated pixels; row padding is zero.
			row := append([]byte{1, 0, 0, 0}, tt.pixel...)
			row = append(row, 2, 0, 0, 128)
			row = append(row, tt.pixel...)
			data := rleFixture(3, row)
			binary.LittleEndian.PutUint32(data, tt.encoding)
			got, err := decodeRLERows(data, 3, 1, len(tt.pixel)*3+2, tt.format)
			want := append(bytes.Repeat(tt.pixel, 3), 0, 0)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got %x, %v; want %x", got, err, want)
			}
			binary.LittleEndian.PutUint32(data, 20)
			if _, err := decodeRLERows(data, 3, 1, 0, tt.format); err == nil {
				t.Fatal("accepted incompatible encoding")
			}
		})
	}
	if _, err := decodeRLERows(rleFixture(1, []byte{1, 0, 0, 0, 1, 2, 3, 4}), 1, 1, 0, PixFmtARGB16); err == nil {
		t.Fatal("accepted unverified wide RLE encoding")
	}
}

func TestDecodeRLERowsMalformed(t *testing.T) {
	good := rleFixture(1, []byte{1, 0, 0, 0, 1, 2, 3, 255})
	for n := range len(good) {
		if _, err := decodeRLERows(good[:n], 1, 1, 0, PixFmtARGB); err == nil {
			t.Fatalf("accepted %d-byte truncation", n)
		}
	}
	for _, tt := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"format", 0, 20}, {"width", 4, 2}, {"height", 8, 2},
		{"offset in header", 12, 12}, {"offset past end", 12, 1000},
		{"zero run", 16, 0}, {"oversized run", 16, 2},
		{"oversized repeat", 16, 0x80000002}, {"packet kind", 16, 0x01000001},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Clone(good)
			binary.LittleEndian.PutUint32(data[tt.offset:], tt.value)
			if _, err := decodeRLERows(data, 1, 1, 0, PixFmtARGB); err == nil {
				t.Fatal("accepted malformed RLE")
			}
		})
	}
	for _, row := range [][]byte{
		{1, 0, 0, 128},             // Missing repeat pixel.
		{1, 0, 0, 0, 1, 2, 3, 255}, // Only one of two pixels.
	} {
		if _, err := decodeRLERows(rleFixture(2, row), 2, 1, 0, PixFmtARGB); err == nil {
			t.Fatalf("accepted malformed row %x", row)
		}
	}
	if _, err := decodeRLERows(good, 1, 1, pixel.MaxBytes+1, PixFmtARGB); err == nil {
		t.Fatal("accepted excessive stride")
	}
}

func FuzzDecodeRLERows(f *testing.F) {
	f.Add(rleFixture(2, []byte{2, 0, 0, 128, 10, 20, 30, 255}), byte(2), byte(1))
	f.Fuzz(func(t *testing.T, data []byte, width, height byte) {
		// Bound fuzz allocations while exercising external lengths and offsets.
		for _, format := range []string{PixFmtARGB, PixFmtGray, PixFmtGray16, PixFmtGrayscale} {
			_, _ = decodeRLERows(data, int(width), int(height), 0, format)
		}
	})
}

func TestDecodeRLESharedAndReorderedRows(t *testing.T) {
	data := rleFixture(1, []byte{1, 0, 0, 128, 10, 20, 30, 255},
		[]byte{1, 0, 0, 0, 40, 50, 60, 255}, nil)
	// Logical rows use physical rows 2, 1, 2; the last row shares row 1's data.
	for i, offset := range []uint32{32, 24, 32} {
		binary.LittleEndian.PutUint32(data[12+4*i:], offset)
	}
	data = append(data, 0xff) // Bytes after a complete row are not its packets.
	got, err := decodeRLERows(data, 1, 3, 0, PixFmtARGB)
	want := []byte{40, 50, 60, 255, 10, 20, 30, 255, 40, 50, 60, 255}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("shared rows = %x, %v", got, err)
	}
}
