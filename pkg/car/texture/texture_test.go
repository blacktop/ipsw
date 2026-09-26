package texture

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"testing"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func textureFixture(payload []byte, compressed bool) []byte {
	version := uint32(0)
	encoded := payload
	if compressed {
		version = 1
		encoded = []byte("bvx-")
		encoded = binary.LittleEndian.AppendUint32(encoded, uint32(len(payload)))
		encoded = append(encoded, payload...)
		encoded = append(encoded, "bvx$"...)
	}
	data := binary.LittleEndian.AppendUint32(nil, version)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(encoded)))
	data = binary.LittleEndian.AppendUint32(data, uint32(len(payload)))
	return append(data, encoded...)
}

func atecFixture(width, height, format int, blocks []byte) []byte {
	header := []byte{'A', 'T', 'E', 'C', 4, 4, 0, byte(width), byte(width >> 8), byte(width >> 16), byte(height), byte(height >> 8), byte(height >> 16), byte(format), 0, 0}
	return textureFixture(append(header, blocks...), false)
}

func TestTexturePayload(t *testing.T) {
	payload := []byte("synthetic texture payload")
	for _, compressed := range []bool{false, true} {
		got, err := texturePayload(textureFixture(payload, compressed))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("compressed=%t got=%x err=%v", compressed, got, err)
		}
	}
	valid := textureFixture(payload, false)
	for _, offset := range []int{0, 4, 8} {
		bad := bytes.Clone(valid)
		bad[offset] ^= 7
		if _, err := texturePayload(bad); err == nil {
			t.Fatalf("accepted malformed header at %d", offset)
		}
	}
	if _, err := texturePayload(valid[:11]); err == nil {
		t.Fatal("accepted truncated wrapper")
	}
}

func TestDecodeDXTCTexture(t *testing.T) {
	// BC1 endpoints red and green; selector indices 0,1,2,3 repeat each row.
	bc1 := []byte{0, 0xf8, 0xe0, 7, 0xe4, 0xe4, 0xe4, 0xe4}
	img, err := DecodeDXTC(atecFixture(3, 2, 33, bc1), 3, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []color.RGBA{{255, 0, 0, 255}, {0, 255, 0, 255}, {170, 85, 0, 255}}
	for x, c := range want {
		if got := img.At(x, 1); got != c {
			t.Errorf("BC1 cropped block x=%d: got %v want %v", x, got, c)
		}
	}
	if img.Bounds() != image.Rect(0, 0, 3, 2) {
		t.Fatal("decoded block padding as image pixels")
	}
	for _, tc := range []struct {
		endpoints []byte
		want      []byte
	}{
		{[]byte{0, 0x18, 0, 0xe0}, []byte{25, 230, 127}},
		{[]byte{0, 0x08, 0, 0x78}, []byte{8, 123, 66}},
	} {
		block := append(bytes.Clone(tc.endpoints), 0xe4, 0xe4, 0xe4, 0xe4)
		img, err := DecodeDXTC(atecFixture(4, 4, 33, block), 4, 4, false)
		if err != nil {
			t.Fatal(err)
		}
		for x, r := range tc.want {
			if got := img.At(x, 0); got != (color.RGBA{r, 0, 0, 255}) {
				t.Fatalf("BC1 endpoint normalization x=%d: %v", x, got)
			}
		}
	}
	transparent := []byte{0, 0, 255, 255, 255, 255, 255, 255}
	img, err = DecodeDXTC(atecFixture(4, 4, 33, transparent), 4, 4, false)
	if err != nil || img.At(0, 0) != (color.RGBA{}) {
		t.Fatalf("BC1 transparent selector: %v %v", img, err)
	}
	// BC2 explicit alpha and BC3 interpolated alpha both use premultiplied
	// CoreUI channels. A red endpoint exceeding alpha must be clamped.
	for _, tc := range []struct {
		name   string
		format int
		alpha  []byte
		want   byte
	}{
		{"BC2", 34, bytes.Repeat([]byte{0x88}, 8), 136},
		{"BC3", 35, []byte{128, 128, 0, 0, 0, 0, 0, 0}, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := append(bytes.Clone(tc.alpha), 0, 0xf8, 0, 0, 0, 0, 0, 0)
			for _, opaque := range []bool{false, true} {
				img, err := DecodeDXTC(atecFixture(4, 4, tc.format, block), 4, 4, opaque)
				if err != nil {
					t.Fatal(err)
				}
				v := tc.want
				if opaque {
					v = 255
				}
				if got := img.At(0, 0); got != (color.RGBA{v, 0, 0, v}) {
					t.Fatalf("opaque=%t got %v", opaque, got)
				}
			}
		})
	}
	for _, tc := range []struct {
		format int
		block  []byte
		want   color.RGBA
	}{
		{36, []byte{63, 63, 0, 0, 0, 0, 0, 0}, color.RGBA{63, 63, 63, 255}},
		{38, []byte{63, 63, 0, 0, 0, 0, 0, 0, 127, 127, 0, 0, 0, 0, 0, 0}, color.RGBA{63, 127, 0, 255}},
	} {
		img, err := DecodeDXTC(atecFixture(4, 4, tc.format, tc.block), 4, 4, false)
		if err != nil || img.At(0, 0) != tc.want {
			t.Fatalf("BC format %d: %v %v", tc.format, img, err)
		}
	}
}

func TestDecodeBCAlpha(t *testing.T) {
	// The first eight texels select every alpha palette entry in order.
	var indices uint64
	for i := range 8 {
		indices |= uint64(i) << uint(i*3+16)
	}
	for _, tc := range []struct {
		a, b byte
		want [8]byte
	}{
		{200, 20, [8]byte{200, 20, 174, 148, 122, 97, 71, 45}},
		{20, 200, [8]byte{20, 200, 56, 92, 128, 164, 0, 255}},
	} {
		block := binary.LittleEndian.AppendUint64(nil, indices|uint64(tc.a)|uint64(tc.b)<<8)
		got := decodeBCAlpha(block)
		if !bytes.Equal(got[:8], tc.want[:]) {
			t.Fatalf("got %v want %v", got[:8], tc.want)
		}
	}
}

func TestDXTCRejectsInvalidGeometry(t *testing.T) {
	valid := atecFixture(4, 4, 33, make([]byte, 8))
	for _, tc := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"signature", 12, 'B'}, {"block", 16, 8}, {"depth", 18, 1},
		{"width", 19, 8}, {"height", 22, 8}, {"format", 25, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bytes.Clone(valid)
			bad[tc.offset] = tc.value
			if _, err := DecodeDXTC(bad, 4, 4, false); err == nil {
				t.Fatal("accepted invalid texture")
			}
		})
	}
	for _, count := range []int{7, 9, 16} {
		if _, err := DecodeDXTC(atecFixture(4, 4, 33, make([]byte, count)), 4, 4, false); err == nil {
			t.Fatalf("accepted %d bytes for a single BC1 block", count)
		}
	}
	if _, err := DecodeDXTC(valid, pixel.MaxBytes, 4, false); err == nil {
		t.Fatal("accepted excessive dimensions")
	}
}

func FuzzTextureHeaders(f *testing.F) {
	f.Add(atecFixture(4, 4, 33, make([]byte, 8)), uint16(4), uint16(4))
	f.Add(astcFixture(), uint16(4), uint16(4))
	f.Fuzz(func(t *testing.T, data []byte, w, h uint16) {
		if len(data) > 1<<16 {
			return
		}
		// Header validation is fuzzed without invoking a native or external codec.
		_, _ = astcPayload(data, int(w), int(h))
		_, _ = texturePayload(data)
	})
}
