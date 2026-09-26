package car

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func jpegAlphaFixture(t testing.TB, width, height, stride int, gray uint8, alpha []byte) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.SetRGBA(x, y, color.RGBA{gray, gray, gray, 255})
		}
	}
	var jpegData bytes.Buffer
	if err := jpeg.Encode(&jpegData, img, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatal(err)
	}
	stream := binary.LittleEndian.AppendUint32([]byte("bvx-"), uint32(len(alpha)))
	stream = append(stream, alpha...)
	stream = append(stream, "bvx$"...)
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(stream)))
	binary.LittleEndian.PutUint32(data[12:], uint32(stride))
	binary.LittleEndian.PutUint32(data[16:], uint32(jpegData.Len()))
	return append(append(data, stream...), jpegData.Bytes()...)
}

func TestDecodeJPEGLZFSE(t *testing.T) {
	// Native CoreUI reports premultiplied RGBA: JPEG luminance 32 remains
	// 32 when alpha is 64, rather than being multiplied down to 8.
	data := jpegAlphaFixture(t, 2, 2, 3, 32, []byte{64, 128, 99, 255, 0, 99})
	for _, opaque := range []bool{false, true} {
		img, err := decodeJPEGLZFSE([]bitmapChunk{{data: data}}, 2, 2, opaque)
		if err != nil {
			t.Fatal(err)
		}
		for i, alpha := range []uint8{64, 128, 255, 0} {
			if opaque {
				alpha = 255
			}
			gray := min(uint8(32), alpha)
			want := color.RGBA{gray, gray, gray, alpha}
			if got := img.At(i%2, i/2); got != want {
				t.Fatalf("opaque=%t pixel %d = %v, want %v", opaque, i, got, want)
			}
		}
	}
	first := jpegAlphaFixture(t, 1, 1, 1, 32, []byte{64})
	second := jpegAlphaFixture(t, 1, 1, 1, 80, []byte{128})
	img, err := decodeJPEGLZFSE([]bitmapChunk{{data: first, rows: 1}, {data: second, rows: 1}}, 1, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := img.At(0, 1); got != (color.RGBA{80, 80, 80, 128}) {
		t.Fatalf("second chunk = %v", got)
	}
}

func TestDecodeJPEGLZFSERejectsMalformed(t *testing.T) {
	valid := jpegAlphaFixture(t, 2, 2, 2, 32, []byte{64, 64, 64, 64})
	for name, mutate := range map[string]func([]byte) []byte{
		"short header": func(b []byte) []byte { return b[:19] },
		"version":      func(b []byte) []byte { b[0] = 1; return b },
		"inner chunks": func(b []byte) []byte { b[4] = 1; return b },
		"alpha size":   func(b []byte) []byte { b[8] = 255; return b },
		"jpeg size":    func(b []byte) []byte { b[16] = 0; return b },
		"stride":       func(b []byte) []byte { b[12] = 1; return b },
		"zero stride":  func(b []byte) []byte { b[12] = 0; return b },
		"alpha magic":  func(b []byte) []byte { b[20] = 0; return b },
		"alpha EOS":    func(b []byte) []byte { b[35] = 0; return b },
		"jpeg bytes": func(b []byte) []byte {
			b[20+int(binary.LittleEndian.Uint32(b[8:]))] = 0
			return b
		},
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":  func(b []byte) []byte { return append(b, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			data := mutate(bytes.Clone(valid))
			if _, err := decodeJPEGLZFSE([]bitmapChunk{{data: data}}, 2, 2, false); err == nil {
				t.Fatal("accepted malformed JPEG+LZFSE")
			}
		})
	}
	for _, chunks := range [][]bitmapChunk{
		nil,
		{{data: valid, rows: 1}},
		{{data: valid, rows: 3}},
		{{data: valid}, {data: valid}},
		{{data: valid, rows: 1}, {data: valid, rows: 1}}, // JPEG dimensions mismatch.
		{{data: jpegAlphaFixture(t, 2, 2, 3, 32, []byte{64, 64, 64, 64})}},
		{{data: jpegAlphaFixture(t, 2, 2, 2, 32, []byte{64, 64, 64, 64, 64})}},
	} {
		if _, err := decodeJPEGLZFSE(chunks, 2, 2, false); err == nil {
			t.Fatal("accepted malformed chunk geometry or alpha plane")
		}
	}
	if _, err := decodeJPEGLZFSE([]bitmapChunk{{data: valid}}, pixel.MaxBytes, 2, false); err == nil {
		t.Fatal("accepted excessive dimensions")
	}
}

func FuzzDecodeJPEGLZFSE(f *testing.F) {
	f.Add([]byte{}, uint8(1), uint8(1), false)
	f.Add(jpegAlphaFixture(f, 2, 2, 2, 32, []byte{64, 128, 255, 0}), uint8(2), uint8(2), false)
	f.Fuzz(func(t *testing.T, data []byte, w, h uint8, opaque bool) {
		_, _ = decodeJPEGLZFSE([]bitmapChunk{{data: data}}, int(w), int(h), opaque)
	})
}
