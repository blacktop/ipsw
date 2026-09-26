package texture

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"path/filepath"
	"strings"
	"testing"
)

func astcFixture() []byte {
	header := []byte{0x13, 0xab, 0xa1, 0x5c, 4, 4, 1, 4, 0, 0, 4, 0, 0, 1, 0, 0}
	// LDR void-extent block with four UNORM16 constant channels.
	block := []byte{0xfc, 0xfd, 255, 255, 255, 255, 255, 255}
	for _, c := range []uint16{17 * 257, 34 * 257, 51 * 257, 68 * 257} {
		block = binary.LittleEndian.AppendUint16(block, c)
	}
	return append(header, block...)
}

func TestASTCPayload(t *testing.T) {
	valid := astcFixture()
	for _, input := range [][]byte{valid, textureFixture(valid, false), textureFixture(valid, true)} {
		got, err := astcPayload(input, 4, 4)
		if err != nil || !bytes.Equal(got, valid) {
			t.Fatalf("got %x err=%v", got, err)
		}
	}
	for _, offset := range []int{0, 4, 6, 7, 10, 13} {
		bad := bytes.Clone(valid)
		bad[offset] = 3
		if _, err := astcPayload(bad, 4, 4); err == nil {
			t.Fatalf("accepted invalid ASTC field at %d", offset)
		}
	}
	for _, input := range [][]byte{valid[:31], append(bytes.Clone(valid), make([]byte, 16)...)} {
		if _, err := astcPayload(input, 4, 4); err == nil {
			t.Fatal("accepted truncated or multiple-mip ASTC")
		}
	}
}

func TestASTCExplicitDecoderFailure(t *testing.T) {
	_, err := DecodeASTC(astcFixture(), 4, 4, filepath.Join(t.TempDir(), "missing-decoder"), false, false)
	if err == nil || !strings.Contains(err.Error(), "ASTC decoder failed") {
		t.Fatalf("explicit decoder path was ignored: %v", err)
	}
}

func TestDecodeTexturePNG(t *testing.T) {
	src := image.NewNRGBA(image.Rect(0, 0, 2, 1))
	src.SetNRGBA(0, 0, color.NRGBA{90, 30, 50, 60})
	src.SetNRGBA(1, 0, color.NRGBA{10, 20, 30, 0})
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, src); err != nil {
		t.Fatal(err)
	}
	for _, opaque := range []bool{false, true} {
		got, err := decodeTexturePNG(encoded.Bytes(), 2, 1, opaque)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{60, 30, 50, 60, 0, 0, 0, 0}
		if opaque {
			want = []byte{90, 30, 50, 255, 10, 20, 30, 255}
		}
		if !bytes.Equal(got.Pix, want) {
			t.Fatalf("opaque=%t got %v want %v", opaque, got.Pix, want)
		}
	}
	if _, err := decodeTexturePNG(encoded.Bytes(), 1, 1, false); err == nil {
		t.Fatal("accepted decoder output with wrong dimensions")
	}
	var diagnostic textureDiagnostics
	if n, err := diagnostic.Write(make([]byte, 10000)); err != nil || n != 10000 || len(diagnostic) != 4096 {
		t.Fatalf("unbounded decoder diagnostics: n=%d len=%d err=%v", n, len(diagnostic), err)
	}
}

func TestDecodeTexturePNGRejects16BitSamples(t *testing.T) {
	for _, tc := range []struct {
		name string
		img  image.Image
	}{
		{"RGBA64", image.NewRGBA64(image.Rect(0, 0, 2, 1))},
		{"NRGBA64", image.NewNRGBA64(image.Rect(0, 0, 2, 1))},
		{"Gray16", image.NewGray16(image.Rect(0, 0, 2, 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := png.Encode(&encoded, tc.img); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeTexturePNG(encoded.Bytes(), 2, 1, false); err == nil || !strings.Contains(err.Error(), "8-bit samples") {
				t.Fatalf("accepted unexpected wide decoder output: %v", err)
			}
		})
	}
}
